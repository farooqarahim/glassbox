//! RFC 3161 trusted-timestamp authority (TSA) client.
//!
//! The client builds an ASN.1 DER-encoded `TimeStampReq` carrying a
//! SHA-256 imprint of the bytes we want timestamped (in Glassbox: a
//! Merkle root), posts it to a configured TSA URL with the standard
//! `application/timestamp-query` content type, and returns the
//! opaque `TimeStampToken` bytes the TSA sends back. The token is
//! stored verbatim in
//! [`TimestampAnchor::token`](glassbox_core::TimestampAnchor::token)
//! so any later verifier can hand it to a CMS-aware parser without
//! re-issuing the request.
//!
//! ## Why a hand-rolled DER encoder?
//!
//! RFC 3161 [`TimeStampReq`](https://datatracker.ietf.org/doc/html/rfc3161#section-2.4.1)
//! is a small ASN.1 structure — version, messageImprint
//! (algorithm + 32-byte hash), and an optional nonce. Hand-encoding
//! six tags and two integers is far smaller than pulling in a full
//! ASN.1 / CMS dependency tree. We do **not** parse the response —
//! the TSA's signed token is consumer-side data, stored as bytes.
//! Parsing it for verification is the consumer's job (CMS libraries
//! exist for every major language).
//!
//! ## Feature flag
//!
//! Enable with `glassbox-witness = { features = ["tsa"] }`. The
//! feature pulls in `ureq` + TLS, which is intentionally optional —
//! air-gapped deployments per spec §27.7 build without it.

use glassbox_core::record::TimestampAnchor;
use thiserror::Error;

/// Errors produced by the TSA client.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TsaError {
    /// HTTP transport failure (DNS, TCP, TLS, response status).
    #[error("TSA transport: {0}")]
    Transport(String),
    /// The TSA returned a status code other than 200.
    #[error("TSA returned HTTP {status}: {body}")]
    BadStatus {
        /// Status code.
        status: u16,
        /// Truncated response body.
        body: String,
    },
    /// The TSA returned content with an unexpected Content-Type.
    #[error("TSA returned unexpected content-type: {0}")]
    BadContentType(String),
    /// Failed to read the response body.
    #[error("TSA read body: {0}")]
    BadBody(String),
}

/// Build the DER bytes of a `TimeStampReq` over a 32-byte SHA-256
/// imprint.
///
/// Layout (per RFC 3161 §2.4.1):
///
/// ```text
/// SEQUENCE {
///   INTEGER 1                         -- version
///   SEQUENCE {                        -- messageImprint
///     SEQUENCE {                      -- hashAlgorithm
///       OBJECT IDENTIFIER 2.16.840.1.101.3.4.2.1   -- id-sha256
///       NULL                          -- parameters
///     }
///     OCTET STRING (32 bytes)         -- hashedMessage
///   }
///   BOOLEAN TRUE                      -- certReq
/// }
/// ```
///
/// No nonce in v0.6; nonce defence-in-depth is on the v0.7 list.
#[must_use]
pub fn build_request(sha256_imprint: &[u8; 32]) -> Vec<u8> {
    // Inner: hashAlgorithm SEQUENCE { OID + NULL }
    // OID 2.16.840.1.101.3.4.2.1 = SHA-256
    let oid_sha256: [u8; 11] = [
        0x06, 0x09, // OBJECT IDENTIFIER, length 9
        0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    ];
    let null: [u8; 2] = [0x05, 0x00];
    let mut alg = Vec::with_capacity(2 + oid_sha256.len() + null.len());
    alg.extend_from_slice(&oid_sha256);
    alg.extend_from_slice(&null);
    let alg = der_sequence(&alg);

    // OCTET STRING 32 bytes
    let mut hashed = Vec::with_capacity(2 + 32);
    hashed.push(0x04); // OCTET STRING
    hashed.push(32);
    hashed.extend_from_slice(sha256_imprint);

    // messageImprint SEQUENCE { hashAlgorithm, hashedMessage }
    let mut imprint_body = Vec::with_capacity(alg.len() + hashed.len());
    imprint_body.extend_from_slice(&alg);
    imprint_body.extend_from_slice(&hashed);
    let imprint = der_sequence(&imprint_body);

    // version INTEGER 1
    let version: [u8; 3] = [0x02, 0x01, 0x01];

    // certReq BOOLEAN TRUE — we want the TSA to include its cert
    let cert_req: [u8; 3] = [0x01, 0x01, 0xff];

    let mut body = Vec::with_capacity(version.len() + imprint.len() + cert_req.len());
    body.extend_from_slice(&version);
    body.extend_from_slice(&imprint);
    body.extend_from_slice(&cert_req);
    der_sequence(&body)
}

/// Wrap `body` in a DER `SEQUENCE` (tag 0x30) with a definite-length
/// header. Only encodes lengths up to 65535 because TimeStampReqs
/// never approach 64 KiB.
fn der_sequence(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 4);
    out.push(0x30);
    let len = body.len();
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        assert!(len < 65536, "DER sequence too large");
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xff) as u8);
    }
    out.extend_from_slice(body);
    out
}

/// Post a `TimeStampReq` to `tsa_url` and return the opaque
/// `TimeStampToken` bytes. Only available with the `tsa` feature.
///
/// Returns a [`TimestampAnchor`] populated with `kind = "rfc3161"`,
/// the configured `authority_id`, and the response token — ready to
/// drop into a `MerkleRootEntry.timestamp_anchors` vector.
#[cfg(feature = "tsa")]
pub fn request(
    tsa_url: &str,
    authority_id: &str,
    sha256_imprint: &[u8; 32],
) -> Result<TimestampAnchor, TsaError> {
    let body = build_request(sha256_imprint);
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(15))
        .build();
    let response = agent
        .post(tsa_url)
        .set("Content-Type", "application/timestamp-query")
        .send_bytes(&body)
        .map_err(|e| TsaError::Transport(e.to_string()))?;
    if response.status() != 200 {
        let status = response.status();
        let body = response.into_string().unwrap_or_default();
        return Err(TsaError::BadStatus {
            status,
            body: body.chars().take(512).collect(),
        });
    }
    let content_type = response.header("Content-Type").unwrap_or("").to_lowercase();
    if !content_type.starts_with("application/timestamp-reply") {
        return Err(TsaError::BadContentType(content_type));
    }
    let mut token = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut token)
        .map_err(|e| TsaError::BadBody(e.to_string()))?;
    Ok(TimestampAnchor {
        kind: "rfc3161".into(),
        authority_id: authority_id.into(),
        token,
    })
}

/// Build a [`TimestampAnchor`] from a token the caller already
/// obtained out-of-band. Always available — no feature flag — so
/// air-gapped operators with their own offline TSA can populate the
/// schema without compiling in HTTP support.
#[must_use]
pub fn anchor_from_token(
    kind: impl Into<String>,
    authority_id: impl Into<String>,
    token: Vec<u8>,
) -> TimestampAnchor {
    TimestampAnchor {
        kind: kind.into(),
        authority_id: authority_id.into(),
        token,
    }
}

#[cfg(feature = "tsa")]
use std::io::Read as _;

#[cfg(test)]
mod tests {
    use super::*;

    /// Static SHA-256 of "abc" — the canonical test vector.
    const ABC_HASH: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];

    #[test]
    fn timestamp_req_has_expected_shape() {
        let bytes = build_request(&ABC_HASH);
        // Outer SEQUENCE.
        assert_eq!(bytes[0], 0x30);
        // Total length sane.
        assert!(bytes.len() > 50 && bytes.len() < 100);
        // Contains the version INTEGER 1.
        assert!(bytes.windows(3).any(|w| w == [0x02, 0x01, 0x01]));
        // Contains the SHA-256 OID.
        assert!(
            bytes
                .windows(9)
                .any(|w| w == [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])
        );
        // Contains the certReq BOOLEAN TRUE.
        assert!(bytes.windows(3).any(|w| w == [0x01, 0x01, 0xff]));
        // Contains the 32-byte imprint at OCTET STRING position.
        let octet_pos = bytes.windows(2).position(|w| w == [0x04, 32]).unwrap();
        assert_eq!(&bytes[octet_pos + 2..octet_pos + 34], &ABC_HASH);
    }

    #[test]
    fn anchor_from_token_wraps_bytes() {
        let anchor = anchor_from_token(
            "rfc3161",
            "operator-tsa.example",
            vec![0xde, 0xad, 0xbe, 0xef],
        );
        assert_eq!(anchor.kind, "rfc3161");
        assert_eq!(anchor.authority_id, "operator-tsa.example");
        assert_eq!(anchor.token, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn der_sequence_short_form_lengths() {
        let body = vec![0u8; 10];
        let seq = der_sequence(&body);
        assert_eq!(seq[0], 0x30);
        assert_eq!(seq[1], 10);
        assert_eq!(seq.len(), 12);
    }

    #[test]
    fn der_sequence_medium_form_lengths() {
        let body = vec![0u8; 200];
        let seq = der_sequence(&body);
        assert_eq!(seq[0], 0x30);
        assert_eq!(seq[1], 0x81);
        assert_eq!(seq[2], 200);
        assert_eq!(seq.len(), 203);
    }

    /// Network test: requires `GLASSBOX_TSA_URL` env var. Skipped
    /// otherwise to keep CI hermetic.
    #[cfg(feature = "tsa")]
    #[test]
    fn live_tsa_round_trip() {
        let Some(url) = std::env::var("GLASSBOX_TSA_URL")
            .ok()
            .filter(|s| !s.is_empty())
        else {
            eprintln!("GLASSBOX_TSA_URL not set; skipping live TSA round-trip");
            return;
        };
        let anchor = request(&url, "live-tsa", &ABC_HASH).expect("TSA round-trip");
        assert!(!anchor.token.is_empty());
        assert_eq!(anchor.kind, "rfc3161");
    }
}
