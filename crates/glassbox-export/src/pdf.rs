//! Annex IV PDF rendering.
//!
//! v0.6 ships a real, valid PDF — opens in Preview/Adobe/Firefox —
//! rendering the [`AnnexIvSidecar`](crate::AnnexIvSidecar) sections
//! that fit Annex IV §§1, 2, 3, 4, 7, 9. Operator-supplied sections
//! (§5, §6, §8) are reproduced as section headers with the JSON
//! verbatim — when the operator wires real evidence into
//! [`SectionOperatorSupplied`](crate::SectionOperatorSupplied) it
//! flows through.
//!
//! ## Signing
//!
//! Spec §22.4 calls for PAdES (PDF Advanced Electronic Signatures).
//! True PAdES is a separate engagement — the standard is large and
//! signature placement inside the PDF byte stream is fiddly. v0.6
//! ships a **detached** hybrid signature alongside the PDF instead:
//! [`sign_detached`] returns a `<pdf bytes, signature bytes>` pair
//! where the signature is the AND-combined Ed25519+ML-DSA-65 sig
//! over the SHA-256 of the PDF bytes. A regulator-facing verifier
//! checks the detached signature against the same operator key the
//! Annex IV manifest is signed under. PAdES embedding lands in v0.7.

use pdf_writer::types::{ActionType, AnnotationType};
use pdf_writer::{Content, Filter, Finish, Name, Obj, Pdf, Rect, Ref, Str, TextStr};

use glassbox_core::crypto::{HybridKeypair, HybridSignature};

use crate::AnnexIvSidecar;

/// Render the sidecar as a real PDF and return the raw bytes.
///
/// Layout: a header, the system metadata, then one section per
/// Annex IV category. Body text is laid out at a fixed pitch — no
/// hyphenation, no text wrapping at word boundaries. Good enough for
/// regulator review; spec §22.2 leaves typographic choices to
/// operators and the bundled template.
#[must_use]
pub fn render(sidecar: &AnnexIvSidecar) -> Vec<u8> {
    let lines = build_lines(sidecar);
    write_pdf(&lines)
}

fn build_lines(s: &AnnexIvSidecar) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();
    push_h1(&mut lines, "Annex IV Technical Documentation");
    push_p(
        &mut lines,
        format!(
            "Stream: {}  •  Generated at: {}",
            s.stream_id, s.generated_at
        ),
    );
    push_p(
        &mut lines,
        format!("Sidecar version: {}", s.sidecar_version),
    );
    push_blank(&mut lines);

    push_h2(&mut lines, "§1 General description");
    push_kv(
        &mut lines,
        "System name",
        s.general_description.system_name.clone(),
    );
    push_kv(
        &mut lines,
        "Annex III category",
        s.general_description.annex_iii_category.clone(),
    );
    push_kv(
        &mut lines,
        "Tenant",
        s.general_description.tenant_id.clone(),
    );
    push_kv(
        &mut lines,
        "System id",
        s.general_description.system_id.clone(),
    );
    push_kv(
        &mut lines,
        "Period from",
        s.general_description
            .period_from
            .clone()
            .unwrap_or_else(|| "(open)".into()),
    );
    push_kv(
        &mut lines,
        "Period to",
        s.general_description
            .period_to
            .clone()
            .unwrap_or_else(|| "(open)".into()),
    );
    push_blank(&mut lines);

    push_h2(&mut lines, "§2 System elements and development");
    push_kv(
        &mut lines,
        "Distinct model fingerprints",
        s.system_elements.model_fingerprints.len().to_string(),
    );
    for fp in &s.system_elements.model_fingerprints {
        push_p(
            &mut lines,
            format!(
                "  • {}/{}/{}  ({} interactions)",
                fp.provider, fp.model_name, fp.model_version, fp.interactions
            ),
        );
    }
    push_kv(
        &mut lines,
        "Prompt templates observed",
        s.system_elements.prompt_templates.len().to_string(),
    );
    push_kv(
        &mut lines,
        "Corpus versions referenced",
        s.system_elements.corpus_versions.len().to_string(),
    );
    push_kv(
        &mut lines,
        "Source SDKs",
        s.system_elements.source_sdks.join(", "),
    );
    push_blank(&mut lines);

    push_h2(&mut lines, "§3 Monitoring, functioning, control");
    push_kv(
        &mut lines,
        "Total records",
        s.monitoring.total_records.to_string(),
    );
    for (kind, n) in &s.monitoring.records_by_kind {
        push_p(&mut lines, format!("  • {kind}: {n}"));
    }
    push_kv(
        &mut lines,
        "Merkle roots committed",
        s.monitoring.merkle_roots_committed.to_string(),
    );
    push_kv(
        &mut lines,
        "Tombstones",
        s.monitoring.tombstones.to_string(),
    );
    push_blank(&mut lines);

    push_h2(&mut lines, "§4 Changes to the system");
    if s.changes.is_empty() {
        push_p(&mut lines, "(none recorded in this window)");
    } else {
        for c in &s.changes {
            push_p(
                &mut lines,
                format!("  [{}] seq={} — {}", c.kind, c.sequence, c.summary),
            );
        }
    }
    push_blank(&mut lines);

    push_h2(&mut lines, "§5 Harmonised standards applied");
    if s.operator_supplied.harmonised_standards.is_empty() {
        push_p(&mut lines, "(operator-supplied; none recorded yet)");
    } else {
        for st in &s.operator_supplied.harmonised_standards {
            push_p(&mut lines, format!("  • {st}"));
        }
    }
    push_blank(&mut lines);

    push_h2(&mut lines, "§6 EU declaration of conformity");
    push_p(
        &mut lines,
        s.operator_supplied
            .declaration_of_conformity
            .clone()
            .unwrap_or_else(|| "(operator-supplied)".into()),
    );
    push_blank(&mut lines);

    push_h2(&mut lines, "§7 Performance assessment");
    push_kv(
        &mut lines,
        "Interactions",
        s.performance.interactions.to_string(),
    );
    push_kv(
        &mut lines,
        "Human oversight records",
        s.performance.human_oversight_records.to_string(),
    );
    push_kv(
        &mut lines,
        "Human oversight %",
        s.performance.human_oversight_percent.to_string(),
    );
    push_blank(&mut lines);

    push_h2(&mut lines, "§8 Risk-management system");
    push_p(
        &mut lines,
        s.operator_supplied
            .risk_management_system
            .clone()
            .unwrap_or_else(|| "(operator-supplied)".into()),
    );
    push_blank(&mut lines);

    push_h2(&mut lines, "§9 Lifecycle changes");
    push_kv(
        &mut lines,
        "Key rotations",
        s.lifecycle.key_rotations.to_string(),
    );
    push_kv(
        &mut lines,
        "Retention policy changes",
        s.lifecycle.retention_policy_changes.to_string(),
    );
    push_kv(
        &mut lines,
        "Open legal holds",
        s.lifecycle.open_legal_holds.to_string(),
    );
    push_blank(&mut lines);

    push_p(
        &mut lines,
        "— End of Annex IV export. See sidecar.json + manifest.json in the archive for machine-readable contents.",
    );

    lines
}

#[derive(Clone, Debug)]
struct Line<'a> {
    text: String,
    size: f32,
    bold: bool,
    _marker: std::marker::PhantomData<&'a ()>,
}

fn push_h1(out: &mut Vec<Line<'static>>, t: impl Into<String>) {
    out.push(Line {
        text: t.into(),
        size: 18.0,
        bold: true,
        _marker: std::marker::PhantomData,
    });
}
fn push_h2(out: &mut Vec<Line<'static>>, t: impl Into<String>) {
    out.push(Line {
        text: t.into(),
        size: 13.0,
        bold: true,
        _marker: std::marker::PhantomData,
    });
}
fn push_p(out: &mut Vec<Line<'static>>, t: impl Into<String>) {
    out.push(Line {
        text: t.into(),
        size: 10.0,
        bold: false,
        _marker: std::marker::PhantomData,
    });
}
fn push_kv(out: &mut Vec<Line<'static>>, k: &str, v: impl Into<String>) {
    push_p(out, format!("  {k}: {}", v.into()));
}
fn push_blank(out: &mut Vec<Line<'static>>) {
    push_p(out, "");
}

fn write_pdf(lines: &[Line<'_>]) -> Vec<u8> {
    let mut pdf = Pdf::new();
    let mut next_id: i32 = 1;
    let mut alloc = || {
        let r = Ref::new(next_id);
        next_id += 1;
        r
    };

    let catalog_id = alloc();
    let pages_id = alloc();
    let helv_id = alloc();
    let helv_bold_id = alloc();

    pdf.catalog(catalog_id).pages(pages_id);
    pdf.type1_font(helv_id).base_font(Name(b"Helvetica"));
    pdf.type1_font(helv_bold_id)
        .base_font(Name(b"Helvetica-Bold"));

    // Page layout: A4 portrait, top y=800, bottom y=50, line pitch
    // depends on the line size. We paginate manually.
    const TOP: f32 = 800.0;
    const BOTTOM: f32 = 50.0;
    const LEFT: f32 = 50.0;

    let mut page_refs: Vec<Ref> = Vec::new();

    let mut page_chunks: Vec<Vec<&Line>> = vec![Vec::new()];
    let mut y = TOP;
    for line in lines {
        let pitch = line.size + 4.0;
        if y - pitch < BOTTOM {
            page_chunks.push(Vec::new());
            y = TOP;
        }
        y -= pitch;
        page_chunks.last_mut().unwrap().push(line);
    }

    for chunk in &page_chunks {
        let page_id = alloc();
        let content_id = alloc();
        page_refs.push(page_id);

        let mut page = pdf.page(page_id);
        page.parent(pages_id)
            .media_box(Rect::new(0.0, 0.0, 595.0, 842.0));
        {
            let mut resources = page.resources();
            resources
                .fonts()
                .pair(Name(b"F1"), helv_id)
                .pair(Name(b"F2"), helv_bold_id);
            resources.finish();
        }
        page.contents(content_id);
        page.finish();

        let mut content = Content::new();
        content.begin_text();
        let mut y_cursor = TOP;
        for line in chunk {
            let pitch = line.size + 4.0;
            y_cursor -= pitch;
            let font = if line.bold { Name(b"F2") } else { Name(b"F1") };
            content.set_font(font, line.size);
            // Absolute text-matrix positioning per line: identity
            // transform with translation (LEFT, y_cursor). Avoids
            // accumulating pitch errors across mixed line sizes.
            content.set_text_matrix([1.0, 0.0, 0.0, 1.0, LEFT, y_cursor]);
            content.show(Str(sanitize_for_pdf(&line.text).as_bytes()));
        }
        content.end_text();
        pdf.stream(content_id, &content.finish());
    }

    {
        let mut pages = pdf.pages(pages_id);
        let kids = page_refs.iter().copied();
        pages
            .kids(kids)
            .count(i32::try_from(page_refs.len()).unwrap_or(i32::MAX));
        pages.finish();
    }

    pdf.finish()
}

/// PDF base-14 fonts can't render arbitrary Unicode without a real
/// font embedding. Strip anything outside printable ASCII so the
/// rendered text stays legible. Per spec §22.2 the canonical-form
/// content lives in the JSON sidecar; the PDF is the regulator-
/// readable summary, not the authoritative artifact.
fn sanitize_for_pdf(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == '\n' || c == '\r' || c == '\t' || c == ' ' || c == '§' {
                if c == '§' { '#' } else { c }
            } else if c.is_ascii_graphic() {
                c
            } else {
                '?'
            }
        })
        .collect()
}

/// Sign a PDF byte slice with a hybrid keypair, returning the detached
/// signature plus the SHA-256 imprint that was signed over. The
/// detached signature is what gets written next to the PDF in the
/// Annex IV zip archive — see [`write_zip_with_pdf`].
pub fn sign_detached(pdf_bytes: &[u8], keypair: &HybridKeypair) -> (HybridSignature, [u8; 32]) {
    let imprint = glassbox_core::canonical::sha256(pdf_bytes);
    let sig = keypair.sign(&imprint);
    (sig, imprint)
}

// Pull in unused-import guards so `Filter`, `Obj`, `TextStr`,
// `ActionType`, `AnnotationType` stay in scope for the
// `pdf-writer`-feature compilation surface without us having to gate
// their absence per release.
#[allow(dead_code, clippy::type_complexity)]
const _IMPORT_GUARD: (
    Option<Filter>,
    Option<ActionType>,
    Option<AnnotationType>,
    fn(Obj),
    fn(TextStr),
) = (None, None, None, |_| {}, |_| {});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AnnexIvSidecar, SectionGeneralDescription, SectionLifecycle, SectionMonitoring,
        SectionOperatorSupplied, SectionPerformance, SectionSystemElements,
    };
    use std::collections::BTreeMap;

    fn empty_sidecar() -> AnnexIvSidecar {
        AnnexIvSidecar {
            sidecar_version: "1.0.0".into(),
            stream_id: "acme/sys".into(),
            generated_at: "2026-05-13T00:00:00Z".into(),
            general_description: SectionGeneralDescription {
                system_name: "Test".into(),
                annex_iii_category: "5b".into(),
                period_from: None,
                period_to: None,
                tenant_id: "acme".into(),
                system_id: "sys".into(),
            },
            system_elements: SectionSystemElements {
                model_fingerprints: vec![],
                prompt_templates: vec![],
                corpus_versions: vec![],
                source_sdks: vec![],
            },
            monitoring: SectionMonitoring {
                total_records: 0,
                records_by_kind: BTreeMap::new(),
                interactions_by_automation_level: BTreeMap::new(),
                approval_outcomes: BTreeMap::new(),
                merkle_roots_committed: 0,
                tombstones: 0,
            },
            changes: vec![],
            operator_supplied: SectionOperatorSupplied::default(),
            performance: SectionPerformance {
                interactions: 0,
                human_oversight_records: 0,
                human_oversight_percent: 0,
                decisions_by_automation: BTreeMap::new(),
            },
            lifecycle: SectionLifecycle {
                key_rotations: 0,
                retention_policy_changes: 0,
                open_legal_holds: 0,
            },
        }
    }

    #[test]
    fn render_produces_pdf_header() {
        let bytes = render(&empty_sidecar());
        assert!(bytes.starts_with(b"%PDF-"));
        assert!(bytes.windows(5).any(|w| w == b"%%EOF"));
    }

    #[test]
    fn sign_detached_signature_verifies() {
        let bytes = render(&empty_sidecar());
        let kp = HybridKeypair::generate().unwrap();
        let (sig, imprint) = sign_detached(&bytes, &kp);
        // Imprint must equal SHA-256(pdf bytes).
        assert_eq!(imprint, glassbox_core::canonical::sha256(&bytes));
        // Signature must verify under the public key over the imprint.
        kp.public_key().verify(&imprint, &sig).unwrap();
    }
}
