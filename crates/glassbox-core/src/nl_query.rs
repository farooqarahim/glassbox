//! Natural-language → structured-query translator (spec §19.3).
//!
//! v0.6 ships a pattern-based, **pure-Rust** translator. No embedded
//! model, no hosted API call. The grammar is deliberately tiny:
//!
//! | English shape | Translates to |
//! |---|---|
//! | `show sequence 42` | `{ sequence: 42 }` |
//! | `record at sequence 42` | `{ sequence: 42 }` |
//! | `show records for decision loan-1` | `{ decision_id: "loan-1" }` |
//! | `decisions for subject applicant-42` | `{ subject_id: "applicant-42" }` |
//! | `last 25 records` | `{ limit: 25 }` |
//! | `first 10 records` | `{ limit: 10 }` |
//!
//! Phrases compose: `show last 5 records for decision loan-1` becomes
//! `{ decision_id: "loan-1", limit: 5 }`.
//!
//! Per spec §19.3, every translation surfaces the structured form to
//! the caller so the user confirms before the query runs. The caller
//! is the MCP `query` tool, the gRPC `Query` RPC, or any future SQL
//! frontend. None of this code executes a query directly.
//!
//! Anything we can't translate produces `NlQueryError::Unparseable`
//! with the original input attached so the caller can surface the
//! exact phrase that didn't parse.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Structured query shape — mirrors the args every Glassbox query
/// frontend accepts (MCP `query` tool, gRPC `Query` RPC, HTTP filter).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredQuery {
    /// Filter on exact sequence number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
    /// Filter on `DecisionContext.decision_id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_id: Option<String>,
    /// Filter on `DecisionContext.subject_id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
    /// Maximum results to return.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

/// Errors produced by the translator.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum NlQueryError {
    /// No supported phrase recognised.
    #[error(
        "could not parse `{0}` — supported phrases are `show sequence N`, `decision X`, `subject X`, `last/first N records`"
    )]
    Unparseable(String),
    /// A numeric phrase had a non-integer where one was expected.
    #[error("expected an integer in `{0}` but got `{1}`")]
    NotANumber(String, String),
}

/// Convenience alias.
pub type Result<T> = core::result::Result<T, NlQueryError>;

/// Translate `input` (English) into a [`StructuredQuery`]. Returns
/// [`NlQueryError::Unparseable`] when no phrase matched. Callers MUST
/// surface the structured form to the user for confirmation before
/// running the underlying query (spec §19.3).
pub fn translate(input: &str) -> Result<StructuredQuery> {
    let lower = input.to_lowercase();
    let mut q = StructuredQuery::default();
    let mut matched = false;

    if let Some(seq) = extract_sequence(&lower)? {
        q.sequence = Some(seq);
        matched = true;
    }
    if let Some(id) = extract_after(&lower, &["decision", "decision id", "decision-id"]) {
        q.decision_id = Some(id);
        matched = true;
    }
    if let Some(id) = extract_after(
        &lower,
        &["subject", "subject id", "subject-id", "applicant"],
    ) {
        q.subject_id = Some(id);
        matched = true;
    }
    if let Some(n) = extract_limit(&lower)? {
        q.limit = Some(n);
        matched = true;
    }
    if matched {
        Ok(q)
    } else {
        Err(NlQueryError::Unparseable(input.into()))
    }
}

fn extract_sequence(s: &str) -> Result<Option<u64>> {
    for marker in ["sequence ", "seq ", "at sequence "] {
        if let Some(rest) = s.find(marker).map(|i| &s[i + marker.len()..]) {
            let token: String = rest.chars().take_while(char::is_ascii_digit).collect();
            if token.is_empty() {
                continue;
            }
            return token
                .parse::<u64>()
                .map(Some)
                .map_err(|_| NlQueryError::NotANumber(s.into(), token));
        }
    }
    Ok(None)
}

fn extract_after(s: &str, markers: &[&str]) -> Option<String> {
    for marker in markers {
        let pat = format!("{marker} ");
        if let Some(idx) = s.find(&pat) {
            let rest = &s[idx + pat.len()..];
            let token: String = rest
                .chars()
                .take_while(|c| !c.is_whitespace() && *c != ',' && *c != '.' && *c != ';')
                .collect();
            if !token.is_empty() {
                return Some(token);
            }
        }
    }
    None
}

fn extract_limit(s: &str) -> Result<Option<usize>> {
    for marker in ["last ", "first ", "limit "] {
        if let Some(idx) = s.find(marker) {
            let rest = &s[idx + marker.len()..];
            let token: String = rest.chars().take_while(char::is_ascii_digit).collect();
            if token.is_empty() {
                continue;
            }
            return token
                .parse::<usize>()
                .map(Some)
                .map_err(|_| NlQueryError::NotANumber(s.into(), token));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_only() {
        let q = translate("show sequence 42").unwrap();
        assert_eq!(q.sequence, Some(42));
        assert_eq!(q.decision_id, None);
    }

    #[test]
    fn decision_only() {
        let q = translate("show records for decision loan-1").unwrap();
        assert_eq!(q.decision_id.as_deref(), Some("loan-1"));
    }

    #[test]
    fn subject_only() {
        let q = translate("decisions for subject applicant-42").unwrap();
        assert_eq!(q.subject_id.as_deref(), Some("applicant-42"));
    }

    #[test]
    fn limit_only() {
        let q = translate("last 25 records").unwrap();
        assert_eq!(q.limit, Some(25));
    }

    #[test]
    fn composes_decision_and_limit() {
        let q = translate("show last 5 records for decision loan-1").unwrap();
        assert_eq!(q.limit, Some(5));
        assert_eq!(q.decision_id.as_deref(), Some("loan-1"));
    }

    #[test]
    fn unparseable_returns_error() {
        let err = translate("tell me about the weather").unwrap_err();
        assert!(matches!(err, NlQueryError::Unparseable(_)));
    }

    #[test]
    fn case_insensitive() {
        let q = translate("SHOW SEQUENCE 7").unwrap();
        assert_eq!(q.sequence, Some(7));
    }

    #[test]
    fn punctuation_in_decision_id_is_trimmed() {
        let q = translate("records for decision loan-1, please").unwrap();
        assert_eq!(q.decision_id.as_deref(), Some("loan-1"));
    }
}
