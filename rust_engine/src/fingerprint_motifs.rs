//! Bounded storage of a lexicographic prefix of motif occurrences, never a ranking.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const MAX_MOTIF_CHECKS: usize = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MotifTruncation {
    pub enumerated: usize,
    pub retained: usize,
    pub omitted: usize,
    pub truncated: bool,
}

pub struct Candidate {
    pub descriptor: Value,
    pub count: u64,
    pub elements: Vec<String>,
}

pub struct MotifBuffer {
    limit: usize,
    checks: usize,
    enumerated: usize,
    kept: BTreeMap<(String, String, usize), Candidate>,
}

impl MotifBuffer {
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            checks: 0,
            enumerated: 0,
            kept: BTreeMap::new(),
        }
    }

    pub fn check(&mut self) -> Result<(), String> {
        self.checks += 1;
        if self.checks > MAX_MOTIF_CHECKS {
            return Err(
                "motif enumeration work budget exceeded; no partial fingerprint produced".into(),
            );
        }
        Ok(())
    }

    pub fn add(
        &mut self,
        descriptor: Value,
        count: u64,
        mut elements: Vec<String>,
    ) -> Result<(), String> {
        self.enumerated = self
            .enumerated
            .checked_add(1)
            .ok_or("motif candidate count overflow")?;
        elements.sort();
        elements.dedup();
        if self.limit > 0 {
            let key = (
                descriptor.to_string(),
                serde_json::to_string(&elements).unwrap(),
                self.enumerated,
            );
            self.kept.insert(
                key,
                Candidate {
                    descriptor,
                    count,
                    elements,
                },
            );
            if self.kept.len() > self.limit {
                self.kept.pop_last();
            }
        }
        Ok(())
    }

    pub fn finish(self) -> (MotifTruncation, Vec<Candidate>) {
        let retained = self.kept.len();
        (
            MotifTruncation {
                enumerated: self.enumerated,
                retained,
                omitted: self.enumerated - retained,
                truncated: self.enumerated > retained,
            },
            self.kept.into_values().collect(),
        )
    }
}
