//! Experimental operational evidence. Original storage is provenance, not a feature.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const VERSION: &str = "osgf.pcode-evidence/0.1.0";
pub fn ensure(ok: bool, message: &str) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(message.into())
    }
}
pub fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operand {
    pub kind: String,
    pub width: usize,
    pub space: String,
    pub offset: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Origin {
    pub address: String,
    pub sequence: usize,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Semantics {
    pub family: String,
    pub signedness: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub id: String,
    pub opcode: String,
    pub semantics: Semantics,
    pub inputs: Vec<Operand>,
    pub output: Option<Operand>,
    pub origin: Origin,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dependency {
    pub from: String,
    pub to: String,
    pub input: usize,
    pub basis: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub binary: String,
    pub sha256: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Function {
    pub id: String,
    pub entry: String,
    pub name: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Environment {
    pub ghidra_version: String,
    pub ghidra_revision: String,
    pub language: String,
    pub compiler_spec: String,
    pub analysis_policy: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub max_operations: usize,
    pub max_dependencies: usize,
    pub timeout_seconds: usize,
    pub simplification: String,
    pub override_policy: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observability {
    pub state: String,
    pub reason: String,
    pub operations_seen: usize,
    pub dependencies_seen: usize,
    pub unresolved_inputs: usize,
    pub truncated: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub schema_version: String,
    pub source: Source,
    pub function: Function,
    pub environment: Environment,
    pub representation: String,
    pub configuration: Configuration,
    pub operations: Vec<Operation>,
    pub dependencies: Vec<Dependency>,
    pub observability: Observability,
    pub warnings: Vec<String>,
}

pub fn semantics(op: &str) -> Semantics {
    let groups = [
        ("arithmetic", "INT_ADD INT_SUB INT_MULT INT_DIV INT_SDIV INT_REM INT_SREM INT_NEGATE INT_2COMP INT_CARRY INT_SCARRY INT_SBORROW"),
        ("bitwise", "INT_AND INT_OR INT_XOR INT_LEFT INT_RIGHT INT_SRIGHT"),
        ("boolean", "BOOL_AND BOOL_OR BOOL_XOR BOOL_NEGATE"),
        ("predicate", "INT_EQUAL INT_NOTEQUAL INT_LESS INT_SLESS INT_LESSEQUAL INT_SLESSEQUAL"),
        ("memory", "LOAD STORE PTRADD PTRSUB"),
        ("control", "BRANCH CBRANCH BRANCHIND CALL CALLIND RETURN"),
        ("transfer", "COPY CAST INT_ZEXT INT_SEXT PIECE SUBPIECE"),
        ("analysis", "MULTIEQUAL INDIRECT"),
    ];
    let family = groups
        .iter()
        .find(|(_, words)| words.split_whitespace().any(|word| word == op))
        .map_or("unsupported", |(family, _)| family);
    let signedness =
        if "INT_SDIV INT_SREM INT_SRIGHT INT_SLESS INT_SLESSEQUAL INT_SEXT INT_SCARRY INT_SBORROW"
            .split_whitespace()
            .any(|word| word == op)
        {
            "signed"
        } else if "INT_DIV INT_REM INT_RIGHT INT_LESS INT_LESSEQUAL INT_ZEXT INT_CARRY"
            .split_whitespace()
            .any(|word| word == op)
        {
            "unsigned"
        } else {
            "not_asserted"
        };
    Semantics {
        family: family.into(),
        signedness: signedness.into(),
    }
}
fn address(value: &str) -> bool {
    let tail = value.rsplit(':').next().unwrap_or("");
    !tail.is_empty() && tail.bytes().all(|v| v.is_ascii_hexdigit())
}
impl Operand {
    fn validate(&self) -> Result<(), String> {
        ensure(
            ["constant", "register", "unique", "memory", "other"].contains(&self.kind.as_str()),
            "invalid operand kind",
        )?;
        ensure(
            self.width > 0 && !self.space.is_empty(),
            "invalid operand width/space",
        )?;
        ensure(
            !self.offset.is_empty()
                && self
                    .offset
                    .bytes()
                    .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v)),
            "invalid operand offset",
        )?;
        if self.kind == "constant" {
            let digits = self.offset.trim_start_matches('0');
            ensure(
                digits.len().div_ceil(2) <= self.width,
                "constant exceeds width",
            )?;
        }
        Ok(())
    }
}
impl Evidence {
    pub fn validate(&self) -> Result<(), String> {
        ensure(self.schema_version == VERSION, "unsupported P-code version")?;
        ensure(
            is_hash(&self.source.sha256) && !self.source.binary.is_empty(),
            "invalid binary provenance",
        )?;
        ensure(
            address(&self.function.entry)
                && self.function.id == format!("fn:{}", self.function.entry),
            "invalid function identity",
        )?;
        ensure(
            [
                &self.environment.ghidra_version,
                &self.environment.ghidra_revision,
                &self.environment.language,
                &self.environment.compiler_spec,
                &self.environment.analysis_policy,
            ]
            .iter()
            .all(|v| !v.is_empty()),
            "missing environment",
        )?;
        ensure(
            ["raw", "high"].contains(&self.representation.as_str()),
            "invalid representation",
        )?;
        let c = &self.configuration;
        ensure(
            c.max_operations > 0
                && c.max_dependencies > 0
                && c.timeout_seconds > 0
                && c.simplification == "decompile"
                && c.override_policy == "instruction-default",
            "invalid extraction configuration",
        )?;
        let obs = &self.observability;
        ensure(
            [
                "complete",
                "partial",
                "unavailable",
                "timeout",
                "cancelled",
                "failed",
            ]
            .contains(&obs.state.as_str()),
            "invalid observation state",
        )?;
        ensure(
            self.operations.len() <= c.max_operations
                && self.dependencies.len() <= c.max_dependencies,
            "extraction budget exceeded",
        )?;
        ensure(
            obs.operations_seen >= self.operations.len()
                && obs.dependencies_seen >= self.dependencies.len(),
            "inconsistent seen counts",
        )?;
        let lost = obs.operations_seen > self.operations.len()
            || obs.dependencies_seen > self.dependencies.len();
        ensure(!lost || obs.truncated, "missing truncation")?;
        ensure(
            !obs.truncated || obs.state == "partial",
            "truncation must be partial",
        )?;
        if ["unavailable", "timeout", "cancelled", "failed"].contains(&obs.state.as_str()) {
            ensure(
                self.operations.is_empty()
                    && self.dependencies.is_empty()
                    && !obs.reason.is_empty(),
                "invalid unavailable evidence",
            )?;
        }
        ensure(
            self.warnings.iter().collect::<BTreeSet<_>>().len() == self.warnings.len(),
            "duplicate warning",
        )?;
        let mut ops = BTreeMap::new();
        let mut origins = BTreeSet::new();
        for op in &self.operations {
            ensure(
                ops.insert(op.id.clone(), op).is_none(),
                "duplicate operation",
            )?;
            ensure(
                !op.opcode.is_empty()
                    && op
                        .opcode
                        .bytes()
                        .all(|v| v.is_ascii_uppercase() || v.is_ascii_digit() || v == b'_'),
                "invalid opcode",
            )?;
            ensure(
                op.semantics == semantics(&op.opcode),
                "opcode semantic mismatch",
            )?;
            ensure(
                address(&op.origin.address)
                    && origins.insert((&op.origin.address, op.origin.sequence)),
                "invalid/duplicate origin",
            )?;
            for value in op.inputs.iter().chain(op.output.iter()) {
                value.validate()?;
            }
        }
        for i in 0..ops.len() {
            ensure(
                ops.contains_key(&format!("op:{i}")),
                "invalid/noncontiguous operation ID",
            )?;
        }
        let mut targets = BTreeSet::new();
        let mut edges = BTreeSet::new();
        for dep in &self.dependencies {
            let from = ops.get(&dep.from).ok_or("dangling dependency source")?;
            let to = ops.get(&dep.to).ok_or("dangling dependency target")?;
            let input = to.inputs.get(dep.input).ok_or("invalid operand slot")?;
            ensure(
                from.output.as_ref() == Some(input),
                "dependency storage mismatch",
            )?;
            ensure(
                targets.insert((&dep.to, dep.input)),
                "conflicting dependency",
            )?;
            ensure(
                dep.basis
                    == if self.representation == "raw" {
                        "instruction-local-unique"
                    } else {
                        "recovered-ssa"
                    },
                "invalid proof basis",
            )?;
            edges.insert((dep.from.clone(), dep.to.clone(), dep.input));
        }
        if self.representation == "raw" {
            let mut local: BTreeMap<(String, u128, usize), String> = BTreeMap::new();
            let mut expected = BTreeSet::new();
            let mut current = "";
            let mut straight = true;
            for i in 0..ops.len() {
                let op = ops[&format!("op:{i}")];
                if op.origin.address != current {
                    local.clear();
                    current = &op.origin.address;
                    straight = true;
                }
                for (slot, value) in op.inputs.iter().enumerate() {
                    if value.kind == "unique" {
                        let offset = u128::from_str_radix(&value.offset, 16)
                            .map_err(|_| "unique offset overflow")?;
                        if let Some(producer) =
                            local.get(&(value.space.clone(), offset, value.width))
                        {
                            expected.insert((producer.clone(), op.id.clone(), slot));
                        }
                    }
                }
                if [
                    "BRANCH",
                    "CBRANCH",
                    "BRANCHIND",
                    "CALL",
                    "CALLIND",
                    "CALLOTHER",
                    "RETURN",
                    "UNIMPLEMENTED",
                ]
                .contains(&op.opcode.as_str())
                {
                    local.clear();
                    straight = false;
                }
                if let Some(output) = &op.output {
                    let start = u128::from_str_radix(&output.offset, 16)
                        .map_err(|_| "output offset overflow")?;
                    local.retain(|(space, offset, width), _| {
                        space != &output.space
                            || offset.saturating_add(*width as u128) <= start
                            || start.saturating_add(output.width as u128) <= *offset
                    });
                    if output.kind == "unique" && straight {
                        local.insert((output.space.clone(), start, output.width), op.id.clone());
                    }
                }
            }
            ensure(edges.is_subset(&expected), "unproven Raw link")?;
            ensure(
                obs.truncated || edges == expected,
                "missing proven Raw link",
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn real() -> Evidence {
        serde_json::from_str(include_str!(
            "../../tests/fixtures/pcode_evidence_v0_1/sum_array-high.json"
        ))
        .unwrap()
    }
    #[test]
    fn real_roundtrip_and_unknown_fields() {
        let d = real();
        d.validate().unwrap();
        assert_eq!(
            d,
            serde_json::from_str::<Evidence>(&serde_json::to_string(&d).unwrap()).unwrap()
        );
        let mut v = serde_json::to_value(d).unwrap();
        v["invented"] = true.into();
        assert!(serde_json::from_value::<Evidence>(v).is_err());
    }
    #[test]
    fn provenance_and_dangling_rejection() {
        let mut d = real();
        d.dependencies[0].from = "op:999".into();
        assert!(d.validate().is_err());
        let mut d = real();
        d.source.sha256 = "bad".into();
        assert!(d.validate().is_err());
    }
    #[test]
    fn signedness_and_predicates_are_not_interchangeable() {
        assert_ne!(semantics("INT_LESS"), semantics("INT_SLESS"));
        let mut d = real();
        d.operations[0].semantics = semantics("INT_SDIV");
        assert!(d.validate().is_err());
    }
    #[test]
    fn raw_fixture_and_budget() {
        let mut d: Evidence = serde_json::from_str(include_str!(
            "../../tests/fixtures/pcode_evidence_v0_1/sum_array-raw.json"
        ))
        .unwrap();
        d.validate().unwrap();
        d.configuration.max_operations = 1;
        assert!(d.validate().is_err());
    }
}
