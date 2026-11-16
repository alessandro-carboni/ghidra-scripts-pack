//! Conservative operational normalization and separately attributable feature view.
use crate::canonical::CanonicalSubgraph;
use crate::fingerprint::OsgfFingerprint;
use crate::graph::NodeType;
use crate::operational_context::{digest, LocalEvidence};
use crate::operational_schema::{ensure, Operation, Origin};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalOperation {
    pub id: String,
    pub context: Value,
    pub descriptor: Value,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalDependency {
    pub from: String,
    pub to: String,
    pub input_role: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Support {
    pub function_id: String,
    pub operation_id: String,
    pub origin: Origin,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalCanonical {
    pub schema_version: String,
    pub source_document: LocalEvidence,
    pub structural: CanonicalSubgraph,
    pub operations: Vec<NormalOperation>,
    pub dependencies: Vec<NormalDependency>,
    pub provenance: BTreeMap<String, Support>,
    pub semantic_digest: String,
}
fn commutative(op: &Operation) -> bool {
    [
        "INT_ADD",
        "INT_MULT",
        "INT_AND",
        "INT_OR",
        "INT_XOR",
        "INT_EQUAL",
        "INT_NOTEQUAL",
        "BOOL_AND",
        "BOOL_OR",
        "BOOL_XOR",
    ]
    .contains(&op.opcode.as_str())
        && op.inputs.len() == 2
        && op.inputs[0].width == op.inputs[1].width
        && op.output.as_ref().is_some_and(|out| {
            if op.semantics.family == "predicate" {
                out.width == 1
            } else {
                out.width == op.inputs[0].width
            }
        })
}
fn descriptor(op: &Operation) -> Value {
    let mut inputs: Vec<Value> = op
        .inputs
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let mut value = json!({"kind":v.kind,"width":v.width,"space":v.space});
            // Stable architecture register IDs and frame-relative stack slots are
            // retained until ABI-aware recovery can justify a stronger abstraction.
            // Dropping them conflates a-b and b-a when both inputs have the same width.
            if v.kind == "register" || v.space == "stack" {
                value["storage_slot"] = json!(v.offset);
            }
            // INDIRECT's iop reference is an analysis handle, not a program literal.
            if op.opcode == "INDIRECT" && i == 1 {
                value = json!({"kind":"analysis_reference","width":v.width});
            } else if v.kind == "constant" {
                let bits = v.offset.trim_start_matches('0');
                value["constant_bits"] = json!(if bits.is_empty() { "0" } else { bits });
            }
            value
        })
        .collect();
    if commutative(op) {
        inputs.sort_by_key(Value::to_string);
    }
    json!({"opcode":op.opcode,"family":op.semantics.family,"signedness":op.semantics.signedness,"inputs":inputs,"output":op.output.as_ref().map(|v|json!({"kind":v.kind,"space":v.space,"width":v.width})),"operand_order":if commutative(op){"commutative"}else{"ordered"}})
}
impl OperationalCanonical {
    pub fn from_source(source: &LocalEvidence) -> Result<Self, String> {
        source.validate()?;
        let mut source = source.clone();
        source
            .operational_evidence
            .sort_by(|a, b| a.function.id.cmp(&b.function.id));
        for doc in &mut source.operational_evidence {
            doc.operations
                .sort_by_key(|o| o.id[3..].parse::<usize>().unwrap());
            doc.dependencies.sort();
            doc.warnings.sort();
        }
        let structural = CanonicalSubgraph::from_source(&source.structural)?;
        let mut operations = Vec::new();
        let mut dependencies = Vec::new();
        let mut provenance = BTreeMap::new();
        for doc in &source.operational_evidence {
            let function = structural
                .nodes
                .iter()
                .find(|n| {
                    n.kind == NodeType::Function
                        && structural
                            .node_sources
                            .get(&n.id)
                            .is_some_and(|nodes| nodes.iter().any(|s| s.id == doc.function.id))
                })
                .ok_or("operational function is not in structural canonical context")?;
            let handle = |id: &str| format!("{}/{}", function.id, id);
            let originals: BTreeMap<_, _> = doc.operations.iter().map(|op| (&op.id, op)).collect();
            for op in &doc.operations {
                let id = handle(&op.id);
                operations.push(NormalOperation {
                    id: id.clone(),
                    context: function.facts.clone(),
                    descriptor: descriptor(op),
                });
                provenance.insert(
                    id,
                    Support {
                        function_id: doc.function.id.clone(),
                        operation_id: op.id.clone(),
                        origin: op.origin.clone(),
                    },
                );
            }
            for dep in &doc.dependencies {
                dependencies.push(NormalDependency {
                    from: handle(&dep.from),
                    to: handle(&dep.to),
                    input_role: if commutative(originals[&dep.to]) {
                        "commutative".into()
                    } else {
                        dep.input.to_string()
                    },
                });
            }
        }
        operations.sort_by(|a, b| a.id.cmp(&b.id));
        dependencies.sort();
        let semantic_digest = digest(
            &json!({"structural":structural.canonical_digest,"operations":operations,"dependencies":dependencies}),
        )?;
        Ok(Self {
            schema_version: "osgf.operational-canonical/0.2.0".into(),
            source_document: source,
            structural,
            operations,
            dependencies,
            provenance,
            semantic_digest,
        })
    }
    pub fn validate(&self) -> Result<(), String> {
        ensure(
            *self == Self::from_source(&self.source_document)?,
            "operational canonical differs from verified source",
        )
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureConfig {
    pub max_two_edge_paths: usize,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Feature {
    pub id: String,
    pub descriptor: Value,
    pub count: u64,
    pub occurrences: Vec<Vec<String>>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalFingerprint {
    pub schema_version: String,
    pub source_canonical: OperationalCanonical,
    pub structural: OsgfFingerprint,
    pub operational_view: Vec<Feature>,
    pub configuration: FeatureConfig,
    pub paths_truncated: bool,
    pub semantic_digest: String,
}
impl OperationalFingerprint {
    pub fn from_canonical(
        canonical: &OperationalCanonical,
        config: FeatureConfig,
    ) -> Result<Self, String> {
        canonical.validate()?;
        ensure(
            config.max_two_edge_paths <= 100_000,
            "path budget exceeds hard resource ceiling",
        )?;
        let structural = OsgfFingerprint::from_canonical(&canonical.structural)?;
        let ops: BTreeMap<_, _> = canonical
            .operations
            .iter()
            .map(|op| (op.id.as_str(), op))
            .collect();
        let mut features: BTreeMap<String, (Value, Vec<Vec<String>>)> = BTreeMap::new();
        let mut add = |desc: Value, occurrence: Vec<String>| {
            let key = desc.to_string();
            features
                .entry(key)
                .or_insert_with(|| (desc, Vec::new()))
                .1
                .push(occurrence);
        };
        let pattern = |id: &str| json!({"context":ops[id].context,"operation":ops[id].descriptor});
        for op in &canonical.operations {
            add(
                json!({"family":"operation","pattern":pattern(&op.id)}),
                vec![op.id.clone()],
            );
        }
        let mut outgoing: BTreeMap<&str, Vec<&NormalDependency>> = BTreeMap::new();
        for dep in &canonical.dependencies {
            add(
                json!({"family":"dependency","producer":pattern(&dep.from),"consumer":pattern(&dep.to),"input_role":dep.input_role}),
                vec![dep.from.clone(), dep.to.clone()],
            );
            outgoing.entry(&dep.from).or_default().push(dep);
        }
        let mut paths = 0;
        let mut paths_truncated = false;
        'outer: for dep in &canonical.dependencies {
            for next in outgoing.get(dep.to.as_str()).into_iter().flatten() {
                if paths == config.max_two_edge_paths {
                    paths_truncated = true;
                    break 'outer;
                }
                add(
                    json!({"family":"two_edge_path","operations":[pattern(&dep.from),pattern(&dep.to),pattern(&next.to)],"input_roles":[dep.input_role,next.input_role]}),
                    vec![dep.from.clone(), dep.to.clone(), next.to.clone()],
                );
                paths += 1;
            }
        }
        let operational_view = features
            .into_values()
            .map(|(descriptor, mut occurrences)| {
                occurrences.sort();
                Ok(Feature {
                    id: digest(&descriptor)?,
                    descriptor,
                    count: occurrences.len() as u64,
                    occurrences,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let science: Vec<_> = operational_view
            .iter()
            .map(|f| json!({"descriptor":f.descriptor,"count":f.count}))
            .collect();
        let semantic_digest = digest(
            &json!({"structural":structural.semantic_digest,"operational":science,"configuration":config}),
        )?;
        Ok(Self {
            schema_version: "0.2.0".into(),
            source_canonical: canonical.clone(),
            structural,
            operational_view,
            configuration: config,
            paths_truncated,
            semantic_digest,
        })
    }
    pub fn validate(&self) -> Result<(), String> {
        ensure(
            *self == Self::from_canonical(&self.source_canonical, self.configuration.clone())?,
            "fingerprint differs from verified operational source",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operational_context::{
        tests::{bundle, config},
        LocalEvidence,
    };
    fn canonical() -> OperationalCanonical {
        let g = bundle();
        OperationalCanonical::from_source(
            &LocalEvidence::from_graph(&g, &g.operational_evidence[0].function.id, config())
                .unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn features_have_exact_occurrences_and_roundtrip() {
        let c = canonical();
        let f = OperationalFingerprint::from_canonical(
            &c,
            FeatureConfig {
                max_two_edge_paths: 4096,
            },
        )
        .unwrap();
        f.validate().unwrap();
        assert!(f
            .operational_view
            .iter()
            .all(|v| v.count == v.occurrences.len() as u64));
        assert!(f
            .operational_view
            .iter()
            .any(|v| v.descriptor["family"] == "two_edge_path"));
    }
    #[test]
    fn permutation_is_deterministic_and_tampering_rejected() {
        let c = canonical();
        let mut source = c.source_document.clone();
        source.operational_evidence[0].operations.reverse();
        source.operational_evidence[0].dependencies.reverse();
        assert_eq!(c, OperationalCanonical::from_source(&source).unwrap());
        let mut bad = c;
        bad.operations[0].descriptor["opcode"] = json!("INT_SUB");
        assert!(bad.validate().is_err());
    }
    #[test]
    fn commutativity_only_for_proven_widths_and_operators() {
        let mut op = canonical().source_document.operational_evidence[0]
            .operations
            .iter()
            .find(|o| o.opcode == "INT_ADD")
            .unwrap()
            .clone();
        let expected = descriptor(&op);
        op.inputs.reverse();
        assert_eq!(expected, descriptor(&op));
        op.opcode = "INT_SUB".into();
        op.semantics = crate::operational_schema::semantics(&op.opcode);
        assert!(!commutative(&op));
        let d = descriptor(&op);
        op.inputs.reverse();
        if op.inputs[0] != op.inputs[1] {
            assert_ne!(d, descriptor(&op));
        }
    }
    #[test]
    fn side_effects_constants_predicates_and_widths_survive() {
        let c = canonical();
        let mut op = c.source_document.operational_evidence[0]
            .operations
            .iter()
            .find(|o| o.opcode == "INT_LESS")
            .unwrap()
            .clone();
        let before = descriptor(&op);
        op.opcode = "INT_SLESS".into();
        op.semantics = crate::operational_schema::semantics(&op.opcode);
        assert_ne!(before, descriptor(&op));
        assert!(c
            .operations
            .iter()
            .any(|o| o.descriptor["opcode"] == "LOAD"));
    }
    #[test]
    fn bounded_paths_qualify_observability() {
        let f = OperationalFingerprint::from_canonical(
            &canonical(),
            FeatureConfig {
                max_two_edge_paths: 0,
            },
        )
        .unwrap();
        assert!(f.paths_truncated);
        assert!(f
            .operational_view
            .iter()
            .all(|f| f.descriptor["family"] != "two_edge_path"));
    }
}
