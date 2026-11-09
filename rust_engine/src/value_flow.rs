//! Opt-in High SSA value view. Bounded structural descriptors are not equivalence proofs.
use crate::operational_context::digest;
use crate::operational_features::{Feature, OperationalFingerprint};
use crate::operational_schema::{ensure, Evidence, Operand, Operation};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

const VERSION: &str = "osgf.value-flow-fingerprint/0.1.0";
const ROUNDS: usize = 2;
const COPY_HOPS: usize = 64;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValueFingerprint {
    pub schema_version: String,
    pub source: OperationalFingerprint,
    pub features: Vec<Feature>,
    pub contracted_copies: BTreeMap<String, String>,
    pub copy_barriers: BTreeMap<String, String>,
    pub paths_truncated: bool,
    pub semantic_digest: String,
}

fn boundary(v: &Operand, analysis_reference: bool) -> Value {
    if analysis_reference {
        return json!({"kind":"analysis_reference","width":v.width});
    }
    let mut d = json!({"kind":v.kind,"space":v.space,"width":v.width});
    if v.kind == "register" || v.space == "stack" {
        d["storage_slot"] = json!(v.offset);
    } else if v.kind == "constant" {
        let bits = v.offset.trim_start_matches('0');
        d["constant_bits"] = json!(if bits.is_empty() { "0" } else { bits });
    }
    d
}

fn temporary(v: &Operand) -> bool {
    matches!(v.kind.as_str(), "register" | "unique") && v.space != "stack"
}

type Links<'a> = BTreeMap<(&'a str, usize), &'a str>;
fn redirects(doc: &Evidence) -> (BTreeMap<String, String>, BTreeMap<String, String>) {
    let ops: BTreeMap<_, _> = doc.operations.iter().map(|o| (o.id.as_str(), o)).collect();
    let links: Links<'_> = doc
        .dependencies
        .iter()
        .map(|d| ((d.to.as_str(), d.input), d.from.as_str()))
        .collect();
    let used: BTreeSet<_> = doc.dependencies.iter().map(|d| d.from.as_str()).collect();
    let next = |id: &str| -> Option<String> {
        let op = ops[id];
        if op.opcode != "COPY" || op.inputs.len() != 1 || !used.contains(id) {
            return None;
        }
        let out = op.output.as_ref()?;
        let producer = *links.get(&(id, 0))?;
        (temporary(out) && temporary(&op.inputs[0]) && out.width == op.inputs[0].width)
            .then(|| producer.to_string())
    };
    let mut barriers = BTreeMap::new();
    let redirects = ops
        .keys()
        .map(|&id| {
            let mut current = id.to_string();
            let mut visited = BTreeSet::new();
            for _ in 0..COPY_HOPS {
                if !visited.insert(current.clone()) {
                    barriers.insert(id.to_string(), "copy_cycle_retained".into());
                    return (id.to_string(), id.to_string());
                }
                match next(&current) {
                    Some(parent) => current = parent,
                    None => return (id.to_string(), current),
                }
            }
            // Cycles or over-budget chains stay unchanged, never guessed equivalent.
            barriers.insert(id.to_string(), "copy_hop_budget_retained".into());
            (id.to_string(), id.to_string())
        })
        .collect();
    (redirects, barriers)
}

impl ValueFingerprint {
    pub fn from_source(source: &OperationalFingerprint) -> Result<Self, String> {
        source.validate()?;
        let canonical = &source.source_canonical;
        let mut grouped: BTreeMap<String, (Value, Vec<Vec<String>>)> = BTreeMap::new();
        let mut contracted_copies = BTreeMap::new();
        let mut copy_barriers = BTreeMap::new();
        let mut path_count = 0;
        let mut paths_truncated = false;
        let mut add = |descriptor: Value, occurrence: Vec<String>| {
            grouped
                .entry(descriptor.to_string())
                .or_insert_with(|| (descriptor, vec![]))
                .1
                .push(occurrence);
        };
        for doc in &canonical.source_document.operational_evidence {
            ensure(
                doc.representation == "high",
                "value-flow requires explicitly recovered High SSA",
            )?;
            let original_ops: BTreeMap<_, _> = canonical
                .provenance
                .iter()
                .filter(|(_, p)| p.function_id == doc.function.id)
                .map(|(id, p)| (p.operation_id.as_str(), id.as_str()))
                .collect();
            let patterns: BTreeMap<_, _> = canonical
                .operations
                .iter()
                .map(|o| (o.id.as_str(), o))
                .collect();
            let (redirects, barriers) = redirects(doc);
            for (id, reason) in barriers {
                copy_barriers.insert(original_ops[id.as_str()].into(), reason);
            }
            for (copy, target) in &redirects {
                if copy != target {
                    contracted_copies.insert(
                        original_ops[copy.as_str()].into(),
                        original_ops[target.as_str()].into(),
                    );
                }
            }
            let ops: BTreeMap<&str, &Operation> = doc
                .operations
                .iter()
                .filter(|op| redirects[&op.id] == op.id)
                .map(|o| (o.id.as_str(), o))
                .collect();
            let links: Links<'_> = doc
                .dependencies
                .iter()
                .filter(|d| ops.contains_key(d.to.as_str()))
                .map(|d| ((d.to.as_str(), d.input), redirects[&d.from].as_str()))
                .collect();
            let descriptor = |op: &Operation, colors: Option<&BTreeMap<String, String>>| {
                let commutative = patterns[original_ops[op.id.as_str()]].descriptor
                    ["operand_order"]
                    == "commutative";
                let mut inputs = Vec::new();
                let mut sharing: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
                for (slot, v) in op.inputs.iter().enumerate() {
                    if let Some(&producer) =
                        links.get(&(op.id.as_str(), slot)).filter(|_| temporary(v))
                    {
                        sharing.entry(producer).or_default().push(slot);
                        inputs.push(json!({"kind":"defined_value","width":v.width,"producer":colors.map(|c| &c[producer])}));
                    } else {
                        inputs.push(boundary(v, op.opcode == "INDIRECT" && slot == 1));
                    }
                }
                if commutative {
                    inputs.sort_by_key(Value::to_string);
                }
                let mut sharing: Vec<_> = sharing.into_values().filter(|v| v.len() > 1).collect();
                sharing.sort();
                json!({"opcode":op.opcode,"family":op.semantics.family,"signedness":op.semantics.signedness,
                    "inputs":inputs,"same_producer_inputs":sharing,
                    "output":op.output.as_ref().map(|v| if temporary(v) {json!({"kind":"defined_value","width":v.width})} else {json!({"kind":v.kind,"space":v.space,"width":v.width})}),
                    "operand_order":if commutative {"commutative"} else {"ordered"}})
            };
            let mut colors: BTreeMap<String, String> = ops
                .values()
                .map(|op| Ok((op.id.clone(), digest(&descriptor(op, None))?)))
                .collect::<Result<_, String>>()?;
            for _ in 0..ROUNDS - 1 {
                colors = ops
                    .values()
                    .map(|op| Ok((op.id.clone(), digest(&descriptor(op, Some(&colors)))?)))
                    .collect::<Result<_, String>>()?;
            }
            let final_patterns: BTreeMap<_, _> = ops.values().map(|op| (op.id.as_str(), json!({"context":patterns[original_ops[op.id.as_str()]].context,"operation":descriptor(op, Some(&colors))}))).collect();
            for (&id, pattern) in &final_patterns {
                add(
                    json!({"family":"operation","pattern":pattern}),
                    vec![original_ops[id].into()],
                );
            }
            let edges: Vec<_> = links
                .iter()
                .map(|(&(to, input), &from)| {
                    let role = if patterns[original_ops[to]].descriptor["operand_order"]
                        == "commutative"
                    {
                        "commutative".into()
                    } else {
                        input.to_string()
                    };
                    (from, to, role)
                })
                .collect();
            let mut outgoing: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
            for (i, (from, to, role)) in edges.iter().enumerate() {
                add(
                    json!({"family":"dependency","producer":final_patterns[from],"consumer":final_patterns[to],"input_role":role}),
                    vec![original_ops[from].into(), original_ops[to].into()],
                );
                outgoing.entry(from).or_default().push(i);
            }
            for (from, to, role) in &edges {
                for &i in outgoing.get(to).into_iter().flatten() {
                    if path_count >= source.configuration.max_two_edge_paths {
                        paths_truncated = true;
                        break;
                    }
                    let (_, end, next_role) = &edges[i];
                    add(
                        json!({"family":"two_edge_path","operations":[final_patterns[from],final_patterns[to],final_patterns[end]],"input_roles":[role,next_role]}),
                        vec![
                            original_ops[from].into(),
                            original_ops[to].into(),
                            original_ops[end].into(),
                        ],
                    );
                    path_count += 1;
                }
            }
        }
        let features: Vec<Feature> = grouped
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
            .collect::<Result<_, String>>()?;
        let science: Vec<_> = features
            .iter()
            .map(|f| json!({"descriptor":f.descriptor,"count":f.count}))
            .collect();
        let semantic_digest = digest(
            &json!({"schema":VERSION,"rounds":ROUNDS,"copy_hops":COPY_HOPS,"max_two_edge_paths":source.configuration.max_two_edge_paths,"features":science}),
        )?;
        Ok(Self {
            schema_version: VERSION.into(),
            source: source.clone(),
            features,
            contracted_copies,
            copy_barriers,
            paths_truncated,
            semantic_digest,
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        ensure(
            *self == Self::from_source(&self.source)?,
            "value fingerprint differs from verified source",
        )
    }
}

pub fn compare(q: &ValueFingerprint, r: &ValueFingerprint) -> Result<Value, String> {
    q.validate()?;
    r.validate()?;
    let old = crate::operational_similarity::compare(&q.source, &r.source)?;
    let counts = |f: &ValueFingerprint| {
        f.features
            .iter()
            .map(|v| (v.descriptor.to_string(), v.count))
            .collect()
    };
    let usable = |f: &ValueFingerprint| {
        f.source
            .source_canonical
            .source_document
            .operational_evidence
            .iter()
            .any(|d| matches!(d.observability.state.as_str(), "complete" | "partial"))
    };
    let (set, multiset, matched) = if usable(q) && usable(r) {
        crate::operational_similarity::jaccard(&counts(q), &counts(r))
    } else {
        (None, None, 0)
    };
    let mean = |a: Option<f64>, b: Option<f64>| match (a, b) {
        (Some(a), Some(b)) => Some((a + b) / 2.0),
        _ => None,
    };
    Ok(
        json!({"schema_version":"osgf.value-flow-similarity/0.1.0","baseline":old,
        "query_semantic_digest":q.semantic_digest,"reference_semantic_digest":r.semantic_digest,
        "normalized":{"set_similarity":set,"multiset_similarity":multiset,"matched_distinct_features":matched,
          "query_features":q.features.len(),"reference_features":r.features.len(),
          "query_contracted_copies":q.contracted_copies.len(),"reference_contracted_copies":r.contracted_copies.len(),
          "paths_truncated":q.paths_truncated||r.paths_truncated,
          "comparison_complete":old["operational"]["comparison_complete"]==true&&!q.paths_truncated&&!r.paths_truncated,
          "query_copy_barriers":q.copy_barriers,"reference_copy_barriers":r.copy_barriers,
          "observability":"Inherits baseline source support; incomplete evidence is not semantic absence; bounded colors may collide"},
        "exact_normalized_mean":{"set_similarity":mean(old["operational"]["set_similarity"].as_f64(),set),"multiset_similarity":mean(old["operational"]["multiset_similarity"].as_f64(),multiset)},
        "decision":null,"policy":"Fixed two-round High SSA view, no recovered-parameter or alias equivalence claim; mean requires both views comparable"}),
    )
}
