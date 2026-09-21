use crate::schema::{build_seed_id, Report, SeedCandidate, SeedEvidence};
use crate::seed_rules::{SeedRuleType, SeedRulesConfig};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const API_NODE_TYPE: &str = "API";
const FUNCTION_NODE_TYPE: &str = "FUNCTION";
const STRING_NODE_TYPE: &str = "STRING";
const STRING_CATEGORY_NODE_TYPE: &str = "STRING_CATEGORY";
const CONSTANT_NODE_TYPE: &str = "CONSTANT";
const SECTION_NODE_TYPE: &str = "SECTION";
const VISIBILITY_INDICATOR_NODE_TYPE: &str = "VISIBILITY_INDICATOR";

const CALLS_API_EDGE_TYPE: &str = "calls_api";
const REFERENCES_STRING_EDGE_TYPE: &str = "references_string";
const HAS_STRING_CATEGORY_EDGE_TYPE: &str = "has_string_category";
const USES_CONSTANT_EDGE_TYPE: &str = "uses_constant";
const BELONGS_TO_SECTION_EDGE_TYPE: &str = "belongs_to_section";
const CONTAINS_INDIRECT_CALL_EDGE_TYPE: &str = "contains_indirect_call";

#[derive(Debug)]
struct SeedAccumulator {
    anchor_function_id: String,
    trigger_id: String,
    reason: String,
    evidence_by_key: BTreeMap<String, SeedEvidence>,
}

pub fn detect_api_seeds_from_report(
    report: &Report,
    rules: &SeedRulesConfig,
) -> Result<Vec<SeedCandidate>, String> {
    let typed_graph = report
        .typed_graph
        .as_ref()
        .ok_or_else(|| "seed detection requires report.typed_graph".to_string())?;

    detect_api_seeds(typed_graph, rules)
}

pub fn detect_api_seeds(
    typed_graph: &Value,
    rules: &SeedRulesConfig,
) -> Result<Vec<SeedCandidate>, String> {
    rules.validate()?;

    let graph = typed_graph
        .as_object()
        .ok_or_else(|| "typed_graph must be a JSON object".to_string())?;

    let nodes = graph
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or_else(|| "typed_graph.nodes must be an array".to_string())?;

    let edges = graph
        .get("edges")
        .and_then(Value::as_array)
        .ok_or_else(|| "typed_graph.edges must be an array".to_string())?;

    let mut function_ids = BTreeSet::new();
    let mut api_names_by_id = BTreeMap::new();

    for node in nodes {
        let Some(node_type) = node.get("type").and_then(Value::as_str) else {
            continue;
        };

        match node_type {
            FUNCTION_NODE_TYPE => {
                let id = required_string(node, "id", "FUNCTION node")?;
                function_ids.insert(id.to_string());
            }
            API_NODE_TYPE => {
                let id = required_string(node, "id", "API node")?;
                let normalized_name = required_string(node, "normalized_name", "API node")?;

                if api_names_by_id
                    .insert(id.to_string(), normalized_name.to_string())
                    .is_some()
                {
                    return Err(format!("duplicate API node id in typed_graph: {id}"));
                }
            }
            _ => {}
        }
    }

    let mut api_rules_by_name = BTreeMap::new();

    for rule in &rules.rules {
        if rule.evidence_type != SeedRuleType::Api {
            continue;
        }

        let normalized_name = rule
            .match_condition
            .normalized_name
            .as_deref()
            .ok_or_else(|| {
                format!(
                    "validated API seed rule '{}' is missing match.normalized_name",
                    rule.id
                )
            })?;

        api_rules_by_name.insert(normalized_name, rule);
    }

    let mut accumulators: BTreeMap<(String, String), SeedAccumulator> = BTreeMap::new();

    for edge in edges {
        if edge.get("type").and_then(Value::as_str) != Some(CALLS_API_EDGE_TYPE) {
            continue;
        }

        let source = required_string(edge, "source", "calls_api edge")?;
        let target = required_string(edge, "target", "calls_api edge")?;

        if !function_ids.contains(source) {
            return Err(format!(
                "calls_api edge source '{}' is not a FUNCTION node in typed_graph",
                source
            ));
        }

        let api_name = api_names_by_id.get(target).ok_or_else(|| {
            format!(
                "calls_api edge target '{}' is not an API node in typed_graph",
                target
            )
        })?;

        let Some(rule) = api_rules_by_name.get(api_name.as_str()).copied() else {
            continue;
        };

        let key = (source.to_string(), rule.id.clone());
        let reason = rule.reason_template.replace("{normalized_name}", api_name);

        let accumulator = accumulators.entry(key).or_insert_with(|| SeedAccumulator {
            anchor_function_id: source.to_string(),
            trigger_id: rule.id.clone(),
            reason,
            evidence_by_key: BTreeMap::new(),
        });

        for callsite in extract_callsites(edge)? {
            let evidence = SeedEvidence {
                kind: "api".to_string(),
                value: api_name.clone(),
                node_id: Some(target.to_string()),
                edge_type: Some(CALLS_API_EDGE_TYPE.to_string()),
                callsite: callsite.clone(),
            };

            let evidence_key = format!(
                "{}\u{1f}{}\u{1f}{}",
                target,
                CALLS_API_EDGE_TYPE,
                callsite.as_deref().unwrap_or("")
            );

            accumulator
                .evidence_by_key
                .entry(evidence_key)
                .or_insert(evidence);
        }
    }

    let mut seeds = Vec::with_capacity(accumulators.len());

    for (_, accumulator) in accumulators {
        let seed_id = build_seed_id(&accumulator.anchor_function_id, &accumulator.trigger_id)?;

        let candidate = SeedCandidate {
            seed_id,
            anchor_function_id: accumulator.anchor_function_id,
            trigger_id: accumulator.trigger_id,
            evidence: accumulator.evidence_by_key.into_values().collect(),
            reason: accumulator.reason,
        };

        candidate.validate()?;
        seeds.push(candidate);
    }

    seeds.sort_by(|left, right| {
        left.anchor_function_id
            .cmp(&right.anchor_function_id)
            .then_with(|| left.trigger_id.cmp(&right.trigger_id))
            .then_with(|| left.seed_id.cmp(&right.seed_id))
    });

    Ok(seeds)
}

pub fn detect_string_category_seeds_from_report(
    report: &Report,
    rules: &SeedRulesConfig,
) -> Result<Vec<SeedCandidate>, String> {
    let typed_graph = report
        .typed_graph
        .as_ref()
        .ok_or_else(|| "seed detection requires report.typed_graph".to_string())?;

    detect_string_category_seeds(typed_graph, rules)
}

pub fn detect_string_category_seeds(
    typed_graph: &Value,
    rules: &SeedRulesConfig,
) -> Result<Vec<SeedCandidate>, String> {
    rules.validate()?;

    let graph = typed_graph
        .as_object()
        .ok_or_else(|| "typed_graph must be a JSON object".to_string())?;

    let nodes = graph
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or_else(|| "typed_graph.nodes must be an array".to_string())?;

    let edges = graph
        .get("edges")
        .and_then(Value::as_array)
        .ok_or_else(|| "typed_graph.edges must be an array".to_string())?;

    let mut function_ids = BTreeSet::new();
    let mut string_values_by_id = BTreeMap::new();
    let mut categories_by_id = BTreeMap::new();

    for node in nodes {
        let Some(node_type) = node.get("type").and_then(Value::as_str) else {
            continue;
        };

        match node_type {
            FUNCTION_NODE_TYPE => {
                let id = required_string(node, "id", "FUNCTION node")?;
                function_ids.insert(id.to_string());
            }
            STRING_NODE_TYPE => {
                let id = required_string(node, "id", "STRING node")?;
                let value = required_string(node, "value", "STRING node")?;

                if string_values_by_id
                    .insert(id.to_string(), value.to_string())
                    .is_some()
                {
                    return Err(format!("duplicate STRING node id in typed_graph: {id}"));
                }
            }
            STRING_CATEGORY_NODE_TYPE => {
                let id = required_string(node, "id", "STRING_CATEGORY node")?;
                let category = required_string(node, "category", "STRING_CATEGORY node")?;

                if categories_by_id
                    .insert(id.to_string(), category.to_string())
                    .is_some()
                {
                    return Err(format!(
                        "duplicate STRING_CATEGORY node id in typed_graph: {id}"
                    ));
                }
            }
            _ => {}
        }
    }

    let mut category_rules_by_name = BTreeMap::new();

    for rule in &rules.rules {
        if rule.evidence_type != SeedRuleType::StringCategory {
            continue;
        }

        let category = rule.match_condition.category.as_deref().ok_or_else(|| {
            format!(
                "validated string_category seed rule '{}' is missing match.category",
                rule.id
            )
        })?;

        category_rules_by_name.insert(category, rule);
    }

    let mut category_ids_by_string: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for edge in edges {
        if edge.get("type").and_then(Value::as_str) != Some(HAS_STRING_CATEGORY_EDGE_TYPE) {
            continue;
        }

        let source = required_string(edge, "source", "has_string_category edge")?;
        let target = required_string(edge, "target", "has_string_category edge")?;

        if !string_values_by_id.contains_key(source) {
            return Err(format!(
                "has_string_category edge source '{}' is not a STRING node in typed_graph",
                source
            ));
        }

        if !categories_by_id.contains_key(target) {
            return Err(format!(
                "has_string_category edge target '{}' is not a STRING_CATEGORY node in typed_graph",
                target
            ));
        }

        category_ids_by_string
            .entry(source.to_string())
            .or_default()
            .insert(target.to_string());
    }

    let mut accumulators: BTreeMap<(String, String), SeedAccumulator> = BTreeMap::new();

    for edge in edges {
        if edge.get("type").and_then(Value::as_str) != Some(REFERENCES_STRING_EDGE_TYPE) {
            continue;
        }

        let source = required_string(edge, "source", "references_string edge")?;
        let target = required_string(edge, "target", "references_string edge")?;

        if !function_ids.contains(source) {
            return Err(format!(
                "references_string edge source '{}' is not a FUNCTION node in typed_graph",
                source
            ));
        }

        let string_value = string_values_by_id.get(target).ok_or_else(|| {
            format!(
                "references_string edge target '{}' is not a STRING node in typed_graph",
                target
            )
        })?;

        let Some(category_ids) = category_ids_by_string.get(target) else {
            continue;
        };

        let reference_sites = extract_reference_sites(edge)?;

        for category_id in category_ids {
            let category = categories_by_id.get(category_id).ok_or_else(|| {
                format!(
                    "STRING category '{}' disappeared from typed_graph index",
                    category_id
                )
            })?;

            let Some(rule) = category_rules_by_name.get(category.as_str()).copied() else {
                continue;
            };

            let key = (source.to_string(), rule.id.clone());
            let reason = rule.reason_template.replace("{category}", category);

            let accumulator = accumulators.entry(key).or_insert_with(|| SeedAccumulator {
                anchor_function_id: source.to_string(),
                trigger_id: rule.id.clone(),
                reason,
                evidence_by_key: BTreeMap::new(),
            });

            let category_evidence = SeedEvidence {
                kind: "string_category".to_string(),
                value: category.clone(),
                node_id: Some(category_id.clone()),
                edge_type: Some(HAS_STRING_CATEGORY_EDGE_TYPE.to_string()),
                callsite: None,
            };

            accumulator
                .evidence_by_key
                .entry(format!(
                    "category\u{1f}{}\u{1f}{}",
                    category_id, HAS_STRING_CATEGORY_EDGE_TYPE
                ))
                .or_insert(category_evidence);

            for reference_site in &reference_sites {
                let string_evidence = SeedEvidence {
                    kind: "string".to_string(),
                    value: string_value.clone(),
                    node_id: Some(target.to_string()),
                    edge_type: Some(REFERENCES_STRING_EDGE_TYPE.to_string()),
                    callsite: reference_site.clone(),
                };

                let evidence_key = format!(
                    "string\u{1f}{}\u{1f}{}\u{1f}{}",
                    target,
                    REFERENCES_STRING_EDGE_TYPE,
                    reference_site.as_deref().unwrap_or("")
                );

                accumulator
                    .evidence_by_key
                    .entry(evidence_key)
                    .or_insert(string_evidence);
            }
        }
    }

    let mut seeds = Vec::with_capacity(accumulators.len());

    for (_, accumulator) in accumulators {
        let seed_id = build_seed_id(&accumulator.anchor_function_id, &accumulator.trigger_id)?;

        let candidate = SeedCandidate {
            seed_id,
            anchor_function_id: accumulator.anchor_function_id,
            trigger_id: accumulator.trigger_id,
            evidence: accumulator.evidence_by_key.into_values().collect(),
            reason: accumulator.reason,
        };

        candidate.validate()?;
        seeds.push(candidate);
    }

    seeds.sort_by(|left, right| {
        left.anchor_function_id
            .cmp(&right.anchor_function_id)
            .then_with(|| left.trigger_id.cmp(&right.trigger_id))
            .then_with(|| left.seed_id.cmp(&right.seed_id))
    });

    Ok(seeds)
}

pub fn detect_constant_category_seeds_from_report(
    report: &Report,
    rules: &SeedRulesConfig,
) -> Result<Vec<SeedCandidate>, String> {
    let typed_graph = report
        .typed_graph
        .as_ref()
        .ok_or_else(|| "seed detection requires report.typed_graph".to_string())?;

    detect_constant_category_seeds(typed_graph, rules)
}

pub fn detect_constant_category_seeds(
    typed_graph: &Value,
    rules: &SeedRulesConfig,
) -> Result<Vec<SeedCandidate>, String> {
    rules.validate()?;

    let graph = typed_graph
        .as_object()
        .ok_or_else(|| "typed_graph must be a JSON object".to_string())?;
    let nodes = graph
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or_else(|| "typed_graph.nodes must be an array".to_string())?;
    let edges = graph
        .get("edges")
        .and_then(Value::as_array)
        .ok_or_else(|| "typed_graph.edges must be an array".to_string())?;

    let mut function_ids = BTreeSet::new();
    let mut constants_by_id: BTreeMap<String, (String, String)> = BTreeMap::new();

    for node in nodes {
        match node.get("type").and_then(Value::as_str) {
            Some(FUNCTION_NODE_TYPE) => {
                function_ids.insert(required_string(node, "id", "FUNCTION node")?.to_string());
            }
            Some(CONSTANT_NODE_TYPE) => {
                let id = required_string(node, "id", "CONSTANT node")?;
                let category = required_string(node, "category", "CONSTANT node")?;
                let display = constant_display_value(node)?;
                if constants_by_id
                    .insert(id.to_string(), (category.to_string(), display))
                    .is_some()
                {
                    return Err(format!("duplicate CONSTANT node id in typed_graph: {id}"));
                }
            }
            _ => {}
        }
    }

    let mut rules_by_category = BTreeMap::new();
    for rule in &rules.rules {
        if rule.evidence_type != SeedRuleType::ConstantCategory {
            continue;
        }
        let category = rule.match_condition.category.as_deref().ok_or_else(|| {
            format!(
                "validated constant_category seed rule '{}' is missing match.category",
                rule.id
            )
        })?;
        rules_by_category.insert(category, rule);
    }

    let mut accumulators: BTreeMap<(String, String), SeedAccumulator> = BTreeMap::new();

    for edge in edges {
        if edge.get("type").and_then(Value::as_str) != Some(USES_CONSTANT_EDGE_TYPE) {
            continue;
        }

        let source = required_string(edge, "source", "uses_constant edge")?;
        let target = required_string(edge, "target", "uses_constant edge")?;

        if !function_ids.contains(source) {
            return Err(format!(
                "uses_constant edge source '{}' is not a FUNCTION node in typed_graph",
                source
            ));
        }

        let (category, display_value) = constants_by_id.get(target).ok_or_else(|| {
            format!(
                "uses_constant edge target '{}' is not a CONSTANT node in typed_graph",
                target
            )
        })?;

        let Some(rule) = rules_by_category.get(category.as_str()).copied() else {
            continue;
        };

        let key = (source.to_string(), rule.id.clone());
        let reason = rule.reason_template.replace("{category}", category);
        let accumulator = accumulators.entry(key).or_insert_with(|| SeedAccumulator {
            anchor_function_id: source.to_string(),
            trigger_id: rule.id.clone(),
            reason,
            evidence_by_key: BTreeMap::new(),
        });

        for use_site in extract_string_sites(edge, "use_sites", "uses_constant edge")? {
            let evidence = SeedEvidence {
                kind: "constant".to_string(),
                value: display_value.clone(),
                node_id: Some(target.to_string()),
                edge_type: Some(USES_CONSTANT_EDGE_TYPE.to_string()),
                callsite: use_site.clone(),
            };
            let evidence_key = format!(
                "constant\u{1f}{}\u{1f}{}\u{1f}{}",
                target,
                category,
                use_site.as_deref().unwrap_or("")
            );
            accumulator
                .evidence_by_key
                .entry(evidence_key)
                .or_insert(evidence);
        }
    }

    finalize_accumulators(accumulators)
}

pub fn detect_section_property_seeds_from_report(
    report: &Report,
    rules: &SeedRulesConfig,
) -> Result<Vec<SeedCandidate>, String> {
    let typed_graph = report
        .typed_graph
        .as_ref()
        .ok_or_else(|| "seed detection requires report.typed_graph".to_string())?;

    detect_section_property_seeds(typed_graph, rules)
}

pub fn detect_section_property_seeds(
    typed_graph: &Value,
    rules: &SeedRulesConfig,
) -> Result<Vec<SeedCandidate>, String> {
    rules.validate()?;

    let graph = typed_graph
        .as_object()
        .ok_or_else(|| "typed_graph must be a JSON object".to_string())?;
    let nodes = graph
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or_else(|| "typed_graph.nodes must be an array".to_string())?;
    let edges = graph
        .get("edges")
        .and_then(Value::as_array)
        .ok_or_else(|| "typed_graph.edges must be an array".to_string())?;

    let mut function_ids = BTreeSet::new();
    let mut sections_by_id: BTreeMap<String, (String, bool)> = BTreeMap::new();

    for node in nodes {
        match node.get("type").and_then(Value::as_str) {
            Some(FUNCTION_NODE_TYPE) => {
                function_ids.insert(required_string(node, "id", "FUNCTION node")?.to_string());
            }
            Some(SECTION_NODE_TYPE) => {
                let id = required_string(node, "id", "SECTION node")?;
                let name = required_string(node, "name", "SECTION node")?;
                let suspicious =
                    node.get("suspicious")
                        .and_then(Value::as_bool)
                        .ok_or_else(|| {
                            format!("SECTION node '{}' requires boolean field 'suspicious'", id)
                        })?;
                if sections_by_id
                    .insert(id.to_string(), (name.to_string(), suspicious))
                    .is_some()
                {
                    return Err(format!("duplicate SECTION node id in typed_graph: {id}"));
                }
            }
            _ => {}
        }
    }

    let rule = rules
        .rules
        .iter()
        .find(|rule| rule.evidence_type == SeedRuleType::SectionProperty)
        .filter(|rule| rule.match_condition.suspicious == Some(true));

    let Some(rule) = rule else {
        return Ok(Vec::new());
    };

    let mut accumulators: BTreeMap<(String, String), SeedAccumulator> = BTreeMap::new();

    for edge in edges {
        if edge.get("type").and_then(Value::as_str) != Some(BELONGS_TO_SECTION_EDGE_TYPE) {
            continue;
        }
        let source = required_string(edge, "source", "belongs_to_section edge")?;
        let target = required_string(edge, "target", "belongs_to_section edge")?;

        if !function_ids.contains(source) {
            return Err(format!(
                "belongs_to_section edge source '{}' is not a FUNCTION node in typed_graph",
                source
            ));
        }
        let (section_name, suspicious) = sections_by_id.get(target).ok_or_else(|| {
            format!(
                "belongs_to_section edge target '{}' is not a SECTION node in typed_graph",
                target
            )
        })?;
        if !*suspicious {
            continue;
        }

        let key = (source.to_string(), rule.id.clone());
        let reason = rule.reason_template.replace("{section_name}", section_name);
        let accumulator = accumulators.entry(key).or_insert_with(|| SeedAccumulator {
            anchor_function_id: source.to_string(),
            trigger_id: rule.id.clone(),
            reason,
            evidence_by_key: BTreeMap::new(),
        });
        let evidence = SeedEvidence {
            kind: "section".to_string(),
            value: section_name.clone(),
            node_id: Some(target.to_string()),
            edge_type: Some(BELONGS_TO_SECTION_EDGE_TYPE.to_string()),
            callsite: None,
        };
        accumulator
            .evidence_by_key
            .entry(format!("section\u{1f}{}", target))
            .or_insert(evidence);
    }

    finalize_accumulators(accumulators)
}

pub fn detect_visibility_signal_seeds_from_report(
    report: &Report,
    rules: &SeedRulesConfig,
) -> Result<Vec<SeedCandidate>, String> {
    let typed_graph = report
        .typed_graph
        .as_ref()
        .ok_or_else(|| "seed detection requires report.typed_graph".to_string())?;

    detect_visibility_signal_seeds(typed_graph, rules)
}

pub fn detect_visibility_signal_seeds(
    typed_graph: &Value,
    rules: &SeedRulesConfig,
) -> Result<Vec<SeedCandidate>, String> {
    rules.validate()?;

    let graph = typed_graph
        .as_object()
        .ok_or_else(|| "typed_graph must be a JSON object".to_string())?;
    let nodes = graph
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or_else(|| "typed_graph.nodes must be an array".to_string())?;
    let edges = graph
        .get("edges")
        .and_then(Value::as_array)
        .ok_or_else(|| "typed_graph.edges must be an array".to_string())?;

    let mut function_ids = BTreeSet::new();
    let mut indicators_by_id: BTreeMap<String, &Value> = BTreeMap::new();

    for node in nodes {
        match node.get("type").and_then(Value::as_str) {
            Some(FUNCTION_NODE_TYPE) => {
                function_ids.insert(required_string(node, "id", "FUNCTION node")?.to_string());
            }
            Some(VISIBILITY_INDICATOR_NODE_TYPE) => {
                let id = required_string(node, "id", "VISIBILITY_INDICATOR node")?;
                if indicators_by_id.insert(id.to_string(), node).is_some() {
                    return Err(format!(
                        "duplicate VISIBILITY_INDICATOR node id in typed_graph: {id}"
                    ));
                }
            }
            _ => {}
        }
    }

    let mut rules_by_signal = BTreeMap::new();
    for rule in &rules.rules {
        if rule.evidence_type != SeedRuleType::VisibilitySignal {
            continue;
        }
        let signal = rule.match_condition.signal.as_deref().ok_or_else(|| {
            format!(
                "validated visibility_signal seed rule '{}' is missing match.signal",
                rule.id
            )
        })?;
        rules_by_signal.insert(signal, rule);
    }

    let mut accumulators: BTreeMap<(String, String), SeedAccumulator> = BTreeMap::new();

    for edge in edges {
        if edge.get("type").and_then(Value::as_str) != Some(CONTAINS_INDIRECT_CALL_EDGE_TYPE) {
            continue;
        }
        let source = required_string(edge, "source", "contains_indirect_call edge")?;
        let target = required_string(edge, "target", "contains_indirect_call edge")?;

        if !function_ids.contains(source) {
            return Err(format!(
                "contains_indirect_call edge source '{}' is not a FUNCTION node in typed_graph",
                source
            ));
        }
        let indicator = indicators_by_id.get(target).copied().ok_or_else(|| {
            format!(
                "contains_indirect_call edge target '{}' is not a VISIBILITY_INDICATOR node in typed_graph",
                target
            )
        })?;
        let linked_function = required_string(indicator, "function", "VISIBILITY_INDICATOR node")?;
        if linked_function != source {
            return Err(format!(
                "VISIBILITY_INDICATOR '{}' belongs to '{}' but edge source is '{}'",
                target, linked_function, source
            ));
        }

        let signals =
            extract_required_string_values(indicator, "signals", "VISIBILITY_INDICATOR node")?;
        for signal in signals {
            let Some(rule) = rules_by_signal.get(signal.as_str()).copied() else {
                continue;
            };
            let callsites = visibility_callsites(indicator, &signal)?;
            let key = (source.to_string(), rule.id.clone());
            let reason = rule.reason_template.replace("{signal}", &signal);
            let accumulator = accumulators.entry(key).or_insert_with(|| SeedAccumulator {
                anchor_function_id: source.to_string(),
                trigger_id: rule.id.clone(),
                reason,
                evidence_by_key: BTreeMap::new(),
            });

            for callsite in callsites {
                let evidence = SeedEvidence {
                    kind: "visibility_signal".to_string(),
                    value: signal.clone(),
                    node_id: Some(target.to_string()),
                    edge_type: Some(CONTAINS_INDIRECT_CALL_EDGE_TYPE.to_string()),
                    callsite: callsite.clone(),
                };
                let evidence_key = format!(
                    "visibility\u{1f}{}\u{1f}{}\u{1f}{}",
                    target,
                    signal,
                    callsite.as_deref().unwrap_or("")
                );
                accumulator
                    .evidence_by_key
                    .entry(evidence_key)
                    .or_insert(evidence);
            }
        }
    }

    finalize_accumulators(accumulators)
}

pub fn detect_unresolved_call_seeds_from_report(
    report: &Report,
    rules: &SeedRulesConfig,
) -> Result<Vec<SeedCandidate>, String> {
    let typed_graph = report
        .typed_graph
        .as_ref()
        .ok_or_else(|| "seed detection requires report.typed_graph".to_string())?;

    detect_unresolved_call_seeds(typed_graph, rules)
}

pub fn detect_unresolved_call_seeds(
    typed_graph: &Value,
    rules: &SeedRulesConfig,
) -> Result<Vec<SeedCandidate>, String> {
    rules.validate()?;

    let graph = typed_graph
        .as_object()
        .ok_or_else(|| "typed_graph must be a JSON object".to_string())?;
    let nodes = graph
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or_else(|| "typed_graph.nodes must be an array".to_string())?;
    let unresolved_calls = graph
        .get("unresolved_calls")
        .and_then(Value::as_array)
        .ok_or_else(|| "typed_graph.unresolved_calls must be an array".to_string())?;

    let mut function_ids = BTreeSet::new();
    for node in nodes {
        if node.get("type").and_then(Value::as_str) == Some(FUNCTION_NODE_TYPE) {
            function_ids.insert(required_string(node, "id", "FUNCTION node")?.to_string());
        }
    }

    let mut rules_by_indicator = BTreeMap::new();
    for rule in &rules.rules {
        if rule.evidence_type != SeedRuleType::UnresolvedCall {
            continue;
        }
        let indicator = rule.match_condition.indicator.as_deref().ok_or_else(|| {
            format!(
                "validated unresolved_call seed rule '{}' is missing match.indicator",
                rule.id
            )
        })?;
        rules_by_indicator.insert(indicator, rule);
    }

    let mut accumulators: BTreeMap<(String, String), SeedAccumulator> = BTreeMap::new();

    for record in unresolved_calls {
        let indicator = required_string(record, "indicator", "unresolved_call record")?;
        let Some(rule) = rules_by_indicator.get(indicator).copied() else {
            continue;
        };
        let caller = required_string(record, "caller", "unresolved_call record")?;
        if !function_ids.contains(caller) {
            return Err(format!(
                "unresolved_call caller '{}' is not a FUNCTION node in typed_graph",
                caller
            ));
        }
        if record.get("unresolved").and_then(Value::as_bool) != Some(true) {
            return Err(format!(
                "unresolved_call record for '{}' must contain unresolved=true",
                caller
            ));
        }
        let callsite = record
            .get("callsite")
            .filter(|value| !value.is_null())
            .map(|value| {
                value
                    .as_str()
                    .map(str::trim)
                    .filter(|text| !text.is_empty())
                    .map(str::to_string)
                    .ok_or_else(|| {
                        "unresolved_call record callsite must be a non-empty string".to_string()
                    })
            })
            .transpose()?;
        let record_reason = required_string(record, "reason", "unresolved_call record")?;

        let key = (caller.to_string(), rule.id.clone());
        let reason = rule.reason_template.replace("{indicator}", indicator);
        let accumulator = accumulators.entry(key).or_insert_with(|| SeedAccumulator {
            anchor_function_id: caller.to_string(),
            trigger_id: rule.id.clone(),
            reason,
            evidence_by_key: BTreeMap::new(),
        });
        let evidence = SeedEvidence {
            kind: "unresolved_call".to_string(),
            value: record_reason.to_string(),
            node_id: None,
            edge_type: None,
            callsite: callsite.clone(),
        };
        let evidence_key = format!(
            "unresolved\u{1f}{}\u{1f}{}",
            callsite.as_deref().unwrap_or(""),
            record_reason
        );
        accumulator
            .evidence_by_key
            .entry(evidence_key)
            .or_insert(evidence);
    }

    finalize_accumulators(accumulators)
}

fn finalize_accumulators(
    accumulators: BTreeMap<(String, String), SeedAccumulator>,
) -> Result<Vec<SeedCandidate>, String> {
    let mut seeds = Vec::with_capacity(accumulators.len());
    for (_, accumulator) in accumulators {
        let seed_id = build_seed_id(&accumulator.anchor_function_id, &accumulator.trigger_id)?;
        let candidate = SeedCandidate {
            seed_id,
            anchor_function_id: accumulator.anchor_function_id,
            trigger_id: accumulator.trigger_id,
            evidence: accumulator.evidence_by_key.into_values().collect(),
            reason: accumulator.reason,
        };
        candidate.validate()?;
        seeds.push(candidate);
    }
    seeds.sort_by(|left, right| {
        left.anchor_function_id
            .cmp(&right.anchor_function_id)
            .then_with(|| left.trigger_id.cmp(&right.trigger_id))
            .then_with(|| left.seed_id.cmp(&right.seed_id))
    });
    Ok(seeds)
}

fn constant_display_value(node: &Value) -> Result<String, String> {
    if let Some(symbolic_names) = node.get("symbolic_names") {
        let symbolic_names = symbolic_names
            .as_array()
            .ok_or_else(|| "CONSTANT node field 'symbolic_names' must be an array".to_string())?;
        let mut names = BTreeSet::new();
        for value in symbolic_names {
            let value = value
                .as_str()
                .map(str::trim)
                .filter(|text| !text.is_empty())
                .ok_or_else(|| "CONSTANT node contains invalid symbolic name".to_string())?;
            names.insert(value.to_string());
        }
        if !names.is_empty() {
            return Ok(names.into_iter().collect::<Vec<_>>().join("|"));
        }
    }
    required_string(node, "value_hex", "CONSTANT node").map(str::to_string)
}

fn extract_string_sites(
    value: &Value,
    field: &str,
    context: &str,
) -> Result<Vec<Option<String>>, String> {
    let Some(values) = value.get(field) else {
        return Ok(vec![None]);
    };
    let values = values
        .as_array()
        .ok_or_else(|| format!("{context} field '{field}' must be an array"))?;
    if values.is_empty() {
        return Ok(vec![None]);
    }
    let mut normalized = BTreeSet::new();
    for item in values {
        let item = item
            .as_str()
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .ok_or_else(|| format!("{context} contains invalid '{field}' value"))?;
        normalized.insert(item.to_string());
    }
    Ok(normalized.into_iter().map(Some).collect())
}

fn extract_required_string_values(
    value: &Value,
    field: &str,
    context: &str,
) -> Result<Vec<String>, String> {
    let values = value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{context} field '{field}' must be an array"))?;
    let mut normalized = BTreeSet::new();
    for item in values {
        let item = item
            .as_str()
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .ok_or_else(|| format!("{context} contains invalid '{field}' value"))?;
        normalized.insert(item.to_string());
    }
    Ok(normalized.into_iter().collect())
}

fn visibility_callsites(indicator: &Value, signal: &str) -> Result<Vec<Option<String>>, String> {
    let field = match signal {
        "indirect_call" => "indirect_callsites",
        "unresolved_call" => "unresolved_indirect_callsites",
        "dynamic_dispatch" => "dynamic_dispatch_callsites",
        _ => return Ok(vec![None]),
    };
    extract_string_sites(indicator, field, "VISIBILITY_INDICATOR node")
}

fn required_string<'a>(value: &'a Value, field: &str, context: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| format!("{context} requires non-empty string field '{field}'"))
}

fn extract_callsites(edge: &Value) -> Result<Vec<Option<String>>, String> {
    if let Some(callsites) = edge.get("callsites") {
        let callsites = callsites
            .as_array()
            .ok_or_else(|| "calls_api edge field 'callsites' must be an array".to_string())?;

        if !callsites.is_empty() {
            let mut normalized = BTreeSet::new();

            for callsite in callsites {
                let callsite = callsite
                    .as_str()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| {
                        "calls_api edge contains an invalid callsite value".to_string()
                    })?;

                normalized.insert(callsite.to_string());
            }

            return Ok(normalized.into_iter().map(Some).collect());
        }
    }

    if let Some(callsite) = edge.get("callsite").filter(|value| !value.is_null()) {
        let callsite = callsite
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                "calls_api edge field 'callsite' must be a non-empty string".to_string()
            })?;

        return Ok(vec![Some(callsite.to_string())]);
    }

    Ok(vec![None])
}

fn extract_reference_sites(edge: &Value) -> Result<Vec<Option<String>>, String> {
    let Some(reference_sites) = edge.get("reference_sites") else {
        return Ok(vec![None]);
    };

    let reference_sites = reference_sites.as_array().ok_or_else(|| {
        "references_string edge field 'reference_sites' must be an array".to_string()
    })?;

    if reference_sites.is_empty() {
        return Ok(vec![None]);
    }

    let mut normalized = BTreeSet::new();

    for reference_site in reference_sites {
        let reference_site = reference_site
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                "references_string edge contains an invalid reference site value".to_string()
            })?;

        normalized.insert(reference_site.to_string());
    }

    Ok(normalized.into_iter().map(Some).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed_rules::{SeedRule, SeedRuleMatch, SEED_RULES_SCHEMA_VERSION};
    use serde_json::json;

    fn api_rule(id: &str, normalized_name: &str) -> SeedRule {
        SeedRule {
            id: id.to_string(),
            evidence_type: SeedRuleType::Api,
            match_condition: SeedRuleMatch {
                normalized_name: Some(normalized_name.to_string()),
                ..SeedRuleMatch::default()
            },
            reason_template: "Function calls API {normalized_name}".to_string(),
            family: Some("test_family".to_string()),
        }
    }

    fn string_category_rule(id: &str, category: &str) -> SeedRule {
        SeedRule {
            id: id.to_string(),
            evidence_type: SeedRuleType::StringCategory,
            match_condition: SeedRuleMatch {
                category: Some(category.to_string()),
                ..SeedRuleMatch::default()
            },
            reason_template: "Function references string categorized as {category}".to_string(),
            family: Some("test_family".to_string()),
        }
    }

    fn rules(entries: Vec<SeedRule>) -> SeedRulesConfig {
        SeedRulesConfig {
            schema_version: SEED_RULES_SCHEMA_VERSION.to_string(),
            rules: entries,
        }
    }

    fn graph(nodes: Vec<Value>, edges: Vec<Value>) -> Value {
        json!({
            "model_version": "0.12.0",
            "nodes": nodes,
            "edges": edges,
            "unresolved_calls": []
        })
    }

    fn function_node(id: &str) -> Value {
        json!({
            "id": id,
            "type": "FUNCTION"
        })
    }

    fn api_node(id: &str, normalized_name: &str) -> Value {
        json!({
            "id": id,
            "type": "API",
            "normalized_name": normalized_name
        })
    }

    fn api_edge(source: &str, target: &str, callsites: &[&str]) -> Value {
        json!({
            "type": "calls_api",
            "source": source,
            "target": target,
            "callsites": callsites,
            "callsite": callsites.first().copied()
        })
    }

    fn string_node(id: &str, value: &str) -> Value {
        json!({
            "id": id,
            "type": "STRING",
            "value": value
        })
    }

    fn string_category_node(id: &str, category: &str) -> Value {
        json!({
            "id": id,
            "type": "STRING_CATEGORY",
            "category": category
        })
    }

    fn string_reference_edge(source: &str, target: &str, reference_sites: &[&str]) -> Value {
        json!({
            "type": "references_string",
            "source": source,
            "target": target,
            "reference_sites": reference_sites,
            "reference_count": reference_sites.len()
        })
    }

    fn string_category_edge(source: &str, target: &str) -> Value {
        json!({
            "type": "has_string_category",
            "source": source,
            "target": target
        })
    }

    fn constant_rule(id: &str, category: &str) -> SeedRule {
        SeedRule {
            id: id.to_string(),
            evidence_type: SeedRuleType::ConstantCategory,
            match_condition: SeedRuleMatch {
                category: Some(category.to_string()),
                ..SeedRuleMatch::default()
            },
            reason_template: "Function uses constant evidence from category {category}".to_string(),
            family: Some("test_family".to_string()),
        }
    }

    fn section_rule() -> SeedRule {
        SeedRule {
            id: "section_property.suspicious".to_string(),
            evidence_type: SeedRuleType::SectionProperty,
            match_condition: SeedRuleMatch {
                suspicious: Some(true),
                ..SeedRuleMatch::default()
            },
            reason_template: "Function belongs to suspicious section {section_name}".to_string(),
            family: Some("test_family".to_string()),
        }
    }

    fn visibility_rule(signal: &str) -> SeedRule {
        SeedRule {
            id: format!("visibility_signal.{signal}"),
            evidence_type: SeedRuleType::VisibilitySignal,
            match_condition: SeedRuleMatch {
                signal: Some(signal.to_string()),
                ..SeedRuleMatch::default()
            },
            reason_template: "Function contains visibility signal {signal}".to_string(),
            family: Some("test_family".to_string()),
        }
    }

    fn unresolved_rule() -> SeedRule {
        SeedRule {
            id: "unresolved_call.present".to_string(),
            evidence_type: SeedRuleType::UnresolvedCall,
            match_condition: SeedRuleMatch {
                indicator: Some("unresolved_call".to_string()),
                ..SeedRuleMatch::default()
            },
            reason_template: "Function contains unresolved call evidence {indicator}".to_string(),
            family: Some("test_family".to_string()),
        }
    }

    fn constant_node(id: &str, category: &str, symbolic_name: &str) -> Value {
        json!({
            "id": id,
            "type": "CONSTANT",
            "category": category,
            "value": 64,
            "value_hex": "0x40",
            "symbolic_names": [symbolic_name],
            "bit_lengths": [32]
        })
    }

    fn constant_edge(source: &str, target: &str, use_sites: &[&str]) -> Value {
        json!({
            "type": "uses_constant",
            "source": source,
            "target": target,
            "use_sites": use_sites,
            "occurrences": use_sites.len(),
            "context_apis": ["VirtualAlloc"]
        })
    }

    fn section_node(id: &str, name: &str, suspicious: bool) -> Value {
        json!({
            "id": id,
            "type": "SECTION",
            "name": name,
            "suspicious": suspicious
        })
    }

    fn section_edge(source: &str, target: &str) -> Value {
        json!({
            "type": "belongs_to_section",
            "source": source,
            "target": target
        })
    }

    fn visibility_node(id: &str, function: &str, signals: &[&str], callsites: &[&str]) -> Value {
        json!({
            "id": id,
            "type": "VISIBILITY_INDICATOR",
            "indicator": "call_visibility",
            "function": function,
            "signals": signals,
            "indirect_callsites": callsites,
            "unresolved_indirect_callsites": [],
            "dynamic_dispatch_callsites": []
        })
    }

    fn visibility_edge(source: &str, target: &str) -> Value {
        json!({
            "type": "contains_indirect_call",
            "source": source,
            "target": target
        })
    }

    fn unresolved_record(caller: &str, callsite: &str) -> Value {
        json!({
            "indicator": "unresolved_call",
            "reason": "no_resolved_function_or_api_target",
            "caller": caller,
            "callee": null,
            "callsite": callsite,
            "direct": false,
            "indirect": true,
            "unresolved": true,
            "occurrences": 1
        })
    }

    fn graph_with_unresolved(
        nodes: Vec<Value>,
        edges: Vec<Value>,
        unresolved_calls: Vec<Value>,
    ) -> Value {
        json!({
            "model_version": "0.12.0",
            "nodes": nodes,
            "edges": edges,
            "unresolved_calls": unresolved_calls
        })
    }

    #[test]
    fn matching_api_creates_seed_on_calling_function() {
        let typed_graph = graph(
            vec![
                function_node("fn:00401000"),
                api_node("api:virtualalloc", "VirtualAlloc"),
            ],
            vec![api_edge("fn:00401000", "api:virtualalloc", &["00401020"])],
        );

        let seeds = detect_api_seeds(
            &typed_graph,
            &rules(vec![api_rule("api.virtualalloc", "VirtualAlloc")]),
        )
        .expect("API trigger detection should succeed");

        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].seed_id, "seed:fn:00401000:api.virtualalloc");
        assert_eq!(seeds[0].anchor_function_id, "fn:00401000");
        assert_eq!(seeds[0].trigger_id, "api.virtualalloc");
        assert_eq!(seeds[0].reason, "Function calls API VirtualAlloc");
        assert_eq!(seeds[0].evidence.len(), 1);
        assert_eq!(seeds[0].evidence[0].callsite.as_deref(), Some("00401020"));
    }

    #[test]
    fn unconfigured_api_does_not_create_seed() {
        let typed_graph = graph(
            vec![
                function_node("fn:00401000"),
                api_node("api:createfile", "CreateFile"),
            ],
            vec![api_edge("fn:00401000", "api:createfile", &["00401020"])],
        );

        let seeds = detect_api_seeds(
            &typed_graph,
            &rules(vec![api_rule("api.virtualalloc", "VirtualAlloc")]),
        )
        .expect("unconfigured APIs should simply produce no seed");

        assert!(seeds.is_empty());
    }

    #[test]
    fn repeated_api_calls_are_aggregated_into_one_seed() {
        let typed_graph = graph(
            vec![
                function_node("fn:00401000"),
                api_node("api:virtualalloc", "VirtualAlloc"),
            ],
            vec![api_edge(
                "fn:00401000",
                "api:virtualalloc",
                &["00401030", "00401020", "00401020"],
            )],
        );

        let seeds = detect_api_seeds(
            &typed_graph,
            &rules(vec![api_rule("api.virtualalloc", "VirtualAlloc")]),
        )
        .expect("repeated calls should aggregate");

        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].evidence.len(), 2);
        assert_eq!(seeds[0].evidence[0].callsite.as_deref(), Some("00401020"));
        assert_eq!(seeds[0].evidence[1].callsite.as_deref(), Some("00401030"));
    }

    #[test]
    fn same_api_in_two_functions_creates_two_seeds() {
        let typed_graph = graph(
            vec![
                function_node("fn:00401000"),
                function_node("fn:00402000"),
                api_node("api:virtualalloc", "VirtualAlloc"),
            ],
            vec![
                api_edge("fn:00402000", "api:virtualalloc", &["00402010"]),
                api_edge("fn:00401000", "api:virtualalloc", &["00401010"]),
            ],
        );

        let seeds = detect_api_seeds(
            &typed_graph,
            &rules(vec![api_rule("api.virtualalloc", "VirtualAlloc")]),
        )
        .expect("both functions should produce seeds");

        assert_eq!(seeds.len(), 2);
        assert_eq!(seeds[0].anchor_function_id, "fn:00401000");
        assert_eq!(seeds[1].anchor_function_id, "fn:00402000");
    }

    #[test]
    fn multiple_matching_apis_in_one_function_create_distinct_trigger_seeds() {
        let typed_graph = graph(
            vec![
                function_node("fn:00401000"),
                api_node("api:virtualalloc", "VirtualAlloc"),
                api_node("api:getprocaddress", "GetProcAddress"),
            ],
            vec![
                api_edge("fn:00401000", "api:getprocaddress", &["00401040"]),
                api_edge("fn:00401000", "api:virtualalloc", &["00401020"]),
            ],
        );

        let seeds = detect_api_seeds(
            &typed_graph,
            &rules(vec![
                api_rule("api.virtualalloc", "VirtualAlloc"),
                api_rule("api.getprocaddress", "GetProcAddress"),
            ]),
        )
        .expect("both API triggers should produce seeds");

        assert_eq!(seeds.len(), 2);
        assert_eq!(seeds[0].trigger_id, "api.getprocaddress");
        assert_eq!(seeds[1].trigger_id, "api.virtualalloc");
    }

    #[test]
    fn seed_detection_is_deterministic_across_node_and_edge_order() {
        let nodes_a = vec![
            function_node("fn:00402000"),
            api_node("api:getprocaddress", "GetProcAddress"),
            function_node("fn:00401000"),
            api_node("api:virtualalloc", "VirtualAlloc"),
        ];
        let edges_a = vec![
            api_edge("fn:00402000", "api:getprocaddress", &["00402030"]),
            api_edge("fn:00401000", "api:virtualalloc", &["00401030"]),
        ];

        let mut nodes_b = nodes_a.clone();
        nodes_b.reverse();
        let mut edges_b = edges_a.clone();
        edges_b.reverse();

        let config = rules(vec![
            api_rule("api.virtualalloc", "VirtualAlloc"),
            api_rule("api.getprocaddress", "GetProcAddress"),
        ]);

        let first = detect_api_seeds(&graph(nodes_a, edges_a), &config)
            .expect("first detection should succeed");
        let second = detect_api_seeds(&graph(nodes_b, edges_b), &config)
            .expect("second detection should succeed");

        assert_eq!(first, second);
    }

    #[test]
    fn malformed_calls_api_endpoint_is_rejected() {
        let typed_graph = graph(
            vec![
                function_node("fn:00401000"),
                api_node("api:virtualalloc", "VirtualAlloc"),
            ],
            vec![api_edge("fn:00999999", "api:virtualalloc", &["00401020"])],
        );

        let result = detect_api_seeds(
            &typed_graph,
            &rules(vec![api_rule("api.virtualalloc", "VirtualAlloc")]),
        );

        assert!(result.is_err());
    }

    #[test]
    fn generated_seed_contains_no_scoring_fields() {
        let typed_graph = graph(
            vec![
                function_node("fn:00401000"),
                api_node("api:virtualalloc", "VirtualAlloc"),
            ],
            vec![api_edge("fn:00401000", "api:virtualalloc", &["00401020"])],
        );

        let seeds = detect_api_seeds(
            &typed_graph,
            &rules(vec![api_rule("api.virtualalloc", "VirtualAlloc")]),
        )
        .expect("seed generation should succeed");

        let serialized = serde_json::to_value(&seeds[0]).expect("seed should serialize");

        for forbidden in [
            "score",
            "priority",
            "confidence",
            "risk_level",
            "legacy_metadata",
        ] {
            assert!(serialized.get(forbidden).is_none());
        }
    }

    #[test]
    fn matching_string_category_creates_seed_on_referencing_function() {
        let typed_graph = graph(
            vec![
                function_node("fn:00401000"),
                string_node("str:00403000", "powershell -enc AAAA"),
                string_category_node("strcat:powershell", "powershell"),
            ],
            vec![
                string_reference_edge("fn:00401000", "str:00403000", &["00401040"]),
                string_category_edge("str:00403000", "strcat:powershell"),
            ],
        );

        let seeds = detect_string_category_seeds(
            &typed_graph,
            &rules(vec![string_category_rule(
                "string_category.powershell",
                "powershell",
            )]),
        )
        .expect("string category trigger detection should succeed");

        assert_eq!(seeds.len(), 1);
        assert_eq!(
            seeds[0].seed_id,
            "seed:fn:00401000:string_category.powershell"
        );
        assert_eq!(seeds[0].anchor_function_id, "fn:00401000");
        assert_eq!(seeds[0].trigger_id, "string_category.powershell");
        assert_eq!(
            seeds[0].reason,
            "Function references string categorized as powershell"
        );
    }

    #[test]
    fn string_category_seed_preserves_category_and_string_provenance() {
        let typed_graph = graph(
            vec![
                function_node("fn:00401000"),
                string_node("str:00403000", "powershell -enc AAAA"),
                string_category_node("strcat:powershell", "powershell"),
            ],
            vec![
                string_reference_edge("fn:00401000", "str:00403000", &["00401050", "00401040"]),
                string_category_edge("str:00403000", "strcat:powershell"),
            ],
        );

        let seeds = detect_string_category_seeds(
            &typed_graph,
            &rules(vec![string_category_rule(
                "string_category.powershell",
                "powershell",
            )]),
        )
        .expect("string category trigger detection should succeed");

        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].evidence.len(), 3);

        let category_evidence = seeds[0]
            .evidence
            .iter()
            .find(|item| item.kind == "string_category")
            .expect("category provenance should be present");

        assert_eq!(category_evidence.value, "powershell");
        assert_eq!(
            category_evidence.node_id.as_deref(),
            Some("strcat:powershell")
        );
        assert_eq!(
            category_evidence.edge_type.as_deref(),
            Some("has_string_category")
        );
        assert!(category_evidence.callsite.is_none());

        let string_evidence: Vec<&SeedEvidence> = seeds[0]
            .evidence
            .iter()
            .filter(|item| item.kind == "string")
            .collect();

        assert_eq!(string_evidence.len(), 2);
        assert_eq!(string_evidence[0].callsite.as_deref(), Some("00401040"));
        assert_eq!(string_evidence[1].callsite.as_deref(), Some("00401050"));
    }

    #[test]
    fn multiple_strings_with_same_category_aggregate_into_one_seed() {
        let typed_graph = graph(
            vec![
                function_node("fn:00401000"),
                string_node("str:00403000", "powershell.exe"),
                string_node("str:00403100", "script.ps1"),
                string_category_node("strcat:powershell", "powershell"),
            ],
            vec![
                string_reference_edge("fn:00401000", "str:00403000", &["00401020"]),
                string_reference_edge("fn:00401000", "str:00403100", &["00401030"]),
                string_category_edge("str:00403000", "strcat:powershell"),
                string_category_edge("str:00403100", "strcat:powershell"),
            ],
        );

        let seeds = detect_string_category_seeds(
            &typed_graph,
            &rules(vec![string_category_rule(
                "string_category.powershell",
                "powershell",
            )]),
        )
        .expect("same-category strings should aggregate");

        assert_eq!(seeds.len(), 1);

        let string_evidence_count = seeds[0]
            .evidence
            .iter()
            .filter(|item| item.kind == "string")
            .count();

        let category_evidence_count = seeds[0]
            .evidence
            .iter()
            .filter(|item| item.kind == "string_category")
            .count();

        assert_eq!(string_evidence_count, 2);
        assert_eq!(category_evidence_count, 1);
    }

    #[test]
    fn same_string_category_in_two_functions_creates_two_seeds() {
        let typed_graph = graph(
            vec![
                function_node("fn:00401000"),
                function_node("fn:00402000"),
                string_node("str:00403000", "http://example.test"),
                string_category_node("strcat:url", "url"),
            ],
            vec![
                string_reference_edge("fn:00402000", "str:00403000", &["00402010"]),
                string_reference_edge("fn:00401000", "str:00403000", &["00401010"]),
                string_category_edge("str:00403000", "strcat:url"),
            ],
        );

        let seeds = detect_string_category_seeds(
            &typed_graph,
            &rules(vec![string_category_rule("string_category.url", "url")]),
        )
        .expect("both functions should produce category seeds");

        assert_eq!(seeds.len(), 2);
        assert_eq!(seeds[0].anchor_function_id, "fn:00401000");
        assert_eq!(seeds[1].anchor_function_id, "fn:00402000");
    }

    #[test]
    fn unconfigured_string_category_does_not_create_seed() {
        let typed_graph = graph(
            vec![
                function_node("fn:00401000"),
                string_node("str:00403000", "C:\\temp\\a.txt"),
                string_category_node("strcat:file_path", "file_path"),
            ],
            vec![
                string_reference_edge("fn:00401000", "str:00403000", &["00401020"]),
                string_category_edge("str:00403000", "strcat:file_path"),
            ],
        );

        let seeds = detect_string_category_seeds(
            &typed_graph,
            &rules(vec![string_category_rule(
                "string_category.powershell",
                "powershell",
            )]),
        )
        .expect("unconfigured category should not fail detection");

        assert!(seeds.is_empty());
    }

    #[test]
    fn string_category_detection_is_deterministic_across_graph_order() {
        let nodes_a = vec![
            string_category_node("strcat:url", "url"),
            function_node("fn:00402000"),
            string_node("str:00403100", "http://two.test"),
            function_node("fn:00401000"),
            string_node("str:00403000", "http://one.test"),
        ];

        let edges_a = vec![
            string_category_edge("str:00403100", "strcat:url"),
            string_reference_edge("fn:00402000", "str:00403100", &["00402020"]),
            string_reference_edge("fn:00401000", "str:00403000", &["00401020"]),
            string_category_edge("str:00403000", "strcat:url"),
        ];

        let mut nodes_b = nodes_a.clone();
        nodes_b.reverse();

        let mut edges_b = edges_a.clone();
        edges_b.reverse();

        let config = rules(vec![string_category_rule("string_category.url", "url")]);

        let first = detect_string_category_seeds(&graph(nodes_a, edges_a), &config)
            .expect("first detection should succeed");

        let second = detect_string_category_seeds(&graph(nodes_b, edges_b), &config)
            .expect("second detection should succeed");

        assert_eq!(first, second);
    }

    #[test]
    fn malformed_references_string_endpoint_is_rejected() {
        let typed_graph = graph(
            vec![
                function_node("fn:00401000"),
                string_node("str:00403000", "powershell.exe"),
                string_category_node("strcat:powershell", "powershell"),
            ],
            vec![
                string_reference_edge("fn:00999999", "str:00403000", &["00401020"]),
                string_category_edge("str:00403000", "strcat:powershell"),
            ],
        );

        let result = detect_string_category_seeds(
            &typed_graph,
            &rules(vec![string_category_rule(
                "string_category.powershell",
                "powershell",
            )]),
        );

        assert!(result.is_err());
    }

    #[test]
    fn malformed_string_category_endpoint_is_rejected() {
        let typed_graph = graph(
            vec![
                function_node("fn:00401000"),
                string_node("str:00403000", "powershell.exe"),
                string_category_node("strcat:powershell", "powershell"),
            ],
            vec![
                string_reference_edge("fn:00401000", "str:00403000", &["00401020"]),
                string_category_edge("str:00999999", "strcat:powershell"),
            ],
        );

        let result = detect_string_category_seeds(
            &typed_graph,
            &rules(vec![string_category_rule(
                "string_category.powershell",
                "powershell",
            )]),
        );

        assert!(result.is_err());
    }

    #[test]
    fn report_round_trip_preserves_typed_graph_for_seed_detection() {
        let typed_graph = graph(
            vec![
                function_node("fn:00401000"),
                api_node("api:virtualalloc", "VirtualAlloc"),
            ],
            vec![api_edge("fn:00401000", "api:virtualalloc", &["00401020"])],
        );

        let input = json!({
            "typed_graph": typed_graph
        });

        let report: Report =
            serde_json::from_value(input).expect("report should deserialize typed_graph");

        assert!(report.typed_graph.is_some());

        let serialized = serde_json::to_value(&report).expect("report should serialize");

        assert!(serialized.get("typed_graph").is_some());
    }

    #[test]
    fn matching_constant_category_creates_seed() {
        let typed_graph = graph(
            vec![
                function_node("fn:00401000"),
                constant_node(
                    "const:memory_protection:0x40",
                    "memory_protection",
                    "PAGE_EXECUTE_READWRITE",
                ),
            ],
            vec![constant_edge(
                "fn:00401000",
                "const:memory_protection:0x40",
                &["00401020"],
            )],
        );
        let seeds = detect_constant_category_seeds(
            &typed_graph,
            &rules(vec![constant_rule(
                "constant_category.memory_protection",
                "memory_protection",
            )]),
        )
        .expect("constant trigger should succeed");
        assert_eq!(seeds.len(), 1);
        assert_eq!(
            seeds[0].seed_id,
            "seed:fn:00401000:constant_category.memory_protection"
        );
        assert_eq!(seeds[0].evidence[0].value, "PAGE_EXECUTE_READWRITE");
        assert_eq!(seeds[0].evidence[0].callsite.as_deref(), Some("00401020"));
    }

    #[test]
    fn multiple_constants_same_category_aggregate_into_one_seed() {
        let typed_graph = graph(
            vec![
                function_node("fn:00401000"),
                constant_node("const:registry_flags:0x10", "registry_flags", "KEY_NOTIFY"),
                constant_node("const:registry_flags:0x20019", "registry_flags", "KEY_READ"),
            ],
            vec![
                constant_edge("fn:00401000", "const:registry_flags:0x10", &["00401020"]),
                constant_edge("fn:00401000", "const:registry_flags:0x20019", &["00401030"]),
            ],
        );
        let seeds = detect_constant_category_seeds(
            &typed_graph,
            &rules(vec![constant_rule(
                "constant_category.registry_flags",
                "registry_flags",
            )]),
        )
        .expect("constant aggregation should succeed");
        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].evidence.len(), 2);
    }

    #[test]
    fn unconfigured_constant_category_creates_no_seed() {
        let typed_graph = graph(
            vec![
                function_node("fn:00401000"),
                constant_node("const:registry_flags:0x10", "registry_flags", "KEY_NOTIFY"),
            ],
            vec![constant_edge(
                "fn:00401000",
                "const:registry_flags:0x10",
                &["00401020"],
            )],
        );
        let seeds = detect_constant_category_seeds(
            &typed_graph,
            &rules(vec![constant_rule(
                "constant_category.memory_protection",
                "memory_protection",
            )]),
        )
        .expect("unconfigured constant should not fail");
        assert!(seeds.is_empty());
    }

    #[test]
    fn malformed_constant_edge_is_rejected() {
        let typed_graph = graph(
            vec![function_node("fn:00401000")],
            vec![constant_edge(
                "fn:00401000",
                "const:memory_protection:0x40",
                &["00401020"],
            )],
        );
        let result = detect_constant_category_seeds(
            &typed_graph,
            &rules(vec![constant_rule(
                "constant_category.memory_protection",
                "memory_protection",
            )]),
        );
        assert!(result.is_err());
    }

    #[test]
    fn suspicious_section_creates_seed_for_member_function() {
        let typed_graph = graph(
            vec![
                function_node("fn:00401000"),
                section_node("sec:00400000", ".packed", true),
            ],
            vec![section_edge("fn:00401000", "sec:00400000")],
        );
        let seeds = detect_section_property_seeds(&typed_graph, &rules(vec![section_rule()]))
            .expect("section trigger should succeed");
        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].trigger_id, "section_property.suspicious");
        assert_eq!(seeds[0].evidence[0].value, ".packed");
    }

    #[test]
    fn normal_section_creates_no_seed() {
        let typed_graph = graph(
            vec![
                function_node("fn:00401000"),
                section_node("sec:00400000", ".text", false),
            ],
            vec![section_edge("fn:00401000", "sec:00400000")],
        );
        let seeds = detect_section_property_seeds(&typed_graph, &rules(vec![section_rule()]))
            .expect("normal section should not fail");
        assert!(seeds.is_empty());
    }

    #[test]
    fn malformed_section_endpoint_is_rejected() {
        let typed_graph = graph(
            vec![function_node("fn:00401000")],
            vec![section_edge("fn:00401000", "sec:00999999")],
        );
        let result = detect_section_property_seeds(&typed_graph, &rules(vec![section_rule()]));
        assert!(result.is_err());
    }

    #[test]
    fn indirect_call_visibility_creates_seed_and_preserves_callsites() {
        let indicator_id = "vis:call_visibility:fn:00401000";
        let typed_graph = graph(
            vec![
                function_node("fn:00401000"),
                visibility_node(
                    indicator_id,
                    "fn:00401000",
                    &["indirect_call"],
                    &["00401030", "00401020"],
                ),
            ],
            vec![visibility_edge("fn:00401000", indicator_id)],
        );
        let seeds = detect_visibility_signal_seeds(
            &typed_graph,
            &rules(vec![visibility_rule("indirect_call")]),
        )
        .expect("visibility trigger should succeed");
        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].evidence.len(), 2);
        assert_eq!(seeds[0].evidence[0].callsite.as_deref(), Some("00401020"));
        assert_eq!(seeds[0].evidence[1].callsite.as_deref(), Some("00401030"));
    }

    #[test]
    fn visibility_edge_function_mismatch_is_rejected() {
        let indicator_id = "vis:call_visibility:fn:00402000";
        let typed_graph = graph(
            vec![
                function_node("fn:00401000"),
                function_node("fn:00402000"),
                visibility_node(
                    indicator_id,
                    "fn:00402000",
                    &["indirect_call"],
                    &["00402020"],
                ),
            ],
            vec![visibility_edge("fn:00401000", indicator_id)],
        );
        let result = detect_visibility_signal_seeds(
            &typed_graph,
            &rules(vec![visibility_rule("indirect_call")]),
        );
        assert!(result.is_err());
    }

    #[test]
    fn unresolved_call_record_creates_seed() {
        let typed_graph = graph_with_unresolved(
            vec![function_node("fn:00401000")],
            vec![],
            vec![unresolved_record("fn:00401000", "00401050")],
        );
        let seeds = detect_unresolved_call_seeds(&typed_graph, &rules(vec![unresolved_rule()]))
            .expect("unresolved call trigger should succeed");
        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].trigger_id, "unresolved_call.present");
        assert_eq!(seeds[0].evidence[0].kind, "unresolved_call");
        assert_eq!(seeds[0].evidence[0].callsite.as_deref(), Some("00401050"));
    }

    #[test]
    fn multiple_unresolved_calls_same_function_aggregate() {
        let typed_graph = graph_with_unresolved(
            vec![function_node("fn:00401000")],
            vec![],
            vec![
                unresolved_record("fn:00401000", "00401050"),
                unresolved_record("fn:00401000", "00401060"),
            ],
        );
        let seeds = detect_unresolved_call_seeds(&typed_graph, &rules(vec![unresolved_rule()]))
            .expect("unresolved calls should aggregate");
        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].evidence.len(), 2);
    }

    #[test]
    fn unresolved_call_with_missing_function_is_rejected() {
        let typed_graph = graph_with_unresolved(
            vec![function_node("fn:00401000")],
            vec![],
            vec![unresolved_record("fn:00999999", "00401050")],
        );
        let result = detect_unresolved_call_seeds(&typed_graph, &rules(vec![unresolved_rule()]));
        assert!(result.is_err());
    }
}
