use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

pub const SEED_RULES_SCHEMA_VERSION: &str = "0.3.0";

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SeedRuleType {
    Api,
    StringCategory,
    ConstantCategory,
    SectionProperty,
    VisibilitySignal,
    UnresolvedCall,
}

impl SeedRuleType {
    fn id_prefix(&self) -> &'static str {
        match self {
            Self::Api => "api.",
            Self::StringCategory => "string_category.",
            Self::ConstantCategory => "constant_category.",
            Self::SectionProperty => "section_property.",
            Self::VisibilitySignal => "visibility_signal.",
            Self::UnresolvedCall => "unresolved_call.",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct SeedRuleMatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normalized_name: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspicious: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub indicator: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SeedRule {
    pub id: String,

    #[serde(rename = "type")]
    pub evidence_type: SeedRuleType,

    #[serde(rename = "match")]
    pub match_condition: SeedRuleMatch,

    pub reason_template: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SeedRulesConfig {
    pub schema_version: String,
    pub rules: Vec<SeedRule>,
}

impl SeedRulesConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != SEED_RULES_SCHEMA_VERSION {
            return Err(format!(
                "unsupported seed rules schema_version '{}'; expected '{}'",
                self.schema_version, SEED_RULES_SCHEMA_VERSION
            ));
        }

        if self.rules.is_empty() {
            return Err("seed rules configuration must contain at least one rule".to_string());
        }

        let mut seen_ids = HashSet::new();
        let mut seen_api_names = HashSet::new();
        let mut seen_string_categories = HashSet::new();
        let mut seen_constant_categories = HashSet::new();
        let mut seen_section_properties = HashSet::new();
        let mut seen_visibility_signals = HashSet::new();
        let mut seen_unresolved_indicators = HashSet::new();

        for rule in &self.rules {
            validate_rule_id(&rule.id, &rule.evidence_type)?;

            if !seen_ids.insert(rule.id.as_str()) {
                return Err(format!("duplicate seed rule id: {}", rule.id));
            }

            if rule.reason_template.trim().is_empty() {
                return Err(format!(
                    "seed rule '{}' reason_template cannot be empty",
                    rule.id
                ));
            }

            if let Some(family) = &rule.family {
                if family.trim().is_empty() {
                    return Err(format!(
                        "seed rule '{}' family cannot be empty when present",
                        rule.id
                    ));
                }
            }

            match rule.evidence_type {
                SeedRuleType::Api => {
                    ensure_only_fields(rule, true, false, false, false, false)?;
                    let normalized_name = nonempty_match_text(
                        &rule.id,
                        "normalized_name",
                        rule.match_condition.normalized_name.as_deref(),
                    )?;
                    require_placeholder(rule, "{normalized_name}")?;
                    if !seen_api_names.insert(normalized_name.to_string()) {
                        return Err(format!(
                            "duplicate API seed trigger for normalized_name: {}",
                            normalized_name
                        ));
                    }
                }
                SeedRuleType::StringCategory => {
                    ensure_only_fields(rule, false, true, false, false, false)?;
                    let category = nonempty_match_text(
                        &rule.id,
                        "category",
                        rule.match_condition.category.as_deref(),
                    )?;
                    validate_canonical_token(category, "string category")?;
                    require_placeholder(rule, "{category}")?;
                    if !seen_string_categories.insert(category.to_string()) {
                        return Err(format!(
                            "duplicate string_category seed trigger for category: {}",
                            category
                        ));
                    }
                }
                SeedRuleType::ConstantCategory => {
                    ensure_only_fields(rule, false, true, false, false, false)?;
                    let category = nonempty_match_text(
                        &rule.id,
                        "category",
                        rule.match_condition.category.as_deref(),
                    )?;
                    validate_canonical_token(category, "constant category")?;
                    require_placeholder(rule, "{category}")?;
                    if !seen_constant_categories.insert(category.to_string()) {
                        return Err(format!(
                            "duplicate constant_category seed trigger for category: {}",
                            category
                        ));
                    }
                }
                SeedRuleType::SectionProperty => {
                    ensure_only_fields(rule, false, false, true, false, false)?;
                    if rule.match_condition.suspicious != Some(true) {
                        return Err(format!(
                            "section_property seed rule '{}' currently requires match.suspicious = true",
                            rule.id
                        ));
                    }
                    require_placeholder(rule, "{section_name}")?;
                    if !seen_section_properties.insert(true) {
                        return Err(
                            "duplicate section_property seed trigger for suspicious=true"
                                .to_string(),
                        );
                    }
                }
                SeedRuleType::VisibilitySignal => {
                    ensure_only_fields(rule, false, false, false, true, false)?;
                    let signal = nonempty_match_text(
                        &rule.id,
                        "signal",
                        rule.match_condition.signal.as_deref(),
                    )?;
                    validate_canonical_token(signal, "visibility signal")?;
                    require_placeholder(rule, "{signal}")?;
                    if !seen_visibility_signals.insert(signal.to_string()) {
                        return Err(format!(
                            "duplicate visibility_signal seed trigger for signal: {}",
                            signal
                        ));
                    }
                }
                SeedRuleType::UnresolvedCall => {
                    ensure_only_fields(rule, false, false, false, false, true)?;
                    let indicator = nonempty_match_text(
                        &rule.id,
                        "indicator",
                        rule.match_condition.indicator.as_deref(),
                    )?;
                    validate_canonical_token(indicator, "unresolved-call indicator")?;
                    if indicator != "unresolved_call" {
                        return Err(format!(
                            "unresolved_call seed rule '{}' currently requires indicator 'unresolved_call'",
                            rule.id
                        ));
                    }
                    require_placeholder(rule, "{indicator}")?;
                    if !seen_unresolved_indicators.insert(indicator.to_string()) {
                        return Err(format!(
                            "duplicate unresolved_call seed trigger for indicator: {}",
                            indicator
                        ));
                    }
                }
            }
        }

        Ok(())
    }
}

pub fn load_seed_rules(path: impl AsRef<Path>) -> Result<SeedRulesConfig, String> {
    let path = path.as_ref();

    let data = fs::read_to_string(path)
        .map_err(|err| format!("failed to read seed rules '{}': {}", path.display(), err))?;

    let config: SeedRulesConfig = serde_json::from_str(&data)
        .map_err(|err| format!("failed to parse seed rules '{}': {}", path.display(), err))?;

    config.validate()?;
    Ok(config)
}

pub fn bundled_seed_rules_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("rules")
        .join("seed_rules.json")
}

fn ensure_only_fields(
    rule: &SeedRule,
    normalized_name: bool,
    category: bool,
    suspicious: bool,
    signal: bool,
    indicator: bool,
) -> Result<(), String> {
    let checks = [
        (
            "normalized_name",
            rule.match_condition.normalized_name.is_some(),
            normalized_name,
        ),
        (
            "category",
            rule.match_condition.category.is_some(),
            category,
        ),
        (
            "suspicious",
            rule.match_condition.suspicious.is_some(),
            suspicious,
        ),
        ("signal", rule.match_condition.signal.is_some(), signal),
        (
            "indicator",
            rule.match_condition.indicator.is_some(),
            indicator,
        ),
    ];

    for (field, present, allowed) in checks {
        if present && !allowed {
            return Err(format!(
                "seed rule '{}' of type {:?} must not define match.{}",
                rule.id, rule.evidence_type, field
            ));
        }
    }

    Ok(())
}

fn nonempty_match_text<'a>(
    rule_id: &str,
    field: &str,
    value: Option<&'a str>,
) -> Result<&'a str, String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("seed rule '{}' requires non-empty match.{}", rule_id, field))
}

fn require_placeholder(rule: &SeedRule, placeholder: &str) -> Result<(), String> {
    if !rule.reason_template.contains(placeholder) {
        return Err(format!(
            "seed rule '{}' reason_template must contain '{}'",
            rule.id, placeholder
        ));
    }
    Ok(())
}

fn validate_rule_id(rule_id: &str, evidence_type: &SeedRuleType) -> Result<(), String> {
    let rule_id = rule_id.trim();

    if rule_id.is_empty() {
        return Err("seed rule id cannot be empty".to_string());
    }

    if !rule_id.starts_with(evidence_type.id_prefix()) {
        return Err(format!(
            "seed rule id '{}' must start with '{}' for its evidence type",
            rule_id,
            evidence_type.id_prefix()
        ));
    }

    if !rule_id.chars().all(|ch| {
        ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '.' || ch == '_' || ch == '-'
    }) {
        return Err(format!(
            "seed rule id '{}' must use only lowercase ASCII letters, digits, '.', '_' or '-'",
            rule_id
        ));
    }

    Ok(())
}

fn validate_canonical_token(value: &str, label: &str) -> Result<(), String> {
    if !value
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
    {
        return Err(format!(
            "{} '{}' must use only lowercase ASCII letters, digits or '_'",
            label, value
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashSet;

    fn rule(
        id: &str,
        evidence_type: SeedRuleType,
        match_condition: SeedRuleMatch,
        reason_template: &str,
    ) -> SeedRule {
        SeedRule {
            id: id.to_string(),
            evidence_type,
            match_condition,
            reason_template: reason_template.to_string(),
            family: Some("test_family".to_string()),
        }
    }

    fn api_rule(id: &str, name: &str) -> SeedRule {
        rule(
            id,
            SeedRuleType::Api,
            SeedRuleMatch {
                normalized_name: Some(name.to_string()),
                ..SeedRuleMatch::default()
            },
            "Function calls API {normalized_name}",
        )
    }

    fn string_rule(id: &str, category: &str) -> SeedRule {
        rule(
            id,
            SeedRuleType::StringCategory,
            SeedRuleMatch {
                category: Some(category.to_string()),
                ..SeedRuleMatch::default()
            },
            "Function references string categorized as {category}",
        )
    }

    fn constant_rule(id: &str, category: &str) -> SeedRule {
        rule(
            id,
            SeedRuleType::ConstantCategory,
            SeedRuleMatch {
                category: Some(category.to_string()),
                ..SeedRuleMatch::default()
            },
            "Function uses constant evidence from category {category}",
        )
    }

    #[test]
    fn bundled_seed_rules_load_and_validate() {
        let config = load_seed_rules(bundled_seed_rules_path())
            .expect("bundled seed_rules.json should load and validate");
        assert_eq!(config.schema_version, SEED_RULES_SCHEMA_VERSION);
        assert_eq!(config.rules.len(), 44);
    }

    #[test]
    fn api_rule_requires_normalized_name() {
        let config = SeedRulesConfig {
            schema_version: SEED_RULES_SCHEMA_VERSION.to_string(),
            rules: vec![rule(
                "api.virtualalloc",
                SeedRuleType::Api,
                SeedRuleMatch::default(),
                "Function calls API {normalized_name}",
            )],
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn string_category_rule_requires_canonical_category() {
        let config = SeedRulesConfig {
            schema_version: SEED_RULES_SCHEMA_VERSION.to_string(),
            rules: vec![string_rule("string_category.powershell", "PowerShell")],
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn constant_category_rule_requires_canonical_category() {
        let config = SeedRulesConfig {
            schema_version: SEED_RULES_SCHEMA_VERSION.to_string(),
            rules: vec![constant_rule(
                "constant_category.memory_protection",
                "MemoryProtection",
            )],
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn section_property_requires_suspicious_true() {
        let config = SeedRulesConfig {
            schema_version: SEED_RULES_SCHEMA_VERSION.to_string(),
            rules: vec![rule(
                "section_property.suspicious",
                SeedRuleType::SectionProperty,
                SeedRuleMatch {
                    suspicious: Some(false),
                    ..SeedRuleMatch::default()
                },
                "Function belongs to suspicious section {section_name}",
            )],
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn visibility_signal_requires_canonical_signal() {
        let config = SeedRulesConfig {
            schema_version: SEED_RULES_SCHEMA_VERSION.to_string(),
            rules: vec![rule(
                "visibility_signal.indirect_call",
                SeedRuleType::VisibilitySignal,
                SeedRuleMatch {
                    signal: Some("IndirectCall".to_string()),
                    ..SeedRuleMatch::default()
                },
                "Function contains visibility signal {signal}",
            )],
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn unresolved_call_rule_requires_expected_indicator() {
        let config = SeedRulesConfig {
            schema_version: SEED_RULES_SCHEMA_VERSION.to_string(),
            rules: vec![rule(
                "unresolved_call.present",
                SeedRuleType::UnresolvedCall,
                SeedRuleMatch {
                    indicator: Some("something_else".to_string()),
                    ..SeedRuleMatch::default()
                },
                "Function contains unresolved call evidence {indicator}",
            )],
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn rule_types_reject_unrelated_match_fields() {
        let config = SeedRulesConfig {
            schema_version: SEED_RULES_SCHEMA_VERSION.to_string(),
            rules: vec![rule(
                "constant_category.memory_protection",
                SeedRuleType::ConstantCategory,
                SeedRuleMatch {
                    category: Some("memory_protection".to_string()),
                    signal: Some("indirect_call".to_string()),
                    ..SeedRuleMatch::default()
                },
                "Function uses constant evidence from category {category}",
            )],
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn duplicate_ids_are_rejected() {
        let entry = api_rule("api.virtualalloc", "VirtualAlloc");
        let config = SeedRulesConfig {
            schema_version: SEED_RULES_SCHEMA_VERSION.to_string(),
            rules: vec![entry.clone(), entry],
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn duplicate_matches_are_rejected_per_rule_type() {
        let config = SeedRulesConfig {
            schema_version: SEED_RULES_SCHEMA_VERSION.to_string(),
            rules: vec![
                constant_rule("constant_category.memory_protection", "memory_protection"),
                constant_rule(
                    "constant_category.memory_protection_alias",
                    "memory_protection",
                ),
            ],
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn unsupported_schema_version_is_rejected() {
        let config = SeedRulesConfig {
            schema_version: "99.0.0".to_string(),
            rules: vec![api_rule("api.virtualalloc", "VirtualAlloc")],
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn scoring_fields_are_rejected_by_contract() {
        for forbidden_field in [
            "weight",
            "priority",
            "score",
            "maliciousness",
            "risk_level",
            "threshold",
        ] {
            let mut value = json!({
                "id": "constant_category.memory_protection",
                "type": "constant_category",
                "match": {"category": "memory_protection"},
                "reason_template": "Function uses constant evidence from category {category}",
                "family": "memory_management"
            });
            value
                .as_object_mut()
                .expect("rule must be object")
                .insert(forbidden_field.to_string(), json!(1));
            assert!(serde_json::from_value::<SeedRule>(value).is_err());
        }
    }

    #[test]
    fn unknown_match_fields_are_rejected() {
        let value = json!({
            "id": "visibility_signal.indirect_call",
            "type": "visibility_signal",
            "match": {"signal": "indirect_call", "score": 30},
            "reason_template": "Function contains visibility signal {signal}",
            "family": "call_visibility"
        });
        assert!(serde_json::from_value::<SeedRule>(value).is_err());
    }

    #[test]
    fn bundled_seed_rules_have_unique_ids() {
        let config =
            load_seed_rules(bundled_seed_rules_path()).expect("bundled seed rules should validate");
        let ids: HashSet<&str> = config.rules.iter().map(|rule| rule.id.as_str()).collect();
        assert_eq!(ids.len(), config.rules.len());
    }

    #[test]
    fn duplicate_visibility_signals_are_rejected() {
        let config = SeedRulesConfig {
            schema_version: SEED_RULES_SCHEMA_VERSION.to_string(),
            rules: vec![
                rule(
                    "visibility_signal.indirect_call",
                    SeedRuleType::VisibilitySignal,
                    SeedRuleMatch {
                        signal: Some("indirect_call".to_string()),
                        ..SeedRuleMatch::default()
                    },
                    "Function contains visibility signal {signal}",
                ),
                rule(
                    "visibility_signal.indirect_call_alias",
                    SeedRuleType::VisibilitySignal,
                    SeedRuleMatch {
                        signal: Some("indirect_call".to_string()),
                        ..SeedRuleMatch::default()
                    },
                    "Function contains visibility signal {signal}",
                ),
            ],
        };
        assert!(config.validate().is_err());
    }
}
