"""Build an isolated, source-pinned Step 10 research adapter; never patch the frozen engine."""

import argparse
import hashlib
import json
import subprocess
import sys

try:
    from .evaluation_protocol import ROOT, AUDIT_DIR, load_protocol, require, serialize
except ImportError:
    from evaluation_protocol import ROOT, AUDIT_DIR, load_protocol, require, serialize

METHOD = ROOT / AUDIT_DIR / "research_adapter"
BUILD = ROOT / AUDIT_DIR / "runtime/research_adapter"
MODULES = "canonical canonical_order fingerprint fingerprint_motifs fingerprint_provenance graph graph_indexes local_subgraph local_subgraph_schema schema seed_validation similarity similarity_observability".split()


def replace_once(text, old, new):
    require(text.count(old) == 1, "research patch no longer applies uniquely: " + old)
    return text.replace(old, new)


def source_inventory():
    paths = ["rust_engine/Cargo.toml", "rust_engine/Cargo.lock"] + [f"rust_engine/src/{m}.rs" for m in MODULES]
    # Code text identity is LF-normalized explicitly; generated compilation bytes
    # are hashed separately. This never changes compiled dataset provenance.
    return {p: hashlib.sha256((ROOT / p).read_text(encoding="utf-8").encode("utf-8")).hexdigest() for p in paths}


def transformed(name):
    text = (ROOT / f"rust_engine/src/{name}.rs").read_text(encoding="utf-8")
    text = text.split("#[cfg(test)]\nmod tests", 1)[0]
    text = text.replace("CanonicalSubgraph", "ResearchGraph").replace("OsgfFingerprint", "ResearchFingerprint")
    if name in {"canonical", "fingerprint", "similarity"}:
        # Distinct contracts even for B: compare feature descriptors/counts, not
        # research document digests, with the frozen B implementation.
        text = text.replace('= "0.1.0";', '= "research-0.1.0";')
    if name == "canonical":
        text = replace_once(text, "pub struct ResearchGraph {", "pub struct ResearchGraph {\n    pub condition: String,")
        text = replace_once(
            text,
            "pub fn from_source(source: &LocalSubgraphDocument) -> Result<Self, String> {",
            """pub fn from_source(source: &LocalSubgraphDocument, condition: &str) -> Result<Self, String> {
        if condition != "A" && condition != "B" { return Err("unknown research condition".into()); }
        let raw = condition == "A";""",
        )
        text = replace_once(text, "let mut result = Self {", "let mut result = Self {\n            condition: condition.into(),")
        text = replace_once(text, "Self::from_source(&self.source_document)?", "Self::from_source(&self.source_document, &self.condition)?")
        text = replace_once(text, 'json!({"schema_version": self.schema_version,', 'json!({"condition": self.condition, "schema_version": self.schema_version,')
        text = replace_once(text, "if let Some(facts) = evidence_facts(node) {", "if let Some(facts) = if raw { raw_evidence_facts(node) } else { evidence_facts(node) } {")
        text = replace_once(text, "if matches!(\n                    node.node_type,", "if !raw && matches!(\n                    node.node_type,")
        text = replace_once(text, "fn edge_facts(edge: &GraphEdge) -> Value {", "fn edge_facts(edge: &GraphEdge, raw: bool) -> Value {")
        text = replace_once(text, ".map(normalize_api)", ".map(|s| if raw { s.to_owned() } else { normalize_api(s) })")
        text = replace_once(text, "facts: edge_facts(edge),", "facts: edge_facts(edge, raw),")
        text = replace_once(
            text,
            "validate_fact_properties(&source)?;",
            """validate_fact_properties(&source)?;
        if raw && source.nodes.iter().any(|n| n.node_type == NodeType::Section
            && n.properties.get("name").is_some_and(|v| !v.is_string())) {
            return Err("research raw section name must be text when present".into());
        }""",
        )
        text += """
// Raw source facts in the SAME feature slots; no addresses or invented targets.
// Strings/categories are exact already. Occurrence counts, role derivation,
// observability and structural labeling are shared preprocessing, not ablations.
fn raw_evidence_facts(node: &GraphNode) -> Option<Value> {
    let mut facts = evidence_facts(node)?;
    match node.node_type {
        NodeType::Api => {
            facts["canonical_value"] = node.properties.get("name")
                .or_else(|| node.properties.get("normalized_name"))?.clone();
        }
        NodeType::Constant => {
            let category = node.properties.get("category");
            let names = node.properties.get("symbolic_names");
            facts["semantic"] = if category.is_none() && names.is_none() { Value::Null }
                else { json!({"raw_category": category, "raw_symbolic_names": names}) };
        }
        NodeType::Section => {
            facts["role"] = json!({"raw_name": node.properties.get("name")});
        }
        _ => {}
    }
    Some(facts)
}
"""
    if name == "fingerprint":
        text = replace_once(text, "ResearchGraph::from_source(&input.source_document)?", "ResearchGraph::from_source(&input.source_document, &input.condition)?")
    return text


def prepare():
    load_protocol()
    pinned = json.loads((METHOD / "source_inventory.json").read_bytes())
    require(source_inventory() == pinned, "research base source changed; explicit adapter revision required")
    sources = {f"src/{name}.rs": transformed(name).encode("utf-8") for name in MODULES}
    sources["src/main.rs"] = (METHOD / "main.rs").read_bytes()
    for name in ("Cargo.toml", "Cargo.lock"):
        sources[name] = (ROOT / "rust_engine" / name).read_bytes()
    for name, raw in sources.items():
        path = BUILD / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() or path.read_bytes() != raw:
            path.write_bytes(raw)
    inventory = {name: hashlib.sha256(raw).hexdigest() for name, raw in sources.items()}
    (BUILD / "generated_sources.json").write_bytes(serialize(inventory))
    return inventory


def executable():
    return BUILD / "target/debug" / ("rust_engine.exe" if sys.platform == "win32" else "rust_engine")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", action="store_true", required=True)
    parser.parse_args()
    prepare()
    subprocess.run(["cargo", "build", "--locked", "--offline", "--manifest-path", str(BUILD / "Cargo.toml")], check=True)
    print("RESEARCH executable (not admitted for corpus evaluation):", executable())
