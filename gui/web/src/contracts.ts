export const version = "0.1.0";
export type Node = {
  id: string;
  type: string;
  label: string;
  anchor: boolean;
  trigger: boolean;
  role: string;
  unresolved: number;
};
export type Edge = { id: string; source: string; target: string; type: string };
export type Graph = { nodes: Node[]; edges: Edge[] };
export type Message = { version: string; type: string; payload?: any };
const commands = new Set([
  "initialize",
  "loadGraph",
  "clearGraph",
  "setSelection",
  "setFilters",
  "fit",
  "setLayout",
  "setLabelMode",
  "focusNode",
  "exportPng",
]);
export function parseMessage(value: unknown): Message {
  if (!value || typeof value !== "object")
    throw Error("Invalid bridge message");
  const m = value as Message;
  if (m.version !== version || !commands.has(m.type))
    throw Error("Unsupported bridge message");
  if (m.type === "loadGraph") {
    const g = m.payload as Graph;
    if (!g || !Array.isArray(g.nodes) || !Array.isArray(g.edges))
      throw Error("Invalid visual graph");
    const ids = new Set(g.nodes.map((n) => n.id));
    if (
      ids.size !== g.nodes.length ||
      g.edges.some((e) => !ids.has(e.source) || !ids.has(e.target))
    )
      throw Error("Invalid topology");
  }
  return m;
}
