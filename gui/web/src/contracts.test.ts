import { describe, it, expect } from "vitest";
import cytoscape from "cytoscape";
import { parseMessage } from "./contracts";
import { loadGraph, applyVisibility } from "./graph";
describe("bridge and display-only graph", () => {
  it("rejects unknown versions/commands", () => {
    expect(() => parseMessage({ version: "2", type: "loadGraph" })).toThrow();
    expect(() =>
      parseMessage({ version: "0.1.0", type: "detectSeeds" }),
    ).toThrow();
  });
  it("rejects missing endpoints", () =>
    expect(() =>
      parseMessage({
        version: "0.1.0",
        type: "loadGraph",
        payload: { nodes: [], edges: [{ source: "absent", target: "absent" }] },
      }),
    ).toThrow());
  it("preserves IDs and topology when hiding/resetting", () => {
    const graph = {
      nodes: [
        {
          id: "fn:1",
          type: "FUNCTION",
          label: "fn",
          anchor: true,
          trigger: false,
          role: "",
          unresolved: 1,
        },
        {
          id: "api:2",
          type: "API",
          label: "api",
          anchor: false,
          trigger: true,
          role: "",
          unresolved: 0,
        },
      ],
      edges: [
        {
          id: "view-edge:0",
          source: "fn:1",
          target: "api:2",
          type: "calls_api",
        },
      ],
    };
    const before = JSON.stringify(graph);
    const cy = cytoscape({ headless: true });
    loadGraph(cy, graph);
    applyVisibility(cy, ["fn:1"]);
    expect(cy.nodes().length).toBe(2);
    expect(cy.edges().length).toBe(1);
    expect(cy.getElementById("api:2").hasClass("hidden")).toBe(true);
    applyVisibility(cy, ["fn:1", "api:2", "view-edge:0"]);
    expect(cy.elements(".hidden").length).toBe(0);
    expect(JSON.stringify(graph)).toBe(before);
    cy.destroy();
  });
});
