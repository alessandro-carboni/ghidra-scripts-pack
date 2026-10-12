import cytoscape, { type Core, type StylesheetJson } from "cytoscape";
import type { Graph } from "./contracts";
export const colors: Record<string, string> = {
  FUNCTION: "#80A9CF",
  API: "#77C6BD",
  STRING: "#B4A0CF",
  STRING_CATEGORY: "#A6BA83",
  CONSTANT: "#CCA474",
  SECTION: "#7D95AD",
  VISIBILITY_INDICATOR: "#C5B477",
};
const shapes: Record<string, string> = {
  FUNCTION: "round-rectangle",
  API: "round-tag",
  STRING: "round-rectangle",
  STRING_CATEGORY: "hexagon",
  CONSTANT: "diamond",
  SECTION: "rectangle",
  VISIBILITY_INDICATOR: "ellipse",
};
export function styles(): StylesheetJson {
  return [
    {
      selector: "node",
      style: {
        "background-color": "#80A9CF",
        width: 38,
        height: 27,
        label: "data(shortLabel)",
        color: "#dce5f3",
        "font-size": 11,
        "text-valign": "bottom",
        "text-margin-y": 8,
        "text-outline-color": "#101722",
        "text-outline-width": 2,
      },
    },
    ...Object.entries(colors).map(([type, color]) => ({
      selector: 'node[type = "' + type + '"]',
      style: { "background-color": color, shape: shapes[type] },
    })),
    {
      selector: "node[?anchor]",
      style: {
        "border-width": 5,
        "border-color": "#8df0df",
        "border-opacity": 1,
        width: 52,
        height: 38,
      },
    },
    {
      selector: "node[?trigger]",
      style: {
        "border-width": 3,
        "border-style": "dashed",
        "border-color": "#efe9c6",
      },
    },
    {
      selector: "edge",
      style: {
        width: 1.2,
        "line-color": "#40536b",
        "target-arrow-color": "#647e9c",
        "target-arrow-shape": "triangle",
        "curve-style": "bezier",
        "arrow-scale": 0.65,
        opacity: 0.65,
      },
    },
    {
      selector: ":selected",
      style: {
        "border-width": 4,
        "border-color": "#ffffff",
        "line-color": "#c0eee8",
        "target-arrow-color": "#c0eee8",
        opacity: 1,
      },
    },
    { selector: ".hidden", style: { display: "none" } },
  ] as StylesheetJson;
}
export function loadGraph(cy: Core, graph: Graph) {
  cy.batch(() => {
    cy.elements().remove();
    cy.add(
      graph.nodes.map((n) => ({
        data: {
          ...n,
          shortLabel:
            (n.anchor ? "◎ " : n.trigger ? "◆ " : "") +
            (n.role ? n.role + " · " : "") +
            (n.unresolved ? "[?" + n.unresolved + "] " : "") +
            n.label.slice(0, 48),
        },
      })),
    );
    cy.add(graph.edges.map((e) => ({ data: e })));
  });
}
export function applyVisibility(cy: Core, ids: string[]) {
  const visible = new Set(ids);
  cy.batch(() => {
    cy.elements().forEach((e) => {
      e.toggleClass("hidden", !visible.has(e.id()));
    });
  });
}
export function createGraph(container: HTMLElement): Core {
  return cytoscape({
    container,
    style: styles(),
    elements: [],
    wheelSensitivity: 0.25,
    minZoom: 0.03,
    maxZoom: 6,
    selectionType: "single",
    boxSelectionEnabled: false,
  });
}
