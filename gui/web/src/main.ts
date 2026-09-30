import "./styles.css";
import type { LayoutOptions } from "cytoscape";
import { createGraph, loadGraph, applyVisibility } from "./graph";
import { parseMessage, version } from "./contracts";
declare global {
  interface Window {
    chrome?: {
      webview: {
        postMessage(message: unknown): void;
        addEventListener(
          name: string,
          cb: (e: { data: unknown }) => void,
        ): void;
      };
    };
  }
}
const cy = createGraph(document.getElementById("graph")!);
let layoutName = "concentric";
let labelMode = "progressive";
function send(type: string, payload?: unknown) {
  window.chrome?.webview.postMessage({ version, type, payload });
}
function labels() {
  const z = cy.zoom();
  cy.style()
    .selector("node")
    .style(
      "label",
      labelMode === "none" || (labelMode === "progressive" && z < 0.55)
        ? ""
        : labelMode === "all" || z > 1.5
          ? "data(label)"
          : "data(shortLabel)",
    )
    .update();
}
function layout() {
  send("layoutStarted");
  const started = performance.now();
  cy.elements(":visible")
    .layout({
      name: layoutName,
      animate: false,
      fit: true,
      padding: 45,
      ...(layoutName === "cose"
        ? {
            randomize: false,
            numIter: 300,
            componentSpacing: 80,
            nodeRepulsion: 8000,
            idealEdgeLength: 90,
          }
        : {}),
      stop: () => {
        labels();
        send("layoutCompleted", {
          nodes: cy.nodes(":visible").length,
          edges: cy.edges(":visible").length,
          renderMs: performance.now() - started,
        });
      },
    } as LayoutOptions)
    .run();
}
cy.on("zoom", labels);
cy.on("tap", "node", (e) => send("nodeSelected", { id: e.target.id() }));
cy.on("tap", "edge", (e) => send("edgeSelected", { id: e.target.id() }));
cy.on("tap", (e) => {
  if (e.target === cy) {
    cy.elements().unselect();
    send("backgroundSelected");
  }
});
window.chrome?.webview.addEventListener("message", (e) => {
  try {
    const m = parseMessage(e.data);
    const p = m.payload;
    switch (m.type) {
      case "initialize":
        break;
      case "loadGraph":
        loadGraph(cy, p);
        document.getElementById("empty")!.style.display = "none";
        layoutName = ["cose", "concentric", "grid"].includes(p.layout)
          ? p.layout
          : "cose";
        layout();
        break;
      case "clearGraph":
        cy.elements().remove();
        document.getElementById("empty")!.style.display = "flex";
        break;
      case "setFilters":
        applyVisibility(cy, p.ids);
        send("viewChanged", {
          nodes: cy.nodes(":visible").length,
          edges: cy.edges(":visible").length,
        });
        break;
      case "setSelection":
        cy.elements().unselect();
        if (p?.id) {
          const selected = cy.getElementById(p.id);
          selected.select();
          if (p.notify && selected.length)
            send(selected.isNode() ? "nodeSelected" : "edgeSelected", {
              id: p.id,
            });
        }
        break;
      case "focusNode": {
        const n = cy.getElementById(p.id);
        if (n.length && !n.hasClass("hidden")) {
          cy.elements().unselect();
          n.select();
          cy.animate(
            { center: { eles: n }, zoom: Math.max(cy.zoom(), 1.4) },
            { duration: 180 },
          );
          send("nodeSelected", { id: p.id });
        }
        break;
      }
      case "fit":
        cy.fit(cy.elements(":visible"), 45);
        break;
      case "setLayout":
        if (!["concentric", "cose", "grid"].includes(p.name))
          throw Error("Unsupported layout");
        layoutName = p.name;
        layout();
        break;
      case "setLabelMode":
        labelMode = p.mode;
        labels();
        break;
      case "exportPng":
        send("pngExported", {
          data: cy.png({
            output: "base64",
            bg: "#101722",
            scale: 2,
            full: false,
          }),
        });
        break;
    }
  } catch (error) {
    send("renderError", { message: String(error) });
  }
});
send("ready");
