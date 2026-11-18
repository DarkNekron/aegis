// Cytoscape.js wrapper. Elements come from the API already capped (AEGIS_UI_MAX_ELEMENTS), so the whole
// directory is never rendered at once; the explorer expands neighbourhoods incrementally instead.

import { useEffect, useRef } from "react";
import cytoscape, { type Core, type ElementDefinition, type StylesheetJson } from "cytoscape";
import type { GraphElements } from "../services/types";

const KIND_STYLE: Record<string, { color: string; shape: string }> = {
  User: { color: "#4c8df6", shape: "ellipse" },
  ServiceAccount: { color: "#22b8cf", shape: "ellipse" },
  Group: { color: "#9b7bf0", shape: "round-rectangle" },
  Computer: { color: "#3fb27f", shape: "round-diamond" },
  Domain: { color: "#e5484d", shape: "star" },
  OU: { color: "#c3a24a", shape: "round-tag" },
  Container: { color: "#8b95a5", shape: "round-tag" },
  GPO: { color: "#f08c3a", shape: "round-hexagon" },
};
export const LEGEND = Object.entries(KIND_STYLE);

const STYLE: StylesheetJson = [
  { selector: "node", style: {
      "background-color": "#8b95a5", label: "data(short)", color: "#c9d1dc", "font-size": 9, "text-valign": "bottom",
      "text-margin-y": 4, width: 26, height: 26, "border-width": 1, "border-color": "#0b0d10",
      "text-wrap": "ellipsis", "text-max-width": "110px" } },
  ...Object.entries(KIND_STYLE).map(([kind, s]) => ({
    selector: `node[kind = "${kind}"]`, style: { "background-color": s.color, shape: s.shape as never } })),
  { selector: "node[?tier0]", style: { "border-width": 3, "border-color": "#e5484d", width: 32, height: 32 } },
  { selector: "node[?placeholder]", style: { "background-opacity": 0.35, "border-style": "dashed" } },
  { selector: "node[?center]", style: { "overlay-color": "#22b8cf", "overlay-opacity": 0.25, "overlay-padding": 6 } },
  { selector: "edge", style: {
      width: 1.2, "line-color": "#3a4352", "target-arrow-color": "#3a4352", "target-arrow-shape": "triangle",
      "curve-style": "bezier", "arrow-scale": 0.8, label: "data(kind)", "font-size": 7, color: "#7d8796",
      "text-rotation": "autorotate", "text-background-color": "#111419", "text-background-opacity": 0.8,
      "text-background-padding": "1px" } },
  { selector: "edge[!traversable]", style: { "line-style": "dotted", opacity: 0.55 } },
  { selector: "edge[?conditional]", style: { "line-style": "dashed", "line-color": "#f5c24c", "target-arrow-color": "#f5c24c" } },
  { selector: "edge[?step]", style: { width: 2.5, "line-color": "#22b8cf", "target-arrow-color": "#22b8cf", color: "#e3e8ef", "font-size": 9 } },
  { selector: ":selected", style: { "border-color": "#22b8cf", "border-width": 3, "line-color": "#22b8cf" } },
];

function shortName(label: unknown): string {
  const text = String(label ?? "");
  return text.split("@")[0]!.split(".")[0]!.slice(0, 28);
}

export function CytoscapeGraph({ elements, layout = "cose", height = 520, center, onNodeSelect, onNodeExpand }: {
  elements: GraphElements; layout?: "cose" | "path" | "concentric"; height?: number; center?: number;
  onNodeSelect?: (id: number) => void; onNodeExpand?: (id: number) => void;
}) {
  const container = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);
  const handlers = useRef({ onNodeSelect, onNodeExpand });
  handlers.current = { onNodeSelect, onNodeExpand };

  useEffect(() => {
    if (!container.current) return;
    const instance = cytoscape({ container: container.current, style: STYLE, minZoom: 0.15, maxZoom: 3 });
    instance.on("tap", "node", (e) => handlers.current.onNodeSelect?.(Number(e.target.id())));
    instance.on("dbltap", "node", (e) => handlers.current.onNodeExpand?.(Number(e.target.id())));
    cy.current = instance;
    return () => { instance.destroy(); cy.current = null; };
  }, []);

  useEffect(() => {
    const instance = cy.current;
    if (!instance) return;
    const defs: ElementDefinition[] = [
      ...elements.nodes.map((n) => ({ group: "nodes" as const, data: { ...n.data, short: shortName(n.data.label),
                                                                        center: center !== undefined && n.data.id === String(center) } })),
      ...elements.edges.map((e) => ({ group: "edges" as const, data: { ...e.data } })),
    ];
    instance.elements().remove();
    instance.add(defs);
    const options = layout === "path"
      ? { name: "breadthfirst", directed: true, spacingFactor: 1.4, padding: 30,
          roots: elements.nodes.length ? [`#${elements.nodes[0]!.data.id}`] : undefined }
      : layout === "concentric"
        ? { name: "concentric", padding: 30, minNodeSpacing: 70, spacingFactor: 1.2,
            concentric: (n: cytoscape.NodeSingular) => (n.data("center") ? 10 : n.data("tier0") ? 5 : 1) }
        : { name: "cose", animate: false, padding: 30, nodeRepulsion: () => 9000, idealEdgeLength: () => 90 };
    instance.layout(options as cytoscape.LayoutOptions).run();
    instance.fit(undefined, 30);
    if (instance.zoom() > 1.6) {  // small graphs: do not blow nodes up to fill the canvas
      instance.zoom(1.6);
      instance.center();
    }
  }, [elements, layout, center]);

  return <div ref={container} style={{ height }} className="w-full rounded-md border border-border bg-surface-0" />;
}

export function GraphLegend() {
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted">
      {LEGEND.map(([kind, s]) => (
        <span key={kind} className="inline-flex items-center gap-1.5"><span className="inline-block h-2.5 w-2.5 rounded-full" style={{ backgroundColor: s.color }} />{kind}</span>
      ))}
      <span className="inline-flex items-center gap-1.5"><span className="inline-block h-2.5 w-2.5 rounded-full border-2 border-sev-critical" />tier-0</span>
      <span>– – conditional</span><span>····· informational (not traversed)</span>
    </div>
  );
}
