import { PointerEvent as ReactPointerEvent, ReactNode, useCallback, useEffect, useMemo, useRef, useState } from "react";

export type GraphNode = { id: string; label?: string; type?: string; count?: number; collection?: string; indexed_at?: string };
export type GraphEdge = { source: string; target: string; relationship?: string; weight?: number };

/** Node fills stay inside the Black Onyx kit (violet / lavender / silver / slate)
 *  plus semantic danger for hash — avoids off-brand teal/lime on the graph. */
const TYPE_COLORS: Record<string, string> = {
  document: "#A78BFA",
  file: "#6C3CF2",
  ip: "#A9ADB6",
  domain: "#A78BFA",
  url: "#6C3CF2",
  hash: "#ef6875",
  cve: "#A9ADB6",
  technique: "#A78BFA",
  tactic: "#6C3CF2",
  email: "#A9ADB6",
  crypto: "#2F3138",
  asn: "#A9ADB6",
  cidr: "#2F3138",
  mac: "#A78BFA",
  user_agent: "#A9ADB6",
  cpe: "#6C3CF2",
  jarm: "#A78BFA",
  social: "#A9ADB6",
  phone: "#2F3138",
  person: "#A78BFA",
  organization: "#6C3CF2",
  username: "#A9ADB6",
  language: "#2F3138",
};
const FALLBACK_COLOR = "#8fa8ba";
const MAX_RENDERED_NODES = 900;
const NODE_SPACING = 48;
const FRAME_MARGIN = 28;
const LABEL_LIMIT = 160;
const GRAVITY_SPAN = 0.4;

function colorFor(type: string | undefined): string {
  return TYPE_COLORS[(type || "").toLowerCase()] || FALLBACK_COLOR;
}

type Simulation = {
  ids: string[];
  index: Map<string, number>;
  x: Float64Array;
  y: Float64Array;
  dx: Float64Array;
  dy: Float64Array;
  pinned: Uint8Array;
  degree: Int32Array;
  links: Array<[number, number]>;
  width: number;
  height: number;
  temperature: number;
};

/**
 * Layout frame for a node count. Repulsion needs roughly NODE_SPACING between
 * neighbours, so the frame grows with the graph and the view zooms to fit it
 * instead of letting the relaxation drift off-canvas.
 */
function layoutFrame(count: number, width: number, height: number): { width: number; height: number } {
  const area = Math.max(count, 1) * NODE_SPACING * NODE_SPACING;
  // Follow the canvas shape loosely; a frame as wide as a 3:1 canvas leaves the
  // relaxation nothing to push against vertically.
  const aspect = Math.min(2, Math.max(0.7, width / Math.max(height, 1)));
  return {
    width: Math.max(width, Math.round(Math.sqrt(area * aspect))),
    height: Math.max(height, Math.round(Math.sqrt(area / aspect))),
  };
}

function createSimulation(nodes: GraphNode[], edges: GraphEdge[], width: number, height: number, seed: number): Simulation {
  const ids = nodes.map(node => node.id);
  const index = new Map<string, number>();
  ids.forEach((id, position) => index.set(id, position));
  const count = ids.length;
  const x = new Float64Array(count);
  const y = new Float64Array(count);
  const degree = new Int32Array(count);
  const links: Array<[number, number]> = [];

  for (const edge of edges) {
    const from = index.get(edge.source);
    const to = index.get(edge.target);
    if (from === undefined || to === undefined || from === to) continue;
    links.push([from, to]);
    degree[from] += 1;
    degree[to] += 1;
  }

  const frame = layoutFrame(count, width, height);

  // Sunflower seeding spreads nodes evenly across the whole frame, so the
  // relaxation starts near its equilibrium density instead of unwinding a ring.
  // It is deterministic, and a new seed rotates it for a fresh layout.
  const golden = Math.PI * (3 - Math.sqrt(5));
  const spanX = (frame.width / 2) - FRAME_MARGIN;
  const spanY = (frame.height / 2) - FRAME_MARGIN;
  for (let i = 0; i < count; i += 1) {
    const ratio = Math.sqrt((i + 0.5) / Math.max(count, 1));
    const angle = i * golden + seed;
    x[i] = frame.width / 2 + Math.cos(angle) * ratio * spanX;
    y[i] = frame.height / 2 + Math.sin(angle) * ratio * spanY;
  }

  return {
    ids,
    index,
    x,
    y,
    dx: new Float64Array(count),
    dy: new Float64Array(count),
    pinned: new Uint8Array(count),
    degree,
    links,
    width: frame.width,
    height: frame.height,
    temperature: Math.min(frame.width, frame.height) * 0.1,
  };
}

/** One Fruchterman-Reingold style relaxation step. */
function stepSimulation(sim: Simulation): void {
  const count = sim.ids.length;
  if (!count) return;
  const area = sim.width * sim.height;
  const k = Math.sqrt(area / count) * 0.85;
  const { x, y, dx, dy } = sim;
  dx.fill(0);
  dy.fill(0);

  for (let i = 0; i < count; i += 1) {
    for (let j = i + 1; j < count; j += 1) {
      let deltaX = x[i] - x[j];
      let deltaY = y[i] - y[j];
      let distance = Math.hypot(deltaX, deltaY);
      if (distance < 0.01) {
        deltaX = (i % 7) - 3 + 0.5;
        deltaY = (j % 5) - 2 + 0.5;
        distance = Math.hypot(deltaX, deltaY) || 1;
      }
      const repulsion = (k * k) / distance;
      const unitX = (deltaX / distance) * repulsion;
      const unitY = (deltaY / distance) * repulsion;
      dx[i] += unitX;
      dy[i] += unitY;
      dx[j] -= unitX;
      dy[j] -= unitY;
    }
  }

  for (const [from, to] of sim.links) {
    const deltaX = x[from] - x[to];
    const deltaY = y[from] - y[to];
    const distance = Math.hypot(deltaX, deltaY) || 0.01;
    const attraction = (distance * distance) / k;
    const unitX = (deltaX / distance) * attraction;
    const unitY = (deltaY / distance) * attraction;
    dx[from] -= unitX;
    dy[from] -= unitY;
    dx[to] += unitX;
    dy[to] += unitY;
  }

  const centreX = sim.width / 2;
  const centreY = sim.height / 2;
  // Gravity is solved per axis against the repulsion sum so the cloud settles into
  // an ellipse shaped like the frame: too weak and it drifts onto the frame walls,
  // too strong and it packs into a dense ball that wastes canvas space.
  const gravityX = (count * k * k) / Math.pow(sim.width * GRAVITY_SPAN, 2);
  const gravityY = (count * k * k) / Math.pow(sim.height * GRAVITY_SPAN, 2);
  for (let i = 0; i < count; i += 1) {
    dx[i] += (centreX - x[i]) * gravityX;
    dy[i] += (centreY - y[i]) * gravityY;
    if (sim.pinned[i]) continue;
    const displacement = Math.hypot(dx[i], dy[i]) || 1;
    const limit = Math.min(displacement, sim.temperature);
    x[i] += (dx[i] / displacement) * limit;
    y[i] += (dy[i] / displacement) * limit;
    // Keep the relaxation inside its frame so the fitted view stays readable.
    x[i] = Math.min(sim.width - FRAME_MARGIN, Math.max(FRAME_MARGIN, x[i]));
    y[i] = Math.min(sim.height - FRAME_MARGIN, Math.max(FRAME_MARGIN, y[i]));
  }
  sim.temperature = Math.max(sim.temperature * 0.972, 0.35);
}

type Viewport = { scale: number; offsetX: number; offsetY: number };

export function GraphView({ nodes, edges, sidebar }: { nodes: GraphNode[]; edges: GraphEdge[]; sidebar?: ReactNode }) {
  const shellRef = useRef<HTMLDivElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const simRef = useRef<Simulation | null>(null);
  const frameRef = useRef(0);
  const dragRef = useRef<{ node: number } | { pan: { x: number; y: number; offsetX: number; offsetY: number } } | null>(null);
  const [size, setSize] = useState({ width: 960, height: 580 });
  const [, setTick] = useState(0);
  const [seed, setSeed] = useState(0.6);
  const [selected, setSelected] = useState<string>("");
  const [showLabels, setShowLabels] = useState(() => nodes.length <= LABEL_LIMIT);
  const [hiddenTypes, setHiddenTypes] = useState<string[]>([]);
  const [view, setView] = useState<Viewport>({ scale: 1, offsetX: 0, offsetY: 0 });

  const allTypeCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const node of nodes) {
      const type = (node.type || "unknown").toLowerCase();
      counts.set(type, (counts.get(type) || 0) + 1);
    }
    return [...counts.entries()].sort((left, right) => right[1] - left[1]);
  }, [nodes]);

  const visibleNodes = useMemo(
    () => nodes.filter(node => !hiddenTypes.includes((node.type || "unknown").toLowerCase())).slice(0, MAX_RENDERED_NODES),
    [nodes, hiddenTypes],
  );
  const nodeById = useMemo(() => {
    const map = new Map<string, GraphNode>();
    for (const node of visibleNodes) map.set(node.id, node);
    return map;
  }, [visibleNodes]);
  const visibleEdges = useMemo(
    () => edges.filter(edge => nodeById.has(edge.source) && nodeById.has(edge.target)),
    [edges, nodeById],
  );

  // Dense graphs are unreadable with every label drawn, so start them label-free.
  useEffect(() => { setShowLabels(nodes.length <= LABEL_LIMIT); }, [nodes]);

  useEffect(() => {
    const shell = shellRef.current;
    if (!shell || typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(entries => {
      const box = entries[0]?.contentRect;
      if (!box) return;
      const width = Math.max(360, Math.round(box.width));
      const height = Math.max(360, Math.round(box.height));
      setSize(previous => (previous.width === width && previous.height === height ? previous : { width, height }));
    });
    observer.observe(shell);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    simRef.current = createSimulation(visibleNodes, visibleEdges, size.width, size.height, seed);
    setView({ scale: 1, offsetX: 0, offsetY: 0 });
    let frames = 0;
    const budget = visibleNodes.length > 320 ? 180 : 420;
    function run() {
      const sim = simRef.current;
      if (!sim) return;
      const steps = visibleNodes.length > 320 ? 1 : 2;
      for (let i = 0; i < steps; i += 1) stepSimulation(sim);
      frames += steps;
      setTick(value => value + 1);
      if (frames < budget && sim.temperature > 0.4) {
        frameRef.current = requestAnimationFrame(run);
        return;
      }
      // Large graphs relax outside the canvas bounds, so frame them once settled.
      fitRef.current();
    }
    frameRef.current = requestAnimationFrame(run);
    return () => cancelAnimationFrame(frameRef.current);
  }, [visibleNodes, visibleEdges, size.width, size.height, seed]);

  const reheat = useCallback(() => {
    const sim = simRef.current;
    if (!sim) return;
    sim.temperature = Math.min(sim.width, sim.height) * 0.06;
    let frames = 0;
    cancelAnimationFrame(frameRef.current);
    function run() {
      const active = simRef.current;
      if (!active) return;
      stepSimulation(active);
      frames += 1;
      setTick(value => value + 1);
      if (frames < 200 && active.temperature > 0.4) frameRef.current = requestAnimationFrame(run);
    }
    frameRef.current = requestAnimationFrame(run);
  }, []);

  const fitRef = useRef<() => void>(() => {});

  const fit = useCallback(() => {
    const sim = simRef.current;
    if (!sim || !sim.ids.length) return;
    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    for (let i = 0; i < sim.ids.length; i += 1) {
      minX = Math.min(minX, sim.x[i]);
      maxX = Math.max(maxX, sim.x[i]);
      minY = Math.min(minY, sim.y[i]);
      maxY = Math.max(maxY, sim.y[i]);
    }
    const padding = 60;
    const spanX = Math.max(maxX - minX, 1) + padding * 2;
    const spanY = Math.max(maxY - minY, 1) + padding * 2;
    const scale = Math.min(size.width / spanX, size.height / spanY, 2.5);
    setView({
      scale,
      offsetX: size.width / 2 - ((minX + maxX) / 2) * scale,
      offsetY: size.height / 2 - ((minY + maxY) / 2) * scale,
    });
  }, [size.height, size.width]);

  useEffect(() => { fitRef.current = fit; }, [fit]);

  function toGraphPoint(event: { clientX: number; clientY: number }): { x: number; y: number } {
    const rect = svgRef.current?.getBoundingClientRect();
    const localX = event.clientX - (rect?.left || 0);
    const localY = event.clientY - (rect?.top || 0);
    return { x: (localX - view.offsetX) / view.scale, y: (localY - view.offsetY) / view.scale };
  }

  function onNodePointerDown(event: ReactPointerEvent<SVGGElement>, id: string) {
    const sim = simRef.current;
    if (!sim) return;
    const position = sim.index.get(id);
    if (position === undefined) return;
    event.stopPropagation();
    event.currentTarget.setPointerCapture?.(event.pointerId);
    sim.pinned[position] = 1;
    dragRef.current = { node: position };
    setSelected(id);
  }

  function onBackgroundPointerDown(event: ReactPointerEvent<SVGSVGElement>) {
    if (event.button !== 0) return;
    svgRef.current?.setPointerCapture?.(event.pointerId);
    dragRef.current = { pan: { x: event.clientX, y: event.clientY, offsetX: view.offsetX, offsetY: view.offsetY } };
  }

  function onPointerMove(event: ReactPointerEvent<SVGSVGElement>) {
    const drag = dragRef.current;
    if (!drag) return;
    if ("node" in drag) {
      const sim = simRef.current;
      if (!sim) return;
      const point = toGraphPoint(event);
      sim.x[drag.node] = point.x;
      sim.y[drag.node] = point.y;
      setTick(value => value + 1);
      return;
    }
    setView(previous => ({
      ...previous,
      offsetX: drag.pan.offsetX + (event.clientX - drag.pan.x),
      offsetY: drag.pan.offsetY + (event.clientY - drag.pan.y),
    }));
  }

  function onPointerUp() {
    dragRef.current = null;
  }

  // React registers wheel handlers passively on the root, so zoom needs a native
  // non-passive listener to stop the page from scrolling underneath the canvas.
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    function onWheel(event: WheelEvent) {
      event.preventDefault();
      const rect = svg!.getBoundingClientRect();
      const localX = event.clientX - rect.left;
      const localY = event.clientY - rect.top;
      setView(previous => {
        const scale = Math.min(4, Math.max(0.15, previous.scale * (event.deltaY < 0 ? 1.12 : 1 / 1.12)));
        const ratio = scale / previous.scale;
        return {
          scale,
          offsetX: localX - (localX - previous.offsetX) * ratio,
          offsetY: localY - (localY - previous.offsetY) * ratio,
        };
      });
    }
    svg.addEventListener("wheel", onWheel, { passive: false });
    return () => svg.removeEventListener("wheel", onWheel);
  }, []);

  const sim = simRef.current;
  const neighbours = useMemo(() => {
    if (!selected) return null;
    const set = new Set<string>([selected]);
    for (const edge of visibleEdges) {
      if (edge.source === selected) set.add(edge.target);
      else if (edge.target === selected) set.add(edge.source);
    }
    return set;
  }, [selected, visibleEdges]);

  const hiddenCount = useMemo(
    () => nodes.filter(node => hiddenTypes.includes((node.type || "unknown").toLowerCase())).length,
    [nodes, hiddenTypes],
  );

  const toggleType = useCallback((type: string) => {
    setSelected("");
    setHiddenTypes(current => current.includes(type) ? current.filter(value => value !== type) : [...current, type]);
  }, []);

  const selectedNode = selected ? nodeById.get(selected) : undefined;
  const selectedEdges = useMemo(
    () => (selected ? visibleEdges.filter(edge => edge.source === selected || edge.target === selected) : []),
    [selected, visibleEdges],
  );

  function radiusFor(position: number): number {
    const degree = sim?.degree[position] || 0;
    return 7 + Math.min(11, Math.sqrt(degree) * 3.1);
  }

  return <div className="graph-layout">
    <div className="card graph-card">
      <div className="graph-toolbar">
        <div className="graph-counts"><strong>{visibleNodes.length}</strong> nodes · <strong>{visibleEdges.length}</strong> edges{hiddenCount ? <> · <strong>{hiddenCount}</strong> hidden by type</> : null}</div>
        <div className="actions">
          <button type="button" className="secondary compact" onClick={fit}>Fit</button>
          <button type="button" className="secondary compact" onClick={reheat}>Settle</button>
          <button type="button" className="secondary compact" onClick={() => setSeed(value => value + 1.31)}>Re-layout</button>
          <button type="button" className="secondary compact" onClick={() => setShowLabels(value => !value)}>{showLabels ? "Hide labels" : "Show labels"}</button>
          <button type="button" className="secondary compact" onClick={() => { setSelected(""); setView({ scale: 1, offsetX: 0, offsetY: 0 }); }}>Reset view</button>
        </div>
      </div>
      <div className="graph-canvas" ref={shellRef}>
        <svg
          ref={svgRef}
          width={size.width}
          height={size.height}
          role="img"
          aria-label={`Relationship graph with ${visibleNodes.length} nodes and ${visibleEdges.length} edges`}
          onPointerDown={onBackgroundPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={onPointerUp}
          onPointerCancel={onPointerUp}
        >
          <defs>
            <marker id="graph-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="rgba(146,178,199,.5)" />
            </marker>
          </defs>
          <g transform={`translate(${view.offsetX} ${view.offsetY}) scale(${view.scale})`}>
            {sim && visibleEdges.map((edge, position) => {
              const from = sim.index.get(edge.source);
              const to = sim.index.get(edge.target);
              if (from === undefined || to === undefined) return null;
              const active = !neighbours || (neighbours.has(edge.source) && neighbours.has(edge.target));
              const midX = (sim.x[from] + sim.x[to]) / 2;
              const midY = (sim.y[from] + sim.y[to]) / 2;
              const highlighted = !!selected && (edge.source === selected || edge.target === selected);
              return <g key={`${edge.source}->${edge.target}-${edge.relationship || ""}-${position}`} className={active ? "graph-edge" : "graph-edge dimmed"}>
                <line x1={sim.x[from]} y1={sim.y[from]} x2={sim.x[to]} y2={sim.y[to]} markerEnd="url(#graph-arrow)" />
                {highlighted && edge.relationship && <text x={midX} y={midY - 4} className="graph-edge-label">{edge.relationship}</text>}
              </g>;
            })}
            {sim && visibleNodes.map(node => {
              const position = sim.index.get(node.id);
              if (position === undefined) return null;
              const active = !neighbours || neighbours.has(node.id);
              const radius = radiusFor(position);
              return <g
                key={node.id}
                className={`graph-node${active ? "" : " dimmed"}${selected === node.id ? " selected" : ""}`}
                transform={`translate(${sim.x[position]} ${sim.y[position]})`}
                onPointerDown={event => onNodePointerDown(event, node.id)}
                onClick={event => { event.stopPropagation(); setSelected(node.id); }}
              >
                <title>{`${node.type || "node"}: ${node.id}`}</title>
                <circle r={radius} fill={colorFor(node.type)} />
                {(showLabels || (neighbours && neighbours.has(node.id))) && (
                  <text
                    x={radius + 5}
                    y={4}
                    style={{ fontSize: `${(10.5 / Math.min(1, view.scale)).toFixed(2)}px` }}
                  >{node.label || node.id}</text>
                )}
              </g>;
            })}
          </g>
        </svg>
        {!visibleNodes.length && <p className="graph-placeholder">No nodes in this graph.</p>}
      </div>
      <p className="graph-hint">Drag the background to pan, scroll to zoom, drag a node to pin it, click a node to isolate its relationships.</p>
    </div>
    <div className="graph-side">
      {sidebar}
      <section className="card">
        <h3>Node types</h3>
        <p className="graph-hint">Click a type to hide or show it in the canvas.</p>
        <ul className="graph-legend">{allTypeCounts.map(([type, count]) => {
          const hidden = hiddenTypes.includes(type);
          return <li key={type}>
            <button type="button" className={`graph-legend-toggle${hidden ? " off" : ""}`} onClick={() => toggleType(type)} aria-pressed={!hidden}>
              <span className="graph-swatch" style={{ background: hidden ? "transparent" : colorFor(type), borderColor: colorFor(type) }} />
              <span>{type.replace(/_/g, " ")}</span>
              <small>{count}</small>
            </button>
          </li>;
        })}</ul>
      </section>
      <section className="card">
        <h3>Selection</h3>
        {selectedNode ? <>
          <p className="graph-selected-id">{selectedNode.label || selectedNode.id}</p>
          <p className="muted">{selectedNode.type || "node"} · {selectedEdges.length} relationship(s){selectedNode.count && selectedNode.count > 1 ? ` · seen in ${selectedNode.count} item(s)` : ""}</p>
          {selectedNode.collection && <p className="muted">Source: {selectedNode.collection}</p>}
          {selectedNode.indexed_at && <p className="muted">Indexed: {selectedNode.indexed_at}</p>}
          {selectedNode.label && selectedNode.label !== selectedNode.id && <p className="graph-selected-full">{selectedNode.id}</p>}
          <ul className="graph-relations">{selectedEdges.map((edge, position) => <li key={`${edge.source}-${edge.target}-${position}`}>
            <small>{edge.relationship || "related"}</small>
            <span>{edge.source === selected ? `→ ${nodeById.get(edge.target)?.label || edge.target}` : `← ${nodeById.get(edge.source)?.label || edge.source}`}</span>
          </li>)}</ul>
        </> : <p className="muted">Click a node to inspect its edges.</p>}
      </section>
      {visibleNodes.length < nodes.length - hiddenCount && <section className="card"><p className="muted">Showing the first {MAX_RENDERED_NODES} of {nodes.length} nodes to keep the layout responsive.</p></section>}
    </div>
  </div>;
}
