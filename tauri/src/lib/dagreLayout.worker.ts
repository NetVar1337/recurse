/**
 * Dagre's layout, off the main thread.
 *
 * A large function's control-flow graph is hundreds of blocks, and laying it out
 * is a synchronous pass over the whole graph — long enough to freeze the window
 * for the length of it, on the thread that also has to answer the analyst's next
 * click. Running it in a worker means the graph paints when it is ready and the
 * app stays responsive while it is not.
 *
 * Dagre has no worker of its own, so the module is bundled as one: Vite turns
 * this file into a worker entry, and the layout below runs inside it.
 */
import dagre from "@dagrejs/dagre";

/** A node as the layout needs it: an id and the box it occupies. */
export interface LayoutBox {
	id: string;
	width: number;
	height: number;
}

/** An edge as the layout needs it. */
export interface LayoutEdge {
	source: string;
	target: string;
}

/** What the worker is asked to do, and what it sends back. */
export interface LayoutRequest {
	nodes: LayoutBox[];
	edges: LayoutEdge[];
}

/**
 * The centred position of every node, in the same order it was asked for.
 *
 * Positions come back rather than whole nodes because the positions are the
 * only thing layout decides; the nodes themselves never left the main thread.
 */
export type LayoutResponse = { x: number; y: number }[];

/**
 * Lay out a graph top to bottom, and return each node's top-left corner.
 *
 * Dagre reports each node's *centre*, so each is converted back to the
 * top-left React Flow positions at, which is where a node is drawn from.
 *
 * @param request - The nodes and edges to arrange.
 * @returns A position per node, in the order they were given.
 */
export function runLayout({ nodes, edges }: LayoutRequest): LayoutResponse {
	const g = new dagre.graphlib.Graph();
	g.setDefaultEdgeLabel(() => ({}));
	g.setGraph({
		rankdir: "TB",
		nodesep: 22,
		ranksep: 56,
		marginx: 16,
		marginy: 16,
	});
	for (const n of nodes) {
		g.setNode(n.id, { width: n.width, height: n.height });
	}
	for (const e of edges) {
		g.setEdge(e.source, e.target);
	}
	dagre.layout(g);
	return nodes.map((n) => {
		const pos = g.node(n.id);
		return { x: pos.x - n.width / 2, y: pos.y - n.height / 2 };
	});
}

/** What the main thread posts: a request carrying the id it is waiting on. */
type Message = LayoutRequest & { id: number };

/**
 * Answer one layout request.
 *
 * The handler lives here rather than being exported because this file is the
 * worker entry: a worker that only exports a function receives the main thread's
 * message and, having nothing wired to it, never answers.
 *
 * Guarded because the module is also imported directly by its tests, where there
 * is no worker global to attach to.
 */
if (typeof self !== "undefined") {
	self.onmessage = (event: MessageEvent<Message>) => {
		const { id, nodes, edges } = event.data;
		try {
			self.postMessage({ id, positions: runLayout({ nodes, edges }) });
		} catch (e) {
			// Answered with the failure rather than left to time out, so the caller
			// can fall back to laying the graph out itself instead of waiting.
			self.postMessage({ id, error: String(e) });
		}
	};
}
