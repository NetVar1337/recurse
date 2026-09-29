import { describe, expect, it } from "vitest";

import { deliverToSelf, selfMessages } from "../../vitest.setup";

import { runLayout, type LayoutRequest } from "./dagreLayout.worker";

/** The graph margin the layout asks dagre for, mirrored here. */
const MARGIN = 16;

/**
 * Two blocks, one jumping to the other: the smallest graph that has a shape.
 *
 * @returns A request for a two-block graph.
 */
function twoBlocks(): LayoutRequest {
	return {
		nodes: [
			{ id: "a", width: 380, height: 80 },
			{ id: "b", width: 380, height: 80 },
		],
		edges: [{ source: "a", target: "b" }],
	};
}

describe("runLayout", () => {
	it("returns one position per node, in the order given", () => {
		const request = twoBlocks();
		const positions = runLayout(request);
		expect(positions).toHaveLength(request.nodes.length);
	});

	it("places a node below the one it jumps to", () => {
		// `rankdir: "TB"` — the graph reads top to bottom, so the block that jumps
		// to another is above it.
		const [a, b] = runLayout(twoBlocks());
		expect(b.y).toBeGreaterThan(a.y);
	});

	it("reports a position as a top-left corner, not a centre", () => {
		// Dagre reports each node's centre; React Flow draws from the top-left, so
		// each comes back minus half the node's own size. A lone node sits one
		// `marginx` in from the edge, so a top-left reading is the margin itself —
		// a centre reading would be the margin plus half the width.
		const [only] = runLayout({
			nodes: [{ id: "a", width: 380, height: 80 }],
			edges: [],
		});
		expect(only.x).toBe(MARGIN);
		expect(only.y).toBe(MARGIN);
	});

	it("places disconnected nodes without throwing", () => {
		// A function can have blocks nothing jumps to or from — an unreachable
		// tail, or a partial decode.
		const positions = runLayout({
			nodes: [
				{ id: "a", width: 380, height: 80 },
				{ id: "b", width: 380, height: 80 },
			],
			edges: [],
		});
		expect(positions).toHaveLength(2);
	});

	it("handles an empty graph", () => {
		expect(runLayout({ nodes: [], edges: [] })).toEqual([]);
	});

	it("answers a posted request, which is the whole point of the worker", () => {
		// A worker file that only exports this function receives the main thread's
		// message and, with nothing wired to it, never answers — which left the
		// graph panel on "building graph…" forever. Asserting that the handler
		// exists and posts a reply is the only thing that catches that.
		expect(typeof self.onmessage).toBe("function");
		deliverToSelf({ id: 7, ...twoBlocks() });

		const posted = selfMessages();
		expect(posted).toHaveLength(1);
		const reply = posted[0] as { id: number; positions: unknown[] };
		expect(reply.id).toBe(7);
		expect(reply.positions).toHaveLength(2);
	});

	it("answers with the failure rather than staying silent", () => {
		// The other half of the same contract: a request the layout cannot run has
		// to come back as an error. A malformed message — one from a main thread
		// that disagrees about the shape — is a real way to get here, and staying
		// silent on it would leave the caller on its timeout.
		deliverToSelf({ id: 9, nodes: null, edges: [] });

		const posted = selfMessages();
		expect(posted).toHaveLength(1);
		expect((posted[0] as { id: number }).id).toBe(9);
		expect((posted[0] as { error?: string }).error).toBeTruthy();
	});
});
