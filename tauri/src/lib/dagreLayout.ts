import {
	runLayout,
	type LayoutBox,
	type LayoutEdge,
	type LayoutRequest,
	type LayoutResponse,
} from "./dagreLayout.worker";

export type { LayoutBox, LayoutEdge };

/**
 * A dagre layout worker, or null where workers are not available.
 *
 * Built on first use rather than at module scope, so that importing this
 * module — which the graph panel does eagerly at mount, before the analyst has
 * opened a graph — does not construct a worker that may never be used.
 */
let worker: Worker | null = null;
let seq = 0;

/**
 * How long a layout may take before it is done on this thread instead.
 *
 * A worker that never answers — because its module failed to load, or it threw
 * something the error event did not carry — would otherwise leave the graph
 * panel on "building graph…" with no way back. Laying out a control-flow graph
 * takes milliseconds, so a wait this long means something is wrong, and doing
 * the work here is always better than waiting for a reply that is not coming.
 */
const LAYOUT_TIMEOUT_MS = 4_000;

/** A layout in flight, and how to settle it. */
interface Pending {
	resolve: (positions: LayoutResponse) => void;
	reject: (error: Error) => void;
	/** Cleared when the request settles, so a late reply cannot settle it twice. */
	timer: ReturnType<typeof setTimeout>;
}

const inflight = new Map<number, Pending>();

/**
 * Take a request out of the in-flight set, if it is still there.
 *
 * A reply and a timeout can both be in flight for the same id — the worker is
 * slow, or it is answering a request that already fell back — so whichever gets
 * here first wins and the other finds nothing to settle.
 *
 * @param id - The request being settled.
 * @returns Its handlers, or undefined if it was already settled.
 */
function finish(id: number): Pending | undefined {
	const pending = inflight.get(id);
	if (!pending) return undefined;
	inflight.delete(id);
	clearTimeout(pending.timer);
	return pending;
}

/**
 * Settle a request with its positions.
 *
 * @param id - The request to settle.
 * @param positions - The computed positions.
 */
function resolveRequest(id: number, positions: LayoutResponse): void {
	finish(id)?.resolve(positions);
}

/**
 * Settle a request as failed.
 *
 * @param id - The request to settle.
 * @param message - Why it failed, for the caller's fallback to report.
 */
function rejectRequest(id: number, message: string): void {
	finish(id)?.reject(new Error(message));
}

function ensureWorker(): Worker | null {
	if (worker) return worker;
	if (typeof Worker === "undefined") return null;
	try {
		worker = new Worker(
			new URL("./dagreLayout.worker.ts", import.meta.url),
			{
				type: "module",
			},
		);
	} catch {
		// A context where a worker cannot be constructed at all. The caller lays
		// the graph out inline instead, which is slower but always works.
		return null;
	}
	worker.onmessage = (
		event: MessageEvent<{
			id: number;
			positions?: LayoutResponse;
			error?: string;
		}>,
	) => {
		const { id, positions, error } = event.data;
		if (error) {
			rejectRequest(id, error);
			return;
		}
		resolveRequest(id, positions ?? []);
	};
	worker.onerror = (event) => {
		// One failure fails everything waiting, rather than leaving callers
		// awaiting a reply that will never come.
		const message = event.message || "graph layout worker failed";
		for (const id of [...inflight.keys()]) {
			rejectRequest(id, message);
		}
	};
	return worker;
}

/**
 * Lay out a control-flow graph in a worker.
 *
 * Always settles. A worker that cannot be constructed, that reports a failure,
 * that throws something the error event did not carry, or that says nothing at
 * all within {@link LAYOUT_TIMEOUT_MS} all reject — so the caller can lay the
 * graph out itself rather than wait on a reply that may never arrive.
 *
 * @param request - The nodes and edges to arrange.
 * @returns A top-left position per node, in the order given.
 */
export function layoutInWorker(
	request: LayoutRequest,
): Promise<LayoutResponse> {
	const w = ensureWorker();
	if (!w) {
		return Promise.reject(new Error("workers are unavailable"));
	}
	const id = ++seq;
	return new Promise<LayoutResponse>((resolve, reject) => {
		const timer = setTimeout(() => {
			rejectRequest(id, "graph layout worker timed out");
		}, LAYOUT_TIMEOUT_MS);
		inflight.set(id, { resolve, reject, timer });
		try {
			w.postMessage({ id, ...request });
		} catch (e) {
			rejectRequest(id, e instanceof Error ? e.message : String(e));
		}
	});
}

/**
 * Lay out a control-flow graph on this thread.
 *
 * The same work {@link runLayout} does in the worker, for the case where there
 * is no worker to run it in.
 *
 * @param request - The nodes and edges to arrange.
 * @returns A top-left position per node, in the order given.
 */
export function layoutInline(request: LayoutRequest): LayoutResponse {
	return runLayout(request);
}
