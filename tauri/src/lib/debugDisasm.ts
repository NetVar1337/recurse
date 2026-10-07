import type { DebugInsn } from "@/types";

/** How many instructions one `disasm` call asks the backend for. */
export const DISASM_WINDOW = 48;

/** Instructions kept below the program counter in the CPU view. */
export const DISASM_AFTER = 48;

/**
 * Forward coverage below the pc that suppresses a refetch. Stepping forward
 * inside an already-decoded window therefore renders instantly from the cache
 * and never blanks; only a pc at the edge of what we have (or somewhere new)
 * costs a round trip.
 */
export const DISASM_MIN_FORWARD = 16;

/**
 * Instructions of a branch target spliced in under the cursor when the branch
 * is going to be taken.
 *
 * The window stops there rather than carrying on: where control is about to go
 * matters more than the code the branch is skipping, and it is the one thing
 * that makes a loop legible from the inside. Standing on a back edge, the whole
 * iteration is right there under it.
 */
export const DISASM_PEEK = 6;

/** Instructions retained per session before the least recent are evicted. */
export const DISASM_MAX = 20000;

/** Longest instruction on any architecture recurse decodes, so a backward walk never scans further. */
const MAX_INSN_BYTES = 16;

/** Instructions decoded from the debuggee's memory this session, keyed by address. */
export type DisasmCache = ReadonlyMap<number, DebugInsn>;

/**
 * What a row of the CPU view is, which is what decides how it is marked.
 *
 * - `past` — the instructions leading into the cursor, in address order
 * - `cursor` — the program counter's own row
 * - `ahead` — decoded below the cursor, not reached yet
 * - `peek` — the code a taken branch is about to land in
 */
export type DisasmRowRole = "past" | "cursor" | "ahead" | "peek";

/** The glyph a row shows in the marker column. */
export type DisasmRowMarker = "pc" | "peek" | null;

/** One line of the CPU view. */
export interface DisasmRow {
	readonly addr: number;
	readonly insn: DebugInsn;
	readonly role: DisasmRowRole;
	readonly marker: DisasmRowMarker;
}

/** Where to splice a branch target in, and how much of it. */
export interface DisasmPeek {
	readonly addr: number;
	readonly lines: number;
}

/**
 * Byte length of a decoded instruction, from its hex `bytes` field, or 0 when
 * the backend sent no bytes and the length cannot be known.
 *
 * ```
 * insnSize({ addr: 0x8048060, bytes: "54", text: "push esp" })      // => 1
 * insnSize({ addr: 0x8048061, bytes: "689d800408", text: "push" }) // => 5
 * insnSize({ addr: 0x8048066, bytes: "", text: "?" })              // => 0
 * ```
 *
 * @param insn - A decoded instruction.
 * @returns Its length in bytes, or 0 when unknown.
 */
export function insnSize(insn: DebugInsn): number {
	const hex = (insn.bytes ?? "").replace(/\s+/g, "");
	if (hex.length < 2 || hex.length % 2 !== 0) return 0;
	return hex.length / 2;
}

/**
 * Address just past `insn`, or null when its length is unknown — a run of
 * instructions cannot be walked across an instruction of unknown size.
 *
 * ```
 * insnEnd({ addr: 0x8048060, bytes: "54", text: "push esp" })      // => 0x8048061
 * insnEnd({ addr: 0x8048060, bytes: "", text: "?" })              // => null
 * ```
 *
 * @param insn - A decoded instruction.
 * @returns The end address, or null when the length is unknown.
 */
export function insnEnd(insn: DebugInsn): number | null {
	const n = insnSize(insn);
	return n > 0 ? insn.addr + n : null;
}

/**
 * Merge freshly decoded instructions into the cache, returning a new map.
 *
 * The cache accumulates for the whole session so stepping never discards what
 * was already on screen, and a fresh decode wins over an older one for the same
 * address: the debuggee's memory is authoritative and may have changed (a
 * breakpoint's trap byte, self-modifying code). Past {@link DISASM_MAX} the
 * least recently decoded addresses are dropped; if the program counter ever
 * lands on an evicted address the caller simply refetches.
 *
 * Recency, not address order, is what eviction walks. The window's context
 * above the cursor is always at *lower* addresses, and a loop's code is
 * wherever the loop is, so an address-ordered cache would systematically drop
 * the rows a reader is about to look at.
 *
 * ```
 * const a = mergeDisasm(new Map(), [
 *   { addr: 0x8048060, bytes: "54", text: "push esp" },
 * ]);
 * mergeDisasm(a, [{ addr: 0x8048061, bytes: "689d800408", text: "push 0x804809d" }]).size
 * // => 2
 * ```
 *
 * @param cache - The cache so far.
 * @param fresh - Instructions just decoded, authoritative for their addresses.
 * @param max - How many addresses to keep.
 * @returns The merged cache.
 */
export function mergeDisasm(
	cache: DisasmCache,
	fresh: readonly DebugInsn[] | null | undefined,
	max: number = DISASM_MAX,
): DisasmCache {
	if (!fresh || fresh.length === 0) return cache;
	const next = new Map(cache);
	for (const insn of fresh) {
		if (insn && typeof insn.addr === "number") {
			// Deleted first so a re-decode lands at the back of the insertion
			// order, which is the recency order the eviction below walks.
			next.delete(insn.addr);
			next.set(insn.addr, insn);
		}
	}
	if (next.size > max) {
		for (const addr of [...next.keys()].slice(0, next.size - max))
			next.delete(addr);
	}
	return next;
}

/**
 * The contiguous run of cached instructions starting at `addr`, walking forward
 * while each instruction begins exactly where the previous one ended. Stops at
 * the first gap, at an instruction of unknown length, or after `limit` rows.
 *
 * ```
 * const cache = new Map([
 *   [0x8048060, { addr: 0x8048060, bytes: "54", text: "push esp" }],
 *   [0x8048061, { addr: 0x8048061, bytes: "689d800408", text: "push 0x804809d" }],
 *   [0x8048066, { addr: 0x8048066, bytes: "31c0", text: "xor eax, eax" }],
 *   [0x8049000, { addr: 0x8049000, bytes: "90", text: "nop" }],
 * ]);
 * forwardRun(cache, 0x8048060, 8).map((i) => i.addr)
 * // => [0x8048060, 0x8048061, 0x8048066]  (stops at the gap before 0x8049000)
 * forwardRun(cache, 0x8049000, 8).length
 * // => 1
 * ```
 *
 * @param cache - Instructions decoded this session.
 * @param addr - Where to start.
 * @param limit - Most rows to return.
 * @returns The run, in address order.
 */
export function forwardRun(
	cache: DisasmCache,
	addr: number,
	limit: number,
): DebugInsn[] {
	const out: DebugInsn[] = [];
	let cur = cache.get(addr);
	while (cur && out.length < limit) {
		out.push(cur);
		const end = insnEnd(cur);
		if (end == null) break;
		cur = cache.get(end);
	}
	return out;
}

/**
 * How many instructions the cache already holds contiguously below `addr`.
 *
 * @param cache - Instructions decoded this session.
 * @param addr - The program counter.
 * @returns The cached run's length, up to the refetch threshold.
 */
export function countForward(cache: DisasmCache, addr: number): number {
	return forwardRun(cache, addr, DISASM_MIN_FORWARD).length;
}

/** The cached instruction ending exactly at `addr`, if any. */
function findPrevious(cache: DisasmCache, addr: number): DebugInsn | null {
	for (let back = 1; back <= MAX_INSN_BYTES; back++) {
		const cand = cache.get(addr - back);
		if (cand && insnEnd(cand) === addr) return cand;
	}
	return null;
}

/**
 * The `before` instructions leading into `addr`, in address order, oldest first.
 *
 * This is context, not a record: it is the code that precedes the cursor,
 * which is the same thing whether or not the program came through it. A back
 * edge means the run that got here is somewhere else entirely, and the view
 * says where — by peeking the target — rather than pretending these rows are it.
 *
 * ```
 * const cache = new Map([
 *   [0x804809c, { addr: 0x804809c, bytes: "c3", text: "ret" }],
 *   [0x804809d, { addr: 0x804809d, bytes: "5c", text: "pop esp" }],
 *   [0x804809e, { addr: 0x804809e, bytes: "31c0", text: "xor eax, eax" }],
 * ]);
 * pastBefore(cache, 0x804809e, 8).map((i) => i.addr)
 * // => [0x804809c, 0x804809d]
 * ```
 *
 * @param cache - Instructions decoded this session.
 * @param addr - The cursor.
 * @param before - How many rows to take.
 * @returns The instructions leading into the cursor, oldest first.
 */
export function pastBefore(
	cache: DisasmCache,
	addr: number,
	before: number,
): DebugInsn[] {
	if (before <= 0) return [];
	const out: DebugInsn[] = [];
	let at = addr;
	while (out.length < before) {
		const prev = findPrevious(cache, at);
		if (!prev) break;
		out.push(prev);
		at = prev.addr;
	}
	out.reverse();
	return out;
}

/**
 * The rows the CPU view shows: the code leading into the program counter, the
 * cursor itself, then either the branch target it is about to land in or the
 * straight decode below it.
 *
 * This is a code window anchored on the cursor, and the whole of it. The rows
 * above are the instructions before the cursor *by address* — the reader's
 * bearings, dimmed — because a row of code that merely sits at a lower address
 * has not run, and dressing it as history is how a loop ends up looking like a
 * straight line that quietly skipped backwards. What actually ran is not
 * knowable from a stop: the answer is the branch the cursor is standing on, and
 * `peek` is where that answer is spliced in.
 *
 * A peek replaces the lookahead rather than joining it, so the window ends
 * where control is about to go. It is only ever the target of a branch the
 * cursor is on, which is the one place a jump is unambiguously the next thing
 * to happen.
 *
 * `before` is the debugger's configurable context depth. Nothing here is ever
 * invented: the window never bridges a gap, so a cursor that lands somewhere
 * with nothing decoded below it simply starts there.
 *
 * Returns an empty list when the cursor itself has not been decoded yet, which
 * is the caller's cue to fetch.
 *
 * ```
 * const insn = (addr: number) => ({ addr, bytes: "90", text: "nop" });
 * const cache = new Map([0x804809c, 0x804809d, 0x804809e].map((a) => [a, insn(a)]));
 * windowAround(cache, 0x804809e, 8, 8, null).map((r) => `${r.role}:${r.addr.toString(16)}`)
 * // => ["past:804809c", "past:804809d", "cursor:804809e"]
 * // The same cursor, on a branch about to be taken, shows where it is going.
 * windowAround(cache, 0x804809e, 1, 8, { addr: 0x804809c, lines: 2 })
 * //   => one past row, the cursor, then peek rows marked `peek`, the first `↳`
 * ```
 *
 * @param cache - Instructions decoded this session.
 * @param pc - The cursor to anchor the view on.
 * @param before - How many instructions of context to keep above it.
 * @param after - How many instructions to decode below it.
 * @param peek - A branch target to splice in instead of the lookahead.
 * @returns The rows to render, in order.
 */
export function windowAround(
	cache: DisasmCache,
	pc: number | null,
	before: number,
	after: number,
	peek: DisasmPeek | null = null,
): DisasmRow[] {
	const cursor = pc == null ? null : (cache.get(pc) ?? null);
	if (cursor == null) return [];
	const rows: DisasmRow[] = [];
	for (const insn of pastBefore(cache, pc as number, before)) {
		rows.push({ addr: insn.addr, insn, role: "past", marker: null });
	}
	rows.push({
		addr: cursor.addr,
		insn: cursor,
		role: "cursor",
		marker: "pc",
	});
	const tail =
		peek === null
			? forwardRun(cache, pc as number, after).slice(1)
			: forwardRun(cache, peek.addr, peek.lines);
	tail.forEach((insn, i) => {
		rows.push({
			addr: insn.addr,
			insn,
			role: peek === null ? "ahead" : "peek",
			marker: peek !== null && i === 0 ? "peek" : null,
		});
	});
	return rows;
}
