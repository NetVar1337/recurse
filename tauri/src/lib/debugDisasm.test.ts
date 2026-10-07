import { describe, expect, it } from "vitest";

import type { DebugInsn } from "../types";
import {
	countForward,
	DISASM_AFTER,
	DISASM_MAX,
	DISASM_PEEK,
	forwardRun,
	insnEnd,
	insnSize,
	mergeDisasm,
	pastBefore,
	windowAround,
} from "./debugDisasm";

/** Build a cache from `[addr, bytesHex, text]` triples. */
function cacheOf(
	rows: readonly (readonly [number, string, string])[],
): Map<number, DebugInsn> {
	return new Map(
		rows.map(([addr, bytes, text]) => [addr, { addr, bytes, text }]),
	);
}

/** The addresses of the rows, in order. */
function rowAddrs(rows: ReturnType<typeof windowAround>): number[] {
	return rows.map((r) => r.addr);
}

/** One label per row, so role and marker are checked together. */
function rowLabels(rows: ReturnType<typeof windowAround>): string[] {
	return rows.map((r) => `${r.role}${r.marker ? `:${r.marker}` : ""}`);
}

describe("insnSize", () => {
	it("reads the length from the hex bytes", () => {
		expect(insnSize({ addr: 0, bytes: "54", text: "push esp" })).toBe(1);
		expect(
			insnSize({ addr: 0, bytes: "689d800408", text: "push 0x804809d" }),
		).toBe(5);
	});

	it("tolerates spaced bytes", () => {
		expect(
			insnSize({ addr: 0, bytes: "31 c0", text: "xor eax, eax" }),
		).toBe(2);
	});

	it("reports 0 when the length cannot be known", () => {
		expect(insnSize({ addr: 0, bytes: "", text: "?" })).toBe(0);
		expect(insnSize({ addr: 0, bytes: "abc", text: "?" })).toBe(0);
	});
});

describe("insnEnd", () => {
	it("is the address just past the instruction", () => {
		expect(
			insnEnd({ addr: 0x8048060, bytes: "54", text: "push esp" }),
		).toBe(0x8048061);
	});

	it("is null when the length is unknown", () => {
		expect(insnEnd({ addr: 0x8048060, bytes: "", text: "?" })).toBeNull();
	});
});

describe("mergeDisasm", () => {
	it("accumulates across fetches instead of replacing", () => {
		const first = mergeDisasm(new Map(), [
			{ addr: 0x8048060, bytes: "54", text: "push esp" },
		]);
		const second = mergeDisasm(first, [
			{ addr: 0x8048061, bytes: "689d800408", text: "push 0x804809d" },
		]);
		expect(second.size).toBe(2);
		expect([...second.keys()]).toEqual([0x8048060, 0x8048061]);
	});

	it("lets a fresh decode win for the same address", () => {
		// A breakpoint's trap byte is replaced, then restored: the newest read
		// of an address is the authoritative one.
		const withTrap = mergeDisasm(new Map(), [
			{ addr: 0x8048060, bytes: "cc", text: "int3" },
		]);
		const restored = mergeDisasm(withTrap, [
			{ addr: 0x8048060, bytes: "54", text: "push esp" },
		]);
		expect(restored.size).toBe(1);
		expect(restored.get(0x8048060)?.text).toBe("push esp");
	});

	it("returns the same cache for an empty fetch", () => {
		const cache = cacheOf([[0x8048060, "54", "push esp"]]);
		expect(mergeDisasm(cache, [])).toBe(cache);
		expect(mergeDisasm(cache, null)).toBe(cache);
		expect(mergeDisasm(cache, undefined)).toBe(cache);
	});

	it("evicts the least recently decoded past the cap", () => {
		const many = Array.from({ length: 10 }, (_, i) => ({
			addr: 0x8048060 + i,
			bytes: "90",
			text: "nop",
		}));
		const capped = mergeDisasm(new Map(), many, 4);
		expect([...capped.keys()]).toEqual([
			0x8048066, 0x8048067, 0x8048068, 0x8048069,
		]);
	});

	it("evicts by recency, not by address order", () => {
		// The window's context above the cursor is always at lower addresses, so
		// dropping the lowest first would systematically discard the rows a
		// reader is looking at.
		const high = cacheOf([[0x7f1980a09597, "4883f825", "cmp rax, 0x25"]]);
		const merged = mergeDisasm(
			high,
			[{ addr: 0x7f1980a09586, bytes: "488914c1", text: "loop head" }],
			1,
		);
		expect([...merged.keys()]).toEqual([0x7f1980a09586]);
	});

	it("counts a re-decode as recent", () => {
		const loop = mergeDisasm(new Map(), [
			{ addr: 0x8048060, bytes: "90", text: "head" },
			{ addr: 0x8048061, bytes: "90", text: "body" },
		]);
		// Coming back round decodes the window again, which is what makes it the
		// code the run is working through.
		const again = mergeDisasm(loop, [
			{ addr: 0x8048060, bytes: "90", text: "head" },
		]);
		const capped = mergeDisasm(
			again,
			[{ addr: 0x900000, bytes: "90", text: "x" }],
			2,
		);
		expect(capped.has(0x8048060)).toBe(true);
	});

	it("defaults the cap to the session limit", () => {
		const many = Array.from({ length: DISASM_MAX + 5 }, (_, i) => ({
			addr: i,
			bytes: "90",
			text: "nop",
		}));
		expect(mergeDisasm(new Map(), many).size).toBe(DISASM_MAX);
	});
});

describe("forwardRun", () => {
	const cache = cacheOf([
		[0x8048060, "54", "push esp"],
		[0x8048061, "689d800408", "push 0x804809d"],
		[0x8048066, "31c0", "xor eax, eax"],
		[0x8048068, "31db", "xor ebx, ebx"],
		[0x8049000, "90", "nop"],
	]);

	it("walks forward while instructions are contiguous", () => {
		expect(forwardRun(cache, 0x8048060, 8).map((i) => i.addr)).toEqual([
			0x8048060, 0x8048061, 0x8048066, 0x8048068,
		]);
	});

	it("stops at a gap rather than bridging it", () => {
		// 0x8049000 is decoded, but it does not follow 0x8048068.
		expect(forwardRun(cache, 0x8048068, 8).map((i) => i.addr)).toEqual([
			0x8048068,
		]);
	});

	it("honours the limit", () => {
		expect(forwardRun(cache, 0x8048060, 2).length).toBe(2);
	});

	it("is empty for an address that was never decoded", () => {
		expect(forwardRun(cache, 0x1234, 8)).toEqual([]);
	});

	it("stops at an instruction of unknown length", () => {
		const odd = cacheOf([
			[0x8048060, "", "?"],
			[0x8048061, "90", "nop"],
		]);
		expect(forwardRun(odd, 0x8048060, 8).map((i) => i.addr)).toEqual([
			0x8048060,
		]);
	});
});

describe("countForward", () => {
	it("measures cached coverage below an address", () => {
		const cache = cacheOf([
			[0x8048060, "90", "nop"],
			[0x8048061, "90", "nop"],
		]);
		expect(countForward(cache, 0x8048060)).toBe(2);
		expect(countForward(cache, 0x9999)).toBe(0);
	});
});

describe("pastBefore", () => {
	// The reported case, at the reported addresses: _start ends with `ret` at
	// 0x804809c and _exit begins at 0x804809d.
	const cache = cacheOf([
		[0x804809c, "c3", "ret"],
		[0x804809d, "5c", "pop esp"],
		[0x804809e, "31c0", "xor eax, eax"],
		[0x80480a0, "40", "inc eax"],
		[0x80480a1, "cd80", "int 0x80"],
	]);

	it("reads the contiguous instructions leading into the cursor", () => {
		expect(pastBefore(cache, 0x80480a0, 8).map((i) => i.addr)).toEqual([
			0x804809c, 0x804809d, 0x804809e,
		]);
	});

	it("bounds and stops at a gap", () => {
		const gapped = cacheOf([
			[0x804809d, "5c", "pop esp"],
			[0x804809e, "31c0", "xor eax, eax"],
		]);
		expect(pastBefore(gapped, 0x804809e, 8).map((i) => i.addr)).toEqual([
			0x804809d,
		]);
		expect(pastBefore(cache, 0x80480a0, 2).map((i) => i.addr)).toEqual([
			0x804809d, 0x804809e,
		]);
	});

	it("is empty at the start of the decoded code, or with no depth", () => {
		expect(pastBefore(cache, 0x804809c, 8)).toEqual([]);
		expect(pastBefore(cache, 0x80480a0, 0)).toEqual([]);
	});

	it("does not walk back across an instruction that ends past the cursor", () => {
		// The cached row at 0x804809d is three bytes, so it ends at 0x80480a0 —
		// past the cursor, and therefore not its predecessor.
		const overlong = cacheOf([
			[0x804809d, "c3c3c3", "ret ret ret"],
			[0x804809f, "31c0", "xor eax, eax"],
		]);
		expect(pastBefore(overlong, 0x804809f, 8)).toEqual([]);
	});
});

describe("windowAround", () => {
	const cache = cacheOf([
		[0x804809c, "c3", "ret"],
		[0x804809d, "5c", "pop esp"],
		[0x804809e, "31c0", "xor eax, eax"],
		[0x80480a0, "40", "inc eax"],
		[0x80480a1, "cd80", "int 0x80"],
	]);

	it("marks the cursor and nothing else", () => {
		// The row above is the instruction before the cursor, not a row that ran:
		// it is `past`, with no marker of any kind.
		const rows = windowAround(cache, 0x80480a0, 8, 8, null);
		expect(rowLabels(rows)).toEqual([
			"past",
			"past",
			"past",
			"cursor:pc",
			"ahead",
		]);
		expect(rowAddrs(rows)).toEqual([
			0x804809c, 0x804809d, 0x804809e, 0x80480a0, 0x80480a1,
		]);
	});

	it("keeps the rows below the cursor regardless of the context depth", () => {
		// The depth bounds context, not lookahead: upcoming code stays visible so
		// the next step has somewhere to land.
		const rows = windowAround(cache, 0x804809d, 1, 8, null);
		expect(rowAddrs(rows)).toEqual([
			0x804809c, 0x804809d, 0x804809e, 0x80480a0, 0x80480a1,
		]);
	});

	it("shows the cursor alone at depth 0", () => {
		expect(rowLabels(windowAround(cache, 0x804809d, 0, 8, null))).toEqual([
			"cursor:pc",
			"ahead",
			"ahead",
			"ahead",
		]);
	});

	it("bounds the rows above and below the cursor", () => {
		const many = cacheOf(
			Array.from(
				{ length: 30 },
				(_, i) => [0x8048060 + i, "90", "nop"] as const,
			),
		);
		const rows = windowAround(many, 0x8048070, 4, 3, null);
		expect(rowAddrs(rows)).toEqual([
			0x804806c, 0x804806d, 0x804806e, 0x804806f, 0x8048070, 0x8048071,
			0x8048072,
		]);
	});

	it("never bridges a gap to reach a distant decoded address", () => {
		// 0x804809d is decoded, but 0x804809c is not, so nothing reaches back to
		// it: the window starts at the cursor rather than invent adjacency.
		const gapped = cacheOf([
			[0x804809d, "5c", "pop esp"],
			[0x804809e, "31c0", "xor eax, eax"],
		]);
		expect(rowAddrs(windowAround(gapped, 0x804809d, 8, 8, null))).toEqual([
			0x804809d, 0x804809e,
		]);
	});

	it("is empty when the cursor has not been decoded yet", () => {
		expect(windowAround(cache, 0x1234, 8, 8, null)).toEqual([]);
	});

	it("is empty without a cursor", () => {
		expect(windowAround(cache, null, 8, 8, null)).toEqual([]);
	});

	it("is empty against an empty cache", () => {
		expect(windowAround(new Map(), 0x8048060, 8, 8, null)).toEqual([]);
	});
});

describe("windowAround with a peek", () => {
	// The loop from a live session: a head at 0x7f1980a09586, three instructions
	// of body, and a back edge at 0x7f1980a0959b that jumps back to the head.
	// Cursor on the back edge, the row that is about to send it round.
	const HEAD = 0x7f1980a09586;
	const BODY = 0x7f1980a0958e;
	const EDGE = 0x7f1980a0959b;
	const cache = new Map<number, DebugInsn>([
		[
			0x7f1980a09580,
			{
				addr: 0x7f1980a09580,
				bytes: "482dafffff6f",
				text: "sub rax, 0x6fffffda",
			},
		],
		[HEAD, { addr: HEAD, bytes: "488914c1", text: "mov [rcx+rax*8], rdx" }],
		[
			0x7f1980a0958a,
			{
				addr: 0x7f1980a0958a,
				bytes: "488b4210",
				text: "mov rax, [rdx+0x10]",
			},
		],
		[BODY, { addr: BODY, bytes: "4883c210", text: "add rdx, 0x10" }],
		[
			0x7f1980a09592,
			{ addr: 0x7f1980a09592, bytes: "4885c0", text: "test rax, rax" },
		],
		[
			0x7f1980a09595,
			{ addr: 0x7f1980a09595, bytes: "7415", text: "je 0x7f1980a095e8" },
		],
		[
			0x7f1980a09597,
			{ addr: 0x7f1980a09597, bytes: "4883f825", text: "cmp rax, 0x25" },
		],
		[EDGE, { addr: EDGE, bytes: "76e9", text: "jbe 0x7f1980a09586" }],
	]);

	it("splices the target in under the cursor, arrow on its first row", () => {
		const rows = windowAround(cache, EDGE, 2, DISASM_AFTER, {
			addr: HEAD,
			lines: DISASM_PEEK,
		});
		expect(rowLabels(rows)).toEqual([
			"past",
			"past",
			"cursor:pc",
			"peek:peek",
			"peek",
			"peek",
			"peek",
			"peek",
			"peek",
		]);
		// The whole lap is right there, without the window inventing a run of
		// addresses across the jump that never happened.
		expect(rowAddrs(rows)).toEqual([
			0x7f1980a09595,
			0x7f1980a09597,
			EDGE,
			HEAD,
			0x7f1980a0958a,
			BODY,
			0x7f1980a09592,
			0x7f1980a09595,
			0x7f1980a09597,
		]);
	});

	it("replaces the lookahead, so the window ends where control is going", () => {
		const rows = windowAround(cache, EDGE, 0, 48, {
			addr: HEAD,
			lines: 2,
		});
		// 0x7f1980a0959d would have been the next address, and is not shown: the
		// branch is not going there.
		expect(rowAddrs(rows)).toEqual([EDGE, HEAD, 0x7f1980a0958a]);
	});

	it("is empty when the target has not been decoded", () => {
		const rows = windowAround(cache, EDGE, 0, 8, {
			addr: 0x1234,
			lines: 4,
		});
		expect(rowLabels(rows)).toEqual(["cursor:pc"]);
	});

	it("repeats an address the window already shows, marked as a peek", () => {
		// A short back edge lands inside the visible context, and those rows
		// appear again under it. That is the point: it is the lap the program is
		// about to run, and the `peek` role keeps it from reading as a duplicate.
		const rows = windowAround(cache, EDGE, 6, 8, { addr: HEAD, lines: 6 });
		expect(rowAddrs(rows).filter((a) => a === HEAD)).toHaveLength(2);
		expect(rowLabels(rows).filter((l) => l === "peek:peek")).toHaveLength(
			1,
		);
		expect(rows.filter((r) => r.role === "cursor")).toHaveLength(1);
	});

	it("keeps the straight lookahead when there is no peek", () => {
		const rows = windowAround(cache, BODY, 1, 8, null);
		expect(rowLabels(rows)).toEqual([
			"past",
			"cursor:pc",
			"ahead",
			"ahead",
			"ahead",
			"ahead",
		]);
	});
});
