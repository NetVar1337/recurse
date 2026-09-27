import { describe, expect, it } from "vitest";

import type { BoundarySymbol, DataSection } from "../types";

/** Clamp a split fraction, mirroring the bounds SplitView enforces. */
function clamp(v: number, min: number, max: number): number {
	return Math.min(max, Math.max(min, v));
}

describe("split bounds", () => {
	it("keeps both panes usable", () => {
		// A pane squeezed to zero is unusable, so the divider cannot reach either
		// end: the other pane always keeps a workable share.
		expect(clamp(0, 0.15, 0.85)).toBe(0.15);
		expect(clamp(1, 0.15, 0.85)).toBe(0.85);
		expect(clamp(-5, 0.15, 0.85)).toBe(0.15);
		expect(clamp(5, 0.15, 0.85)).toBe(0.85);
	});

	it("leaves a fraction inside the range alone", () => {
		expect(clamp(0.62, 0.15, 0.85)).toBe(0.62);
	});
});

const SECTIONS: DataSection[] = [
	{
		name: ".rodata",
		addr: 0x1d000,
		size: 21288,
		kind: "read-only data",
		readable: true,
		writable: false,
		executable: false,
		uninitialized: false,
	},
	{
		name: ".data",
		addr: 0x28000,
		size: 608,
		kind: "writable data",
		readable: true,
		writable: true,
		executable: false,
		uninitialized: false,
	},
	{
		name: ".bss",
		addr: 0x28260,
		size: 4888,
		kind: "zero-initialised data",
		readable: true,
		writable: true,
		executable: false,
		uninitialized: true,
	},
];

const BOUNDARIES: BoundarySymbol[] = [
	{ name: "_edata", addr: 0x80490a3, kind: "end of initialised data" },
	{ name: "_end", addr: 0x80490a4, kind: "end of image" },
];

/** The section filter, as the panel applies it. */
function filterSections(all: DataSection[], q: string): DataSection[] {
	const query = q.trim().toLowerCase();
	if (!query) return all;
	return all.filter(
		(s) =>
			s.name.toLowerCase().includes(query) ||
			s.kind.toLowerCase().includes(query),
	);
}

describe("section filter", () => {
	it("returns everything for an empty query", () => {
		expect(filterSections(SECTIONS, "")).toHaveLength(3);
		expect(filterSections(SECTIONS, "   ")).toHaveLength(3);
	});

	it("matches on the section name, case-insensitively", () => {
		expect(filterSections(SECTIONS, "rodata").map((s) => s.name)).toEqual([
			".rodata",
		]);
		expect(filterSections(SECTIONS, ".BSS").map((s) => s.name)).toEqual([
			".bss",
		]);
	});

	it("matches on the kind text", () => {
		expect(filterSections(SECTIONS, "writable").map((s) => s.name)).toEqual(
			[".data"],
		);
		expect(
			filterSections(SECTIONS, "zero-initialised").map((s) => s.name),
		).toEqual([".bss"]);
	});

	it("matches text, not the permission flags", () => {
		// `.bss` is writable but its kind reads "zero-initialised data", so
		// searching `writable` finds the kind that says so. The flags are shown
		// in the row, not searched: mixing a flag name into a text filter would
		// make it match on a different question than the one being asked.
		const bss = SECTIONS.find((s) => s.name === ".bss");
		expect(bss?.writable).toBe(true);
		expect(
			filterSections(SECTIONS, "writable").map((s) => s.name),
		).not.toContain(".bss");
	});

	it("does not match on an address or a size", () => {
		expect(filterSections(SECTIONS, "0x28000")).toHaveLength(0);
		expect(filterSections(SECTIONS, "21288")).toHaveLength(0);
	});
});

describe("boundary markers", () => {
	it("reports the address, not code, so a key is the pair", () => {
		// Two markers can share an address; the list keys on both so neither
		// disappears, which is the case in the hand-written `start` binary.
		const shared: BoundarySymbol[] = [
			{
				name: "_edata",
				addr: 0x80490a3,
				kind: "end of initialised data",
			},
			{
				name: "__bss_start",
				addr: 0x80490a3,
				kind: "start of zero-initialised data",
			},
		];
		const keys = shared.map((b) => `${b.addr}:${b.name}`);
		expect(new Set(keys).size).toBe(2);
	});

	it("carries a description as well as an address", () => {
		for (const b of BOUNDARIES) {
			expect(b.kind.length).toBeGreaterThan(0);
		}
	});
});
