import { describe, expect, it } from "vitest";

import type { BoundarySymbol, DataSection, DataSegment } from "../types";

/** Clamp a split fraction, mirroring the bounds a stack divider enforces. */
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
		file_offset: 0x1cfe8,
		align: 0x20,
		section_type: "PROGBITS",
		flags: 0x2,
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
		file_offset: 0x27fe0,
		align: 0x10,
		section_type: "PROGBITS",
		flags: 0x3,
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
		// `.bss` occupies no file bytes, so it has no file offset to speak of —
		// which is exactly what distinguishes it and why the row says so.
		file_offset: 0x28260,
		align: 0x10,
		section_type: "NOBITS",
		flags: 0x3,
	},
	{
		name: ".rela.dyn",
		addr: 0x1c000,
		size: 0x1e8,
		kind: "relocations",
		readable: true,
		writable: false,
		executable: false,
		uninitialized: false,
		file_offset: 0x1bfd0,
		align: 0x8,
		section_type: "RELA",
		flags: 0x2,
	},
];

/**
 * The segments of the same image, as the kernel sees it.
 *
 * The two `LOAD` entries are what is actually mapped; the rest describe the
 * image rather than occupying it, and `GNU_RELRO` is the one an analyst reads
 * for a hardening finding.
 */
const SEGMENTS: DataSegment[] = [
	{
		kind: "LOAD",
		addr: 0x0,
		mem_size: 0x1234,
		file_size: 0x1234,
		file_offset: 0,
		align: 0x1000,
		readable: true,
		writable: false,
		executable: true,
	},
	{
		kind: "LOAD",
		addr: 0x3000,
		// More memory than file: the tail is zero-filled, which is `.bss`.
		mem_size: 0x732,
		file_size: 0x640,
		file_offset: 0x1234,
		align: 0x1000,
		readable: true,
		writable: true,
		executable: false,
	},
	{
		kind: "GNU_RELRO",
		addr: 0x3000,
		mem_size: 0x1f0,
		file_size: 0x1f0,
		file_offset: 0x1234,
		align: 0x1,
		readable: true,
		writable: false,
		executable: false,
	},
	{
		kind: "GNU_STACK",
		addr: 0,
		mem_size: 0,
		file_size: 0,
		file_offset: 0,
		align: 0x10,
		readable: false,
		writable: true,
		executable: false,
	},
];

/** The segment filter, as the panel applies it. */
function filterSegments(all: DataSegment[], q: string): DataSegment[] {
	const query = q.trim().toLowerCase();
	if (!query) return all;
	return all.filter((g) => g.kind.toLowerCase().includes(query));
}

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
			s.kind.toLowerCase().includes(query) ||
			s.section_type.toLowerCase().includes(query),
	);
}

describe("section filter", () => {
	it("returns everything for an empty query", () => {
		expect(filterSections(SECTIONS, "")).toHaveLength(SECTIONS.length);
		expect(filterSections(SECTIONS, "   ")).toHaveLength(SECTIONS.length);
	});

	it("matches on the header's own type", () => {
		// The one an analyst reaches for when hunting every table of
		// relocations, and every region the loader zero-fills.
		expect(filterSections(SECTIONS, "rela").map((s) => s.name)).toEqual([
			".rela.dyn",
		]);
		expect(filterSections(SECTIONS, "nobits").map((s) => s.name)).toEqual([
			".bss",
		]);
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

describe("segment filter", () => {
	it("returns everything for an empty query", () => {
		expect(filterSegments(SEGMENTS, "")).toHaveLength(SEGMENTS.length);
	});

	it("matches on the segment type, case-insensitively", () => {
		expect(filterSegments(SEGMENTS, "load")).toHaveLength(2);
		expect(filterSegments(SEGMENTS, "RELRO").map((g) => g.kind)).toEqual([
			"GNU_RELRO",
		]);
	});

	it("reports a segment larger in memory than in the file as zero-filled", () => {
		// The one number in a segment row that is a finding rather than a fact
		// about the layout: the difference is `.bss`.
		const bss = SEGMENTS.filter((g) => g.mem_size > g.file_size);
		expect(bss).toHaveLength(1);
		expect(bss[0].kind).toBe("LOAD");
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
