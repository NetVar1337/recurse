import { describe, expect, it } from "vitest";

import { moduleAt, nearestSymbol } from "./debugModules";
import type { DebugModule, DebugModuleSymbol } from "../types";

/** A module mapped at `base`, `size` bytes long. */
function mod(path: string, base: number, size = 0x10000): DebugModule {
	return { path, base, end: base + size };
}

/** A declared function at `addr`. */
function func(addr: number, name: string): DebugModuleSymbol {
	return { addr, name, is_func: true };
}

describe("moduleAt", () => {
	const mods = [
		mod("/bin/target", 0x555555554000),
		mod("/lib/libc.so.6", 0x7f000000),
	];

	it("finds the module an address is in", () => {
		expect(moduleAt(mods, 0x7f000010)?.path).toBe("/lib/libc.so.6");
		expect(moduleAt(mods, 0x555555554010)?.path).toBe("/bin/target");
	});

	it("claims nothing outside every module", () => {
		// A heap address, a stack address, and the byte one past the end: none of
		// them is in a file, so none may be named after one.
		expect(moduleAt(mods, 0x7ffd3dc96000)).toBeNull();
		expect(moduleAt(mods, 0x7f010000)).toBeNull();
		expect(moduleAt(mods, 0)).toBeNull();
	});

	it("has no module to find before the map is read", () => {
		expect(moduleAt([], 0x7f000010)).toBeNull();
	});
});

describe("nearestSymbol", () => {
	const symbols = [func(0x1000, "first"), func(0x2000, "second")];

	it("names an exact entry with no offset", () => {
		expect(nearestSymbol(symbols, 0x2000)).toEqual({
			name: "second",
			offset: 0,
		});
	});

	it("names the function an address is inside, with the distance", () => {
		expect(nearestSymbol(symbols, 0x201f)).toEqual({
			name: "second",
			offset: 0x1f,
		});
	});

	it("skips a label in favour of the function it sits inside", () => {
		const withLabel = [
			func(0x2000, "second"),
			{ addr: 0x2010, name: "second.local", is_func: false },
		];
		expect(nearestSymbol(withLabel, 0x2018)).toEqual({
			name: "second",
			offset: 0x18,
		});
	});

	it("claims nothing below the first symbol", () => {
		expect(nearestSymbol(symbols, 0xfff)).toBeNull();
	});

	it("claims nothing in an empty table", () => {
		expect(nearestSymbol([], 0x2000)).toBeNull();
	});

	it("finds the right entry in a table the size of libc's", () => {
		// 4000 symbols, sorted, as a stripped library's `.dynsym` would be.
		const big = Array.from({ length: 4000 }, (_, i) =>
			func(i * 0x100, `sym_${i.toString(16)}`),
		);
		// 0x6734 sits 0x34 past the entry at 0x6700, which is sym index 0x67.
		expect(nearestSymbol(big, 0x6734)).toEqual({
			name: "sym_67",
			offset: 0x34,
		});
	});
});
