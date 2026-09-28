import { describe, expect, it } from "vitest";

import { moduleAt, nearestSymbol, printableAt } from "./debugModules";
import type { DebugMemory, DebugModule, DebugModuleSymbol } from "../types";

/** A read that answers with the given hex, whatever it is asked for. */
function reading(hex: string): (addr: number) => Promise<DebugMemory | null> {
	return async (addr) => ({ addr, len: hex.length / 2, hex });
}

/** A module mapped at `base`, `size` bytes long. */
function mod(path: string, base: number, size = 0x10000): DebugModule {
	return { path, base, end: base + size };
}

/** A declared function at `addr`. */
function func(addr: number, name: string): DebugModuleSymbol {
	return { addr, name, is_func: true };
}

describe("printableAt", () => {
	/** `"Give Me Your Flag\0"` */
	const FLAG = "47697665204d6520596f757220466c616700";

	it("spells out a C string", async () => {
		expect(await printableAt(reading(FLAG), 0x601000)).toBe(
			"Give Me Your Flag",
		);
	});

	it("reads a short string out of a window full of the rest of .rodata", async () => {
		// Text, then a NUL, then whatever follows it: the terminator is what
		// makes it a string, and everything after it is not part of the answer.
		const window = `${FLAG}deadbeef`;
		expect(await printableAt(reading(window), 0x601000)).toBe(
			"Give Me Your Flag",
		);
	});

	it("claims nothing for data that is not text", async () => {
		// A pointer, a struct, a jump table: printable bytes that happen to start
		// with a letter are still not a string.
		expect(
			await printableAt(reading("00ff4018deadbeef00"), 0x601000),
		).toBeNull();
		expect(
			await printableAt(reading("2500000000000000"), 0x601000),
		).toBeNull();
	});

	it("needs four characters, as the static string scan does", async () => {
		// Three is a table of small numbers wearing a terminator; four is a word.
		expect(await printableAt(reading("41424300"), 0x601000)).toBeNull();
		expect(await printableAt(reading("4142434400"), 0x601000)).toBe("ABCD");
	});

	it("claims nothing for an empty or unterminated run", async () => {
		expect(await printableAt(reading("00"), 0x601000)).toBeNull();
		expect(await printableAt(reading(""), 0x601000)).toBeNull();
		// Fills the whole window without a NUL: not shown, because where it ends
		// is unknown and a truncated guess is not a string.
		expect(
			await printableAt(reading("41".repeat(64)), 0x601000),
		).toBeNull();
	});

	it("truncates a long string rather than spilling the column", async () => {
		const long = `${"41".repeat(80)}00`;
		expect(await printableAt(reading(long), 0x601000)).toBe("A".repeat(48));
	});

	it("claims nothing when the read fails", async () => {
		// An unmapped range, or a process that has exited. This decorates a view
		// and is not allowed to disturb it.
		const failing = async (): Promise<DebugMemory | null> => {
			throw new Error("no debuggee is running");
		};
		expect(await printableAt(failing, 0x601000)).toBeNull();
		expect(await printableAt(async () => null, 0x601000)).toBeNull();
	});
});

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
