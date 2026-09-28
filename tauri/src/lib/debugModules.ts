import type { DebugMemory, DebugModule, DebugModuleSymbol } from "../types";

/** How far a string operand is read before giving up on it. */
export const STRING_WINDOW = 64;

/** Longest string spelled out in a comment, as the static views do. */
const STRING_MAX = 48;

/**
 * Shortest run of text worth spelling out.
 *
 * The same threshold the static string scan uses, and for the same reason: a
 * handful of printable bytes followed by a zero is what almost every table of
 * small numbers looks like, so a one-character "string" is noise rather than
 * information.
 */
const STRING_MIN = 4;

/**
 * The text at `addr`, if that is what is there.
 *
 * Read from the live debuggee, because in a running program the only honest
 * source for what a pointer means is the bytes the pointer is pointing at. A
 * C string is printable bytes ended by a NUL, and the test is deliberately
 * strict: a word of text is spelled out, and anything that is not text is left
 * to be an address, since a wrong `; "..."` is worse than none.
 *
 * A read can fail — the range may be unmapped, or the process may have exited —
 * which is reported as no text rather than as an error: this decorates a view,
 * and it is not allowed to disturb it.
 *
 * @param read - Reads bytes at an address, as `debugCommand("read")` does.
 * @param addr - Where to look.
 * @returns The text without its terminator, or null if it is not text.
 */
export async function printableAt(
	read: (addr: number) => Promise<DebugMemory | null>,
	addr: number,
): Promise<string | null> {
	let bytes: DebugMemory | null;
	try {
		bytes = await read(addr);
	} catch {
		return null;
	}
	const raw = bytes?.hex;
	if (!raw) return null;
	const octets: number[] = [];
	for (let i = 0; i + 1 < raw.length; i += 2) {
		octets.push(Number.parseInt(raw.slice(i, i + 2), 16));
	}
	// Everything read must be printable: a run that runs into a non-text byte
	// is data that happens to start with letters, and is not a string.
	const out: number[] = [];
	for (const byte of octets) {
		if (byte === 0) break;
		if (byte < 0x20 || byte > 0x7e) return null;
		out.push(byte);
	}
	if (out.length < STRING_MIN) return null;
	// A string with no terminator in the window is not one either.
	if (out.length === octets.length) return null;
	return String.fromCharCode(...out).slice(0, STRING_MAX);
}

/**
 * The module an address is mapped from, if any.
 *
 * Ranges are the kernel's, merged per file, so a segment boundary is not a
 * miss. An address in no file — a heap, a stack, an anonymous mapping — belongs
 * to no module, which is what stops a garbage pointer from being named after
 * whatever happens to sit below it in the map.
 *
 * ```
 * moduleAt([{ path: "/lib/libc.so.6", base: 0x7f00, end: 0x9000 }], 0x8000)
 *   // => the libc module
 * moduleAt([{ path: "/lib/libc.so.6", base: 0x7f00, end: 0x9000 }], 0x9000)
 *   // => null — one past the end is not inside
 * ```
 *
 * @param modules - The files mapped into the process.
 * @param addr - A runtime address.
 * @returns The module it belongs to, or null.
 */
export function moduleAt(
	modules: readonly DebugModule[],
	addr: number,
): DebugModule | null {
	return modules.find((m) => addr >= m.base && addr < m.end) ?? null;
}

/**
 * The function an address is in, or the nearest one below it.
 *
 * A call target is a function entry, so the nearest symbol at or below it is the
 * answer. An untyped label is skipped in favour of a declared function, because
 * a label inside a function is not what a call names.
 *
 * ```
 * nearestSymbol([{ addr: 0x1000, name: "b", is_func: true }], 0x101f)
 *   // => { name: "b", offset: 0x1f }
 * nearestSymbol([{ addr: 0x1000, name: "b", is_func: true }], 0x0fff)
 *   // => null — below every symbol, so nothing is claimed
 * ```
 *
 * @param symbols - The module's symbols, sorted by address.
 * @param offset - The address relative to the module's base.
 * @returns The name and how far into it the address is, or null.
 */
export function nearestSymbol(
	symbols: readonly DebugModuleSymbol[],
	offset: number,
): { name: string; offset: number } | null {
	// The binary search for "how many symbols are at or below this address".
	let lo = 0;
	let hi = symbols.length;
	while (lo < hi) {
		const mid = (lo + hi) >> 1;
		if (symbols[mid].addr <= offset) lo = mid + 1;
		else hi = mid;
	}
	const at = lo;
	for (let i = at - 1; i >= 0; i--) {
		const symbol = symbols[i];
		if (!symbol.is_func) continue;
		return { name: symbol.name, offset: offset - symbol.addr };
	}
	return null;
}
