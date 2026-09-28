import type { DebugModule, DebugModuleSymbol } from "../types";

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
