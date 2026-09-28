import { insnSize } from "./debugDisasm";
import type { DebugInsn } from "../types";

/**
 * Where a `call` or `jmp` is going.
 *
 * `direct` is a relative or absolute branch the decoder already resolved, so the
 * address is the destination. `slot` is a jump *through* a pointer: the address
 * is the slot in the GOT, which is data rather than code, and only the thing it
 * points at is a function.
 */
export type CallTarget =
	| { readonly kind: "direct"; readonly addr: number }
	| { readonly kind: "slot"; readonly addr: number };

/** `call 0x1234` — the destination is in the instruction. */
const DIRECT = /^(?:call|jmp)\s+(?:qword\s+ptr\s+)?0x([0-9a-f]+)/i;

/** `call qword ptr [rip + 0x200836]` — the destination is a GOT slot. */
const RIP_RELATIVE =
	/^(?:call|jmp)\b.*?\[\s*rip\s*([+-])\s*0x([0-9a-f]+)\s*\]/i;

/**
 * The destination of a `call` or `jmp`, as an address in the debuggee's own
 * address space.
 *
 * Only the two forms a compiler actually emits for a call worth naming are
 * recognised: a direct branch, and the RIP-relative jump through the GOT that a
 * PIE uses for an import. A call through a register (`call rax`) is indirect in
 * a way the instruction alone cannot resolve, so it is reported as no target
 * rather than guessed at.
 *
 * A `call rel32` prints an absolute address, because the decoder has already
 * done the arithmetic that makes it absolute, so the printed form is what gets
 * parsed and the result is the address the decoder meant.
 *
 * ```
 * callTarget({ addr: 0x401000, bytes: "e807050000", text: "call 0x401234" })
 *   // => { kind: "direct", addr: 0x401234 }
 * callTarget({ addr: 0x7f00, bytes: "ff15d6080200", text: "call qword ptr [rip + 0x200836]" })
 *   // => { kind: "slot", addr: 0x20873c }   // six bytes on, so rip is 0x7f06
 * callTarget({ addr: 0x401000, bytes: "ffd0", text: "call rax" })
 *   // => null
 * ```
 *
 * @param insn - The decoded instruction.
 * @returns The destination, or null when the instruction does not name one.
 */
export function callTarget(insn: DebugInsn): CallTarget | null {
	const text = insn.text.trim();
	const rip = RIP_RELATIVE.exec(text);
	if (rip) {
		const disp = Number.parseInt(rip[2], 16) * (rip[1] === "-" ? -1 : 1);
		const next = insn.addr + insnSize(insn);
		return { kind: "slot", addr: next + disp };
	}
	const direct = DIRECT.exec(text);
	if (direct) return { kind: "direct", addr: Number.parseInt(direct[1], 16) };
	return null;
}

/**
 * The GOT slot a PLT stub jumps through.
 *
 * A PLT stub for an import is `jmp qword ptr [rip + disp32]` — the six bytes
 * `ff 25` and a displacement — and the displacement is relative to the end of
 * that jump, which is the whole trick: the stub is the only place in the file
 * that says which GOT slot belongs to which import, so reading it is how a
 * `call [rip + x]` gets a name. Reading the GOT slot itself does not work: the
 * dynamic linker patches it to the resolved libc address the first time the
 * import is called, and there are no symbols for that.
 *
 * ```
 * pltSlot(0x1080, "ff25100000 00")  // => 0x2086
 * pltSlot(0x1080, "554889e5")        // => null — not a PLT jump
 * ```
 *
 * @param addr - The stub's address in the debuggee's address space.
 * @param bytes - The stub's bytes, hex, as `debugCommand("read")` returns them.
 * @returns The slot's address, or null when these bytes are not a PLT jump.
 */
export function pltSlot(addr: number, bytes: string): number | null {
	const hex = bytes.replace(/\s+/g, "");
	const octets: number[] = [];
	for (let i = 0; i + 1 < hex.length; i += 2) {
		octets.push(Number.parseInt(hex.slice(i, i + 2), 16));
	}
	if (octets.length < 6 || octets[0] !== 0xff || octets[1] !== 0x25) {
		return null;
	}
	// The displacement is four bytes, little-endian and signed; rip points past
	// the six-byte jump.
	const unsigned =
		((octets[2] |
			(octets[3] << 8) |
			(octets[4] << 16) |
			(octets[5] << 24)) >>>
			0) |
		0;
	const disp = unsigned > 0x7fffffff ? unsigned - 0x100000000 : unsigned;
	return addr + 6 + disp;
}

/**
 * A short, readable name for a function the pane will annotate a call with.
 *
 * The analysis engine prefixes a discovered import thunk with `imp.`, which is
 * noise next to a comment the analyst is reading for the name: `imp.__isoc99_scanf`
 * says `__isoc99_scanf`, and the surrounding disassembly already says it is an
 * import. A `fcn_` or `sym.` prefix is left alone — that part is the name the
 * engine could not resolve, and hiding it would hide that too.
 *
 * ```
 * shortName("imp.puts")     // => "puts"
 * shortName("fcn_00001234") // => "fcn_00001234"
 * ```
 *
 * @param name - The name as the analysis engine reports it.
 * @returns The name to show.
 */
export function shortName(name: string): string {
	return name.startsWith("imp.") ? name.slice(4) : name;
}
