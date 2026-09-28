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

/** Any `[rip ± 0x…]` operand, whatever the instruction does with it. */
const RIP_OPERAND = /\[\s*rip\s*([+-])\s*0x([0-9a-f]+)\s*\]/i;

/**
 * `[rbp - 0x18]`, `[rbp + 8]`, `[rbp - 4]`.
 *
 * The offset is printed in whichever base the decoder chose, and a small frame
 * slot usually comes out decimal — `[rbp - 4]` is a loop counter, not a
 * `[rbp - 0x4]` — so both spellings have to be read or the most common variable
 * in a function is the one that never gets a name.
 */
const FRAME_SLOT = /\[\s*rbp\s*([+-])\s*(0x[0-9a-f]+|\d+)\s*\]/i;

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
 * The address a `[rip + x]` operand points at.
 *
 * Every data reference the compiler makes position-independently looks like
 * this — a GOT slot, a string in rodata, a global, a jump table — and the
 * displacement means nothing on its own: it is an offset from the end of this
 * instruction, so only adding it to that end says what is being read. Which is
 * exactly what the operand is for, and why a view that shows the raw
 * displacement without this says nothing about the value.
 *
 * The lookup is one per instruction rather than per operand, which is all the
 * x86-64 forms in practice need: an instruction with two rip-relative operands
 * does not exist in the ISA.
 *
 * ```
 * ripTarget({ addr: 0x400510, bytes: "ff35f2f20a00", text: "push qword ptr [rip + 0x200af2]" })
 *   // => 0x601008   // six bytes on, then the displacement
 * ripTarget({ addr: 0x400510, bytes: "4889c0", text: "mov rax, rax" })
 *   // => null
 * ```
 *
 * @param insn - The decoded instruction.
 * @returns The address the operand refers to, or null when there is none.
 */
export function ripTarget(insn: DebugInsn): number | null {
	const m = RIP_OPERAND.exec(insn.text);
	if (!m) return null;
	const disp = Number.parseInt(m[2], 16) * (m[1] === "-" ? -1 : 1);
	return insn.addr + insnSize(insn) + disp;
}

/**
 * The frame offset a `[rbp - 0x18]` operand refers to.
 *
 * The same question [`ripTarget`] answers for a position-independent reference,
 * asked of the frame pointer instead: where in the frame is this variable, and
 * therefore which name belongs beside it.
 *
 * ```
 * frameOffsetOf({ addr: 0x1004, bytes: "488b45e8", text: "mov rax, qword ptr [rbp - 0x8]" })
 *   // => -8
 * frameOffsetOf({ addr: 0x1004, bytes: "488b442410", text: "mov rax, qword ptr [rsp + 0x10]" })
 *   // => null — no frame pointer, so no frame to be relative to
 * ```
 *
 * @param insn - The decoded instruction.
 * @returns The offset, or null when the instruction names no frame slot.
 */
export function frameOffsetOf(insn: DebugInsn): number | null {
	return frameOffsetIn(insn.text);
}

/**
 * The frame offset named anywhere in an instruction's text.
 *
 * Split out from [`frameOffsetOf`] because the static views have a line of
 * disassembly and nothing else: they never decoded an instruction object, and
 * the question they are asking — which name goes beside this `[rbp - 0x18]` — is
 * the same one.
 *
 * ```
 * frameOffsetIn("mov dword ptr [rbp - 4], 0xbadf00d")
 * // => -4
 * frameOffsetIn("mov rax, qword ptr [rsp + 0x10]")
 * // => null
 * ```
 *
 * @param text - The instruction, or the operand part of it.
 * @returns The offset, or null when the text names no frame slot.
 */
export function frameOffsetIn(text: string): number | null {
	const m = FRAME_SLOT.exec(text);
	if (!m) return null;
	const raw = m[2];
	const magnitude = raw.startsWith("0x")
		? Number.parseInt(raw.slice(2), 16)
		: Number.parseInt(raw, 10);
	return m[1] === "-" ? -magnitude : magnitude;
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
