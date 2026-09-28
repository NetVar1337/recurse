import type { DebugInsn } from "../types";

/**
 * A stack slot a function uses as a variable.
 *
 * Not a symbol — nothing in the file says these exist. They are the distinct
 * `[rbp + k]` references a function makes, which is the same thing a decompiler
 * discovers when it invents `local_18h`, and the counts here are what make a
 * name worth choosing: a slot written once and read in a loop is the loop
 * counter, a slot only ever read is a saved register or a constant.
 */
export interface LocalVar {
	/** Byte offset from the frame pointer: `-8` for `[rbp - 8]`. */
	offset: number;
	/** Times the slot is read. */
	reads: number;
	/** Times the slot is written. */
	writes: number;
	/** Widest access seen, in bytes. */
	width: number;
	/**
	 * Whether the slot's own address is taken (`lea reg, [rbp - 0x18]`), which
	 * is what makes it a pointer rather than a number the compiler spilled.
	 */
	isPointer: boolean;
}

/**
 * An argument register the function reads.
 *
 * The first six integer arguments arrive in registers on the SysV x86-64 ABI,
 * and a callee that spills one to the stack has, in effect, told us it uses it.
 * A register written before it is read belongs to the function, not the caller.
 */
export interface ArgVar {
	/** Register name, as the disassembly spells it. */
	reg: string;
	/** Zero-based position in the ABI's argument order. */
	index: number;
	/** Times read after being loaded. */
	reads: number;
	/** Times written before being read, which is the callee claiming it. */
	writes: number;
}

/** The SysV x86-64 integer argument registers, in order. */
export const ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"] as const;

/**
 * Mnemonics whose first operand is a source, not a destination.
 *
 * `test` and `cmp` read both operands and change neither, and `push` consumes
 * its operand. Counting the first as written would make every argument look
 * claimed by the function and drop it from the list entirely.
 */
const READS_BOTH = new Set(["test", "cmp", "push", "bt", "bts", "btr", "btc"]);

/**
 * A register named as a whole, as a 32/16/8-bit alias, or as the numbered
 * `r8`–`r15` family in its 32-bit form.
 */
const REG =
	/\b(e(di|si|dx|cx)|r\d+d|r(?:1[0-5]|[0-9]|ax|bx|cx|dx|si|di|bp|sp|ip)|e[a-d]x|[abcd][lh]|[sd]il|[sb]pl)\b/i;

/**
 * Bytes moved by a register operand, from its name.
 *
 * `rax` is eight, `eax` four, `ax` two, `al` one, and a `r8`–`r15` is eight by
 * virtue of starting with `r` and having no `e`/`a`/`b`/`c`/`d` narrowing.
 */
function regWidth(name: string): number {
	const n = name.toLowerCase();
	if (/^r\d/.test(n)) return 8;
	if (/^e[a-d]x$/.test(n)) return 4;
	if (/^(ax|bx|cx|dx|si|di|bp|sp)$/.test(n)) return 2;
	if (/^(al|bl|cl|dl|ah|bh|ch|dh|sil|dil|bpl|spl)$/.test(n)) return 1;
	return 8;
}

/** Width from an explicit `byte`/`word`/`dword`/`qword ptr` operand. */
function ptrWidth(text: string): number | null {
	if (/\bbyte ptr\b/.test(text)) return 1;
	if (/\bword ptr\b/.test(text)) return 2;
	if (/\bdword ptr\b/.test(text)) return 4;
	if (/\bqword ptr\b/.test(text)) return 8;
	return null;
}

/**
 * The ABI argument register a name is, or is an alias of.
 *
 * A 32-bit operand on a 64-bit register is the same register, and a function
 * that takes `char *` in `rdi` writes to it as `edi`.
 */
function argRegName(name: string): string | null {
	const n = name.toLowerCase();
	const all: readonly string[] = ARG_REGS;
	if (all.includes(n)) return n;
	const wide = /^e(di|si|dx|cx)$/.exec(n);
	if (wide) return `r${wide[1]}`;
	const numbered = /^r(\d+)d$/.exec(n);
	if (numbered && Number(numbered[1]) >= 8) return `r${numbered[1]}`;
	return null;
}

/**
 * How a function addresses its own frame.
 *
 * Two shapes, and both are common: a function that establishes a frame pointer
 * addresses its frame through it, and a leaf function that never does addresses
 * the same memory through the stack pointer. Requiring the first shape means a
 * whole class of function has no variables at all, and its locals — plainly
 * visible as `[rsp - 8]` — go unnamed.
 */
export interface Frame {
	/** `rbp`-shaped, or `rsp`-shaped, whichever the function uses. */
	base: "rbp" | "rsp";
	/**
	 * Whether the frame could not be read from any instructions.
	 *
	 * A view can hold a line of disassembly before it has the function's
	 * prologue, and a slot whose operand is right there must still name.
	 */
	unknown: boolean;
	/** Whether a frame pointer was pushed and set up. */
	hasFramePointer: boolean;
	/**
	 * Bytes the stack reaches below the frame pointer, from the frame
	 * allocation in the prologue.
	 *
	 * This is what makes a `[rsp + x]` reference and an `[rbp + y]` one
	 * comparable: with the frame pointer at `rbp`, the stack sits `depth` bytes
	 * below it, so `[rsp + x]` is the same slot as `[rbp + x - depth]`. Taken as
	 * the deepest the function goes, which is the allocation in the prologue —
	 * the odd function that allocates a second frame mid-body will name a slot a
	 * little differently from the register it used, and still name the *variable*
	 * correctly, which is the part that matters.
	 */
	depth: number;
}

/** The frame a function sets up, or addresses through the stack pointer. */
export function frameOf(insns: readonly DebugInsn[]): Frame {
	if (insns.length === 0) {
		return { base: "rsp", hasFramePointer: false, depth: 0, unknown: true };
	}
	let pushed = false;
	let set = false;
	let depth = 0;
	for (const insn of insns) {
		const text = insn.text.trim();
		if (/^push\s+rbp$/i.test(text)) pushed = true;
		if (/^mov\s+rbp,\s*rsp$/i.test(text)) {
			set = true;
			continue;
		}
		// The allocation that makes the frame, and the alignment that pads it.
		// Both are `rsp`-relative and neither is a variable.
		const sub = /^sub\s+rsp,\s*(0x[0-9a-f]+|\d+)$/i.exec(text);
		if (sub) depth = Math.max(depth, numberOf(sub[1]));
		const and = /^and\s+rsp,\s*(-?(0x[0-9a-f]+|\d+))$/i.exec(text);
		if (and) depth = Math.max(depth, -numberOf(and[1]) & 0xf);
	}
	return {
		base: set ? "rbp" : "rsp",
		hasFramePointer: set && pushed,
		depth,
		// No prologue in view means the frame is *unread*, not that there is
		// none: the debugger's window is a slice of the function and usually does
		// not reach its first instruction, and a window that missed the prologue
		// would otherwise report a leaf frame and resolve no `rbp` slot at all.
		// Nothing is lost by saying so, because a function that truly has no frame
		// pointer addresses its frame through the stack, whose offsets are the
		// ones an unknown frame already reads as written.
		unknown: !set,
	};
}

/** A number as the decoder printed it: hexadecimal or decimal. */
function numberOf(text: string): number {
	return text.startsWith("0x") || text.startsWith("0X")
		? Number.parseInt(text.slice(2), 16)
		: Number.parseInt(text, 10);
}

/**
 * The canonical slot a stack operand names, whichever register names it.
 *
 * Every frame reference in a function collapses to one number: an offset from
 * the frame pointer when there is one, and from the stack pointer after
 * translating by the frame's depth when there is not. That is what lets
 * `[rbp - 0x18]` and `[rsp + 0x58]` be recognised as the same variable instead
 * of two rows with two names.
 *
 * Offset 0 is the saved frame pointer when there is a frame pointer, and a link
 * rather than a variable, so it is reported as null and never named.
 *
 * ```
 * const frame = frameOf([
 *   { addr: 0, bytes: "55", text: "push rbp" },
 *   { addr: 1, bytes: "4889e5", text: "mov rbp, rsp" },
 *   { addr: 4, bytes: "4883ec20", text: "sub rsp, 0x20" },
 * ]);
 * slotIn("mov rax, qword ptr [rbp - 0x18]", frame)  // => -24
 * slotIn("mov rax, qword ptr [rsp + 0x8]", frame)   // => -24
 * ```
 *
 * @param text - The instruction, or the operand part of it.
 * @param frame - The frame the function addresses.
 * @returns The slot's canonical offset, or null when it names no frame slot.
 */
export function slotIn(text: string, frame: Frame): number | null {
	// With no instructions to read the frame from, nothing is known about how
	// this function addresses its stack — and a listing that has not decoded its
	// function yet must still resolve a plain `[rbp - 4]` rather than quietly
	// matching nothing. The offsets are used as written, which is right for a
	// frame-pointer function and the best available answer for a leaf one.
	if (frame.unknown) {
		return frameSlot(text, "rbp") ?? frameSlot(text, "rsp");
	}
	if (frame.hasFramePointer) {
		const viaFrame = frameSlot(text, "rbp");
		if (viaFrame !== null) return viaFrame === 0 ? null : viaFrame;
		const viaStack = frameSlot(text, "rsp");
		if (viaStack === null) return null;
		const canonical = viaStack - frame.depth;
		return canonical === 0 ? null : canonical;
	}
	// No frame pointer: the stack pointer is the frame, so its offsets are
	// already canonical — a function that never sets up a frame has locals
	// counted from the allocation it did make.
	const viaStack = frameSlot(text, "rsp");
	return viaStack === null || viaStack === 0 ? null : viaStack;
}

/** The offset an operand names through a given frame register, or null. */
function frameSlot(text: string, reg: string): number | null {
	const m = new RegExp(
		`\\[\\s*${reg}\\s*([+-])\\s*(0x[0-9a-f]+|\\d+)\\s*\\]`,
		"i",
	).exec(text);
	if (!m) return null;
	const magnitude = numberOf(m[2]);
	return m[1] === "-" ? -magnitude : magnitude;
}

/**
 * The analyst's name for the variable a line of disassembly touches.
 *
 * The one lookup every view shares, kept pure and separate from the hook so it
 * can be checked without rendering anything: the debugger, the function listing
 * and the graph all resolve a name through here, which is the only reason a name
 * recorded in one of them appears in the others.
 *
 * @param names - Recorded names, as `"<func>:<slot>" -> name`.
 * @param func - The function's static address.
 * @param insns - The function's instructions, which say how it addresses frames.
 * @param text - The instruction, or the operand part of it.
 * @returns The name, or "" when the slot is unnamed or the line names no slot.
 */
export function varNameIn(
	names: Readonly<Record<string, string>>,
	func: number,
	insns: readonly DebugInsn[],
	text: string,
): string {
	const slot = slotIn(text, frameOf(insns));
	if (slot === null) return "";
	return names[`${func}:${slot}`] ?? "";
}

/**
 * The derived name a variable has until the analyst gives it a real one.
 *
 * Shown in the disassembly beside the operand, because a slot that is only
 * visible as `[rbp - 4]` is not something an analyst can *see*: the derived name
 * is what turns the operand into a thing with an identity, and it is where the
 * click that renames it goes.
 */
export function derivedName(slot: number): string {
	return `var_${Math.abs(slot).toString(16)}`;
}

/**
 * How a slot is written in a row of the variables view.
 *
 * The canonical offset is what a name is keyed by, but the analyst recognises
 * the operand they can see, so the row is labelled in that register's terms.
 */
export function slotLabel(slot: number, frame: Frame): string {
	const magnitude = Math.abs(slot).toString(16);
	if (!frame.hasFramePointer) return `rsp${slot < 0 ? "-" : "+"}${magnitude}`;
	const throughStack = slot < -frame.depth;
	const reg = throughStack ? "rsp" : "rbp";
	const shown = throughStack ? slot + frame.depth : slot;
	return `${reg}${shown < 0 ? "-" : "+"}${Math.abs(shown).toString(16)}`;
}

/**
 * The stack slots a function uses as variables.
 *
 * Derived from the frame pointer the prologue establishes, so it is a list of
 * what the code does rather than a list of what the file declares: no symbol
 * table has these, and a stripped binary's variable tracking is built from the
 * same evidence. The saved frame pointer at offset 0 is a link, not a variable,
 * and is left out — a name for it would be `saved rbp`, which nobody types.
 *
 * ```
 * localsOf([
 *   { addr: 0x1000, bytes: "554889e5", text: "push rbp" },
 *   { addr: 0x1001, bytes: "4889e5", text: "mov rbp, rsp" },
 *   { addr: 0x1004, bytes: "48c745e800000000", text: "mov qword ptr [rbp - 0x8], 0" },
 *   { addr: 0x100b, bytes: "488b45e8", text: "mov rax, qword ptr [rbp - 0x8]" },
 * ]).map((v) => v.offset)
 * // => [-8]
 * ```
 *
 * @param insns - The function's instructions, in address order.
 * @returns Its slots, nearest the frame pointer first.
 */
export function localsOf(insns: readonly DebugInsn[]): LocalVar[] {
	const frame = frameOf(insns);
	const slots = new Map<number, LocalVar>();
	for (const insn of insns) {
		const text = insn.text;
		const operands = text.slice(text.indexOf(" ") + 1);
		// A `lea` takes the slot's address; it neither reads nor writes the value
		// stored there, and mistaking it for a read would make every pointer look
		// like a variable that is used before it is set.
		const isLea = /^(lea|leaq)\b/.test(text.trim());
		const [destination, source = ""] = operands.split(",");
		// `cmp` and `test` read both operands and change neither, so a slot in
		// the first position of one is a read — otherwise the comparison that
		// ends a loop reads as the loop storing to its counter.
		const readsBoth = READS_BOTH.has(
			text.trim().split(/\s+/)[0].toLowerCase(),
		);
		const destSlot = slotIn(destination, frame);
		const srcSlot = slotIn(source, frame);
		if (destSlot === null && srcSlot === null) continue;

		const slot = destSlot ?? srcSlot!;
		const existing = slots.get(slot) ?? {
			offset: slot,
			reads: 0,
			writes: 0,
			width: 0,
			isPointer: false,
		};
		// The widest access is the variable's own width: a slot read as a byte and
		// written as a qword is a qword with a byte-sized window on it.
		existing.width = Math.max(
			existing.width,
			ptrWidth(operands) ?? regWidth(destination),
		);
		if (isLea) {
			existing.isPointer = true;
		} else if (destSlot !== null && !readsBoth) {
			existing.writes += 1;
		} else {
			existing.reads += 1;
		}
		slots.set(slot, existing);
	}
	return [...slots.values()].sort(
		(a, b) => Math.abs(a.offset) - Math.abs(b.offset),
	);
}

/**
 * The argument registers a function actually uses.
 *
 * Traced from the entry: an argument is read at some point *before* it is
 * written, and a register that is written first is the function's own. Reading a
 * register the caller may not have set is not proof of an argument, but writing
 * one first is proof against it, and between the two this keeps the locals and
 * the parameters apart without a calling-convention database.
 *
 * ```
 * argsOf([
 *   { addr: 0x1000, bytes: "4889fb", text: "mov rbx, rdi" },
 *   { addr: 0x1003, bytes: "4885ff", text: "test rdi, rdi" },
 * ]).map((a) => a.reg)
 * // => ["rdi"]
 * ```
 *
 * @param insns - The function's instructions, in address order.
 * @returns The argument registers it reads, in ABI order.
 */
export function argsOf(insns: readonly DebugInsn[]): ArgVar[] {
	const state = new Map<string, ArgVar>();
	for (const insn of insns) {
		const text = insn.text.trim();
		if (/^(jmp|call|ret)\b/.test(text)) continue;
		const operands = text.slice(text.indexOf(" ") + 1);
		const [destination = "", source = ""] = operands.split(",");
		const readsBoth = READS_BOTH.has(text.split(/\s+/)[0].toLowerCase());
		// One touch per register per instruction: `test rdi, rdi` mentions the
		// register twice and is still a single read, and an instruction that both
		// reads and writes it (`mov rdi, rdi`) is a write — the function has
		// claimed the register either way.
		const touched = new Map<string, "read" | "write">();
		for (const [operand, destinationSide] of [
			[destination, true],
			[source, false],
		] as const) {
			const reg = REG.exec(operand.trim());
			if (!reg) continue;
			const canonical = argRegName(reg[1]);
			if (canonical === null) continue;
			const written = destinationSide && !readsBoth;
			if (written || touched.get(canonical) === undefined) {
				touched.set(canonical, written ? "write" : "read");
			}
		}
		for (const [reg, how] of touched) {
			const all: readonly string[] = ARG_REGS;
			const arg = state.get(reg) ?? {
				reg,
				index: all.indexOf(reg),
				reads: 0,
				writes: 0,
			};
			if (how === "write") arg.writes += 1;
			else arg.reads += 1;
			state.set(reg, arg);
		}
	}
	return (
		[...state.values()]
			// Read before written: the caller's value reached the function.
			.filter((a) => a.reads > 0 && a.writes === 0)
			.sort((a, b) => a.index - b.index)
	);
}

/**
 * The name a variable is shown under until the analyst gives it one.
 *
 * `var_18` reads as an offset, which is what it is, and does not pretend the
 * value is known; `arg1` is the first argument by the ABI's own count. A
 * pointer is marked as one because that much the instructions do say.
 */
export function defaultVarName(v: LocalVar | ArgVar): string {
	if ("index" in v) return `arg${v.index + 1}`;
	return derivedName(v.offset);
}

/**
 * A one-line guess at what a variable holds, for a row of text next to it.
 *
 * Deliberately coarse and never in the rename: the point is to save the analyst
 * typing, not to assert a type they did not check. A pointer is a pointer
 * because the code took its address; a narrow slot is a small number.
 */
export function describeVar(v: LocalVar): string {
	if (v.isPointer) return "pointer";
	if (v.width === 1) return "byte";
	if (v.width === 2) return "short";
	if (v.width === 4) return "int";
	return "qword";
}
