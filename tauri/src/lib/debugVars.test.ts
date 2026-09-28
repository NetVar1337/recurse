import { describe, expect, it } from "vitest";

import {
	ARG_REGS,
	argsOf,
	defaultVarName,
	describeVar,
	derivedName,
	frameOf,
	localsOf,
	slotIn,
	slotLabel,
	varNameIn,
} from "./debugVars";
import type { DebugInsn } from "../types";

/** A decoded instruction, with a length the tests do not depend on. */
function at(addr: number, text: string, bytes = "90"): DebugInsn {
	return { addr, bytes, text };
}

/** A function with a frame pointer set up, and nothing else in it. */
const PROLOGUE: DebugInsn[] = [
	at(0x1000, "push rbp", "55"),
	at(0x1001, "mov rbp, rsp", "4889e5"),
];

describe("localsOf", () => {
	it("finds a slot that is written and read", () => {
		const locals = localsOf([
			...PROLOGUE,
			at(0x1004, "mov qword ptr [rbp - 0x8], 0", "48c745f800000000"),
			at(0x100b, "mov rax, qword ptr [rbp - 0x8]", "488b45f8"),
		]);
		expect(locals).toEqual([
			{ offset: -8, reads: 1, writes: 1, width: 8, isPointer: false },
		]);
	});

	it("leaves the saved frame pointer out", () => {
		// `[rbp]` holds the caller's rbp: a link, not a variable, and nobody
		// types a name for it.
		const locals = localsOf([
			...PROLOGUE,
			at(0x1004, "mov qword ptr [rbp], rax", "48894500"),
			at(0x1008, "mov rax, qword ptr [rbp - 0x8]", "488b45f8"),
		]);
		expect(locals.map((v) => v.offset)).toEqual([-8]);
	});

	it("marks a slot whose address is taken as a pointer", () => {
		// `lea` reads the slot's address, not its value, so it is neither a read
		// nor a write — and a pointer is a pointer because of exactly this.
		const locals = localsOf([
			...PROLOGUE,
			at(0x1004, "lea rdx, [rbp - 0x18]", "488d55e8"),
			at(0x1008, "mov qword ptr [rbp - 0x18], rax", "488945e8"),
		]);
		expect(locals[0]).toEqual({
			offset: -0x18,
			reads: 0,
			writes: 1,
			width: 8,
			isPointer: true,
		});
	});

	it("takes the widest access as the variable's width", () => {
		// A byte-sized window onto a qword is still a qword.
		const locals = localsOf([
			...PROLOGUE,
			at(0x1004, "mov byte ptr [rbp - 0x18], 1", "c645e801"),
			at(0x1008, "mov rax, qword ptr [rbp - 0x18]", "488b45e8"),
		]);
		expect(locals[0].width).toBe(8);
	});

	it("reads a decimal offset, which is how a small slot is printed", () => {
		// `[rbp - 4]` is a loop counter, not a `[rbp - 0x4]`, and a matcher that
		// only reads hex would leave the most common variable in a function
		// without a name.
		const locals = localsOf([
			...PROLOGUE,
			at(0x1004, "mov dword ptr [rbp - 4], 0xbadf00d", "c745fc0dfaad00"),
			at(0x100b, "add dword ptr [rbp - 4], 1", "8345fc01"),
		]);
		expect(locals[0]).toEqual({
			offset: -4,
			reads: 0,
			writes: 2,
			width: 4,
			isPointer: false,
		});
	});

	it("reads a narrow slot as narrow", () => {
		const locals = localsOf([
			...PROLOGUE,
			at(0x1004, "mov byte ptr [rbp - 0x1], 1", "c645ff01"),
		]);
		expect(locals[0].width).toBe(1);
	});

	it("orders slots by how close they are to the frame pointer", () => {
		const locals = localsOf([
			...PROLOGUE,
			at(0x1004, "mov qword ptr [rbp - 0x28], 0", "48c745d800000000"),
			at(0x100b, "mov qword ptr [rbp - 0x8], 0", "48c745f800000000"),
			at(0x1012, "mov qword ptr [rbp - 0x10], 0", "48c745f000000000"),
		]);
		expect(locals.map((v) => v.offset)).toEqual([-0x8, -0x10, -0x28]);
	});

	it("counts a loop counter's writes, which is what names it", () => {
		const locals = localsOf([
			...PROLOGUE,
			at(0x1004, "mov dword ptr [rbp - 0x4], 0", "c745fc00000000"),
			at(0x100b, "add dword ptr [rbp - 0x4], 1", "8345fc01"),
			at(0x100f, "mov eax, dword ptr [rbp - 0x4]", "8b45fc"),
		]);
		expect(locals[0]).toEqual({
			offset: -4,
			reads: 1,
			writes: 2,
			width: 4,
			isPointer: false,
		});
	});

	it("finds the slots of a function that never sets up a frame pointer", () => {
		// A leaf function addresses its frame through the stack pointer, and its
		// locals are just as visible there. Demanding a frame pointer would leave
		// every leaf function in the binary with no variables at all.
		const locals = localsOf([
			at(0x1000, "sub rsp, 0x18", "4883ec18"),
			at(0x1004, "mov qword ptr [rsp + 0x8], rax", "4889442408"),
			at(0x1009, "mov rax, qword ptr [rsp + 0x8]", "488b442408"),
		]);
		expect(locals).toEqual([
			{ offset: 0x8, reads: 1, writes: 1, width: 8, isPointer: false },
		]);
	});

	it("counts a stack-pointer slot and a frame-pointer slot as one variable", () => {
		// With `rsp` 0x20 below `rbp`, these two operands are the same eight
		// bytes, and one name has to cover both spellings of it.
		const body = [
			...PROLOGUE,
			at(0x1004, "sub rsp, 0x20", "4883ec20"),
			at(0x1008, "mov qword ptr [rsp + 0x8], rax", "4889442408"),
			at(0x100d, "mov rax, qword ptr [rbp - 0x18]", "488b45e8"),
		];
		expect(localsOf(body)).toEqual([
			{ offset: -0x18, reads: 1, writes: 1, width: 8, isPointer: false },
		]);
	});

	it("finds nothing in a function that touches no frame", () => {
		expect(localsOf([at(0x1000, "nop", "90")])).toEqual([]);
	});

	it("does not mistake a call's operand for a slot", () => {
		// The frame pointer is saved across a call, so every frame-pointer
		// function has these; they are not variables.
		const locals = localsOf([
			...PROLOGUE,
			at(0x1004, "mov rax, qword ptr [rbp - 0x8]", "488b45f8"),
			at(0x1008, "call rax", "ffd0"),
		]);
		expect(locals).toHaveLength(1);
	});
});

describe("frameOf", () => {
	it("sees a frame pointer being set up", () => {
		expect(frameOf(PROLOGUE)).toEqual({
			base: "rbp",
			hasFramePointer: true,
			depth: 0,
			unknown: false,
		});
	});

	it("counts the frame allocation, which is what a stack offset is measured from", () => {
		expect(
			frameOf([...PROLOGUE, at(0x1004, "sub rsp, 0x20", "4883ec20")]),
		).toEqual({
			base: "rbp",
			hasFramePointer: true,
			depth: 0x20,
			unknown: false,
		});
	});

	it("calls a function with no frame pointer an unread frame, not a leaf one", () => {
		// Nothing here says whether a prologue exists elsewhere in the function —
		// the debugger's window usually does not include one — so the honest
		// answer is "unread", and a stack offset is then read as written, which is
		// what a leaf function needs anyway.
		expect(frameOf([at(0x1000, "sub rsp, 0x18", "4883ec18")])).toEqual({
			base: "rsp",
			hasFramePointer: false,
			depth: 0x18,
			unknown: true,
		});
	});

	it("reads a frame-pointer function's slots from a window with no prologue", () => {
		// The debugger's disassembly window is a slice: it holds the middle of a
		// function, not its first instruction. Reading that slice as a leaf
		// function would resolve no `rbp` slot at all, and a name recorded in one
		// view would be invisible in the other.
		const window = [
			at(0x91a, "mov dword ptr [rbp - 4], 0xbadf00d", "c745fc0dfaad00"),
			at(0x921, "mov eax, dword ptr [rbp - 4]", "8b45fc"),
		];
		expect(frameOf(window).unknown).toBe(true);
		expect(
			slotIn("mov dword ptr [rbp - 4], 0xbadf00d", frameOf(window)),
		).toBe(-4);
	});

	it("does not mistake a saved frame pointer for a frame", () => {
		// `mov rbx, rbp` saves a register; it does not establish a frame, and
		// treating it as one would translate every stack offset wrongly.
		expect(
			frameOf([
				at(0x1000, "push rbx", "53"),
				at(0x1001, "mov rbp, rbx", "4889dd"),
				at(0x1004, "sub rsp, 0x10", "4883ec10"),
			]),
		).toEqual({
			base: "rsp",
			hasFramePointer: false,
			depth: 0x10,
			unknown: true,
		});
	});
});

describe("slotIn", () => {
	const withFrame = frameOf([
		...PROLOGUE,
		at(0x1004, "sub rsp, 0x20", "4883ec20"),
	]);
	const leaf = frameOf([at(0x1000, "sub rsp, 0x18", "4883ec18")]);

	it("reads a frame-pointer offset as written", () => {
		expect(slotIn("mov rax, qword ptr [rbp - 0x18]", withFrame)).toBe(
			-0x18,
		);
	});

	it("translates a stack offset onto the same frame", () => {
		// `rsp` is 0x20 below `rbp`, so `[rsp + 8]` is `[rbp - 0x18]`.
		expect(slotIn("mov rax, qword ptr [rsp + 0x8]", withFrame)).toBe(-0x18);
	});

	it("claims nothing for the saved frame pointer", () => {
		// Offset 0 through the frame pointer is the link back to the caller's
		// frame, not a variable, and a name for it would be "saved rbp".
		expect(slotIn("mov rbp, qword ptr [rbp]", withFrame)).toBeNull();
	});

	it("leaves a stack frame's own offsets alone", () => {
		// With no frame pointer the stack pointer *is* the frame, so `[rsp + 8]`
		// is a slot counted from the allocation and not translated by it.
		expect(slotIn("mov rax, qword ptr [rsp + 0x8]", leaf)).toBe(0x8);
	});

	it("still reads a slot when the frame is unknown", () => {
		// A listing can hold a line of disassembly before its function's prologue
		// has been decoded, and a plain `[rbp - 4]` must still name rather than
		// quietly match nothing.
		const unknown = frameOf([]);
		expect(unknown.unknown).toBe(true);
		expect(slotIn("mov dword ptr [rbp - 4], 0xbadf00d", unknown)).toBe(-4);
		expect(slotIn("mov rax, qword ptr [rsp + 0x8]", unknown)).toBe(0x8);
	});

	it("has no slot for a register that is not the frame", () => {
		expect(slotIn("mov rax, qword ptr [rbx - 8]", withFrame)).toBeNull();
		expect(slotIn("mov rax, rax", withFrame)).toBeNull();
	});
});

describe("slotLabel", () => {
	it("labels a slot the way the code writes it", () => {
		const withFrame = frameOf([
			...PROLOGUE,
			at(0x1004, "sub rsp, 0x20", "4883ec20"),
		]);
		// Reached through the frame pointer, so that is how it is shown.
		expect(slotLabel(-0x18, withFrame)).toBe("rbp-18");
		// Below the frame allocation, so the stack pointer is the register the
		// analyst will see in the disassembly.
		expect(slotLabel(-0x30, withFrame)).toBe("rsp-10");
	});

	it("labels a leaf function's slots against the stack pointer", () => {
		const leaf = frameOf([at(0x1000, "sub rsp, 0x18", "4883ec18")]);
		expect(slotLabel(0x8, leaf)).toBe("rsp+8");
	});
});

/**
 * The `banner` function from the crackme in the session, as the debuggee's own
 * decoder printed it: a frame pointer, no explicit frame allocation, and locals
 * reached through both registers.
 */
const BANNER: DebugInsn[] = [
	{ addr: 0x8eb, bytes: "55", text: "push rbp" },
	{ addr: 0x8ec, bytes: "4889e5", text: "mov rbp, rsp" },
	{ addr: 0x8ef, bytes: "b801000000", text: "mov eax, 1" },
	{ addr: 0x8f4, bytes: "e8db0b0000", text: "call 0x14d4" },
	{
		addr: 0x8f9,
		bytes: "c745fc0dfaad00",
		text: "mov dword ptr [rbp - 4], 0xbadf00d",
	},
	{
		addr: 0x900,
		bytes: "c745f8ad1dfeff",
		text: "mov dword ptr [rbp - 8], 0xfffe1dad",
	},
	{ addr: 0x907, bytes: "8b55f8", text: "mov edx, dword ptr [rbp - 8]" },
	{ addr: 0x90a, bytes: "8b45fc", text: "mov eax, dword ptr [rbp - 4]" },
	{ addr: 0x90d, bytes: "89c6", text: "mov esi, eax" },
	{ addr: 0x90f, bytes: "488d3d...", text: "lea rdi, [rip + 0x212]" },
	{ addr: 0x919, bytes: "31c0", text: "xor eax, eax" },
	{ addr: 0x91b, bytes: "e8100a0000", text: "call 0x730" },
	{ addr: 0x920, bytes: "488d45b0", text: "lea rax, [rbp - 0x70]" },
	{ addr: 0x924, bytes: "4889c6", text: "mov rsi, rax" },
	{ addr: 0x927, bytes: "488d3d...", text: "lea rdi, [rip + 0x217]" },
	{ addr: 0x937, bytes: "83f8ff", text: "cmp eax, -1" },
	{ addr: 0x93a, bytes: "7405", text: "je 0x941" },
	{
		addr: 0x93c,
		bytes: "81f8c0ff3300",
		text: "cmp dword ptr [rbp - 4], 0xc0ff33",
	},
];

describe("the crackme's banner function", () => {
	it("addresses its frame through the frame pointer", () => {
		expect(frameOf(BANNER).hasFramePointer).toBe(true);
	});

	it("finds both of its locals, in the spelling the code uses", () => {
		const locals = localsOf(BANNER);
		expect(locals.map((v) => v.offset)).toEqual([-4, -8, -0x70]);
		// `cmp [rbp - 4], 0xc0ff33` is the loop's test, so the counter is both
		// written and read.
		expect(locals[0].writes).toBe(1);
		expect(locals[0].reads).toBe(2);
	});

	it("gives every access to a slot the same key", () => {
		const frame = frameOf(BANNER);
		for (const insn of BANNER) {
			const slot = slotIn(insn.text, frame);
			if (slot !== null) expect(typeof slot).toBe("number");
		}
		expect(slotIn("lea rax, [rbp - 0x70]", frameOf(BANNER))).toBe(-0x70);
	});
});

describe("derivedName", () => {
	it("names a slot after its own offset", () => {
		// What a row shows before the analyst has named anything: a slot with an
		// identity, so `[rbp - 4]` is a thing rather than an arithmetic exercise.
		expect(derivedName(-4)).toBe("var_4");
		expect(derivedName(-0x18)).toBe("var_18");
		expect(derivedName(0x8)).toBe("var_8");
	});
});

describe("varNameIn", () => {
	// The names as the variables view records them: `"<func>:<slot>"`.
	const NAMES = { [`${0x8eb}:-4`]: "counter", [`${0x8eb}:rdi`]: "input" };

	it("finds the name of a frame slot in the listing that shows it", () => {
		// The whole point: a name typed in one view has to be found by the line of
		// disassembly the analyst is reading in another.
		expect(
			varNameIn(
				NAMES,
				0x8eb,
				BANNER,
				"mov dword ptr [rbp - 4], 0xbadf00d",
			),
		).toBe("counter");
	});

	it("finds it through the stack pointer as well", () => {
		const frame = [...BANNER, at(0x940, "sub rsp, 0x20", "4883ec20")];
		// `[rsp + 0x1c]` is `[rbp - 4]` once the frame is 0x20 deep: the same
		// variable, named once.
		expect(
			varNameIn(NAMES, 0x8eb, frame, "mov eax, dword ptr [rsp + 0x1c]"),
		).toBe("counter");
	});

	it("keeps one function's names out of another's", () => {
		expect(
			varNameIn(NAMES, 0x999, BANNER, "mov dword ptr [rbp - 4], 1"),
		).toBe("");
	});

	it("has no name for a slot nobody named, or for no slot at all", () => {
		expect(
			varNameIn(NAMES, 0x8eb, BANNER, "mov dword ptr [rbp - 8], 0xfff"),
		).toBe("");
		expect(varNameIn(NAMES, 0x8eb, BANNER, "mov rax, rax")).toBe("");
		// The saved frame pointer is a link, not a variable, so it is never named.
		expect(
			varNameIn(NAMES, 0x8eb, BANNER, "mov rbp, qword ptr [rbp]"),
		).toBe("");
	});

	/**
	 * The transfer the two views depend on: a name recorded while debugging is
	 * found by the static listing, and the debugger's window — a slice of the
	 * function that does not include its prologue — has to resolve the same slot.
	 */
	it("transfers a name from the debugger's window to the static listing", () => {
		// The debugger decodes a window around the cursor, so the prologue is
		// usually not in it.
		const debuggerWindow = BANNER.slice(8);
		expect(
			debuggerWindow.some((i) => /^push rbp$/.test(i.text.trim())),
		).toBe(false);
		const line = "mov dword ptr [rbp - 4], 0xbadf00d";
		// Same name, from a window that never saw the prologue and from the whole
		// function, which is what the static listing holds.
		expect(varNameIn(NAMES, 0x8eb, debuggerWindow, line)).toBe("counter");
		expect(varNameIn(NAMES, 0x8eb, BANNER, line)).toBe("counter");
	});

	it("still finds a name before the function's frame is known", () => {
		// A listing can render a line before its function's instructions have
		// loaded, and the name must not depend on that having happened.
		expect(varNameIn(NAMES, 0x8eb, [], "mov dword ptr [rbp - 4], 1")).toBe(
			"counter",
		);
	});
});

describe("argsOf", () => {
	it("finds a register read but never written", () => {
		const args = argsOf([
			at(0x1000, "mov rbx, rdi", "4889fb"),
			at(0x1003, "test rdi, rdi", "4885ff"),
		]);
		expect(args).toEqual([{ reg: "rdi", index: 0, reads: 2, writes: 0 }]);
	});

	it("leaves out a register the function claims for itself", () => {
		// Written before it is read, so it is a local in a register, not an
		// argument: the caller never had anything to put there.
		expect(argsOf([at(0x1000, "xor edi, edi", "31ff")])).toEqual([]);
	});

	it("orders arguments by the ABI, not by first use", () => {
		const args = argsOf([
			at(0x1000, "mov rax, r9", "4c89c8"),
			at(0x1003, "mov rcx, rsi", "4889f1"),
		]);
		// r9 is the sixth integer argument, whatever order it is first used in.
		expect(args.map((a) => `${a.index}:${a.reg}`)).toEqual([
			"1:rsi",
			"5:r9",
		]);
	});

	it("knows all six integer argument registers", () => {
		const args = argsOf(
			ARG_REGS.map((r, i) => at(0x1000 + i, `mov rax, ${r}`, "90")),
		);
		expect(args.map((a) => a.reg)).toEqual([...ARG_REGS]);
	});

	it("matches a 32-bit alias of an argument register", () => {
		// A function taking `char *` in rdi writes to it as `edi`, and it is
		// still the first argument.
		expect(argsOf([at(0x1000, "mov eax, edi", "89f8")])).toEqual([
			{ reg: "rdi", index: 0, reads: 1, writes: 0 },
		]);
	});

	it("does not treat a callee-saved register as an argument", () => {
		expect(argsOf([at(0x1000, "mov rax, rbx", "4889d8")])).toEqual([]);
	});
});

describe("defaultVarName", () => {
	it("names a slot by its offset, in hex", () => {
		expect(
			defaultVarName({
				offset: -0x18,
				reads: 1,
				writes: 1,
				width: 8,
				isPointer: false,
			}),
		).toBe("var_18");
	});

	it("names an argument by its position", () => {
		expect(
			defaultVarName({ reg: "rdi", index: 0, reads: 1, writes: 0 }),
		).toBe("arg1");
	});
});

describe("describeVar", () => {
	it("says what the instructions actually show", () => {
		const base = { offset: -8, reads: 1, writes: 1, isPointer: false };
		expect(describeVar({ ...base, width: 1 })).toBe("byte");
		expect(describeVar({ ...base, width: 4 })).toBe("int");
		expect(describeVar({ ...base, width: 8 })).toBe("qword");
		// A pointer is the one thing the code said outright.
		expect(describeVar({ ...base, width: 8, isPointer: true })).toBe(
			"pointer",
		);
	});
});
