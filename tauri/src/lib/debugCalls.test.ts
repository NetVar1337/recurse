import { describe, expect, it } from "vitest";
import {
	callTarget,
	frameOffsetIn,
	frameOffsetOf,
	pltSlot,
	ripTarget,
	shortName,
} from "./debugCalls";
import type { DebugInsn } from "../types";

/** A decoded instruction with a known length, so rip arithmetic is checkable. */
function insn(addr: number, text: string, bytes = "90"): DebugInsn {
	return { addr, bytes, text };
}

describe("callTarget", () => {
	it("reads a direct call's destination", () => {
		expect(
			callTarget(insn(0x401000, "call 0x401234", "e807050000")),
		).toEqual({
			kind: "direct",
			addr: 0x401234,
		});
	});

	it("reads a direct jmp too, for a tail call", () => {
		expect(
			callTarget(insn(0x401000, "jmp 0x401234", "e907050000")),
		).toEqual({
			kind: "direct",
			addr: 0x401234,
		});
	});

	it("reads a call through the GOT as the slot it jumps through", () => {
		// `ff 15` is six bytes, so rip points 6 past the instruction.
		expect(
			callTarget(
				insn(0x7f00, "call qword ptr [rip + 0x200836]", "ff15d6080200"),
			),
		).toEqual({ kind: "slot", addr: 0x7f06 + 0x200836 });
	});

	it("handles a negative displacement", () => {
		expect(
			callTarget(
				insn(0x7f00, "jmp qword ptr [rip - 0x20]", "ff25e0ffffff"),
			),
		).toEqual({ kind: "slot", addr: 0x7f06 - 0x20 });
	});

	it("has no target for a call through a register", () => {
		// The destination is in a register, so nothing in the instruction names
		// it; guessing here would put a wrong name on a call.
		expect(callTarget(insn(0x401000, "call rax", "ffd0"))).toBeNull();
		expect(
			callTarget(insn(0x401000, "call qword ptr [rax]", "ff10")),
		).toBeNull();
	});

	it("has no target for an instruction that is not a branch", () => {
		expect(callTarget(insn(0x401000, "mov rbp, rsp", "4889e5"))).toBeNull();
	});

	it("ignores an absolute address in a comment", () => {
		expect(callTarget(insn(0x401000, "nop ; 0xdeadbeef", "90"))).toBeNull();
	});
});

describe("ripTarget", () => {
	it("resolves a data operand's displacement to an address", () => {
		// `push qword ptr [rip + 0x200af2]`, six bytes on, is 0x601008: which is
		// a real GOT slot, and not something the displacement says on its own.
		expect(
			ripTarget(
				insn(
					0x400510,
					"push qword ptr [rip + 0x200af2]",
					"ff35f2f20a00",
				),
			),
		).toBe(0x601008);
	});

	it("resolves any instruction, not only a branch", () => {
		// A store to a global and a lea of an address are both references, and
		// both are just as opaque as a call.
		expect(
			ripTarget(
				insn(
					0x400649,
					"mov byte ptr [rip + 0x2009fe], 1",
					"c605fe09200001",
				),
			),
		).toBe(0x60104e);
		expect(
			ripTarget(
				insn(0x400640, "lea rdx, [rip + 0x2006ae]", "488d15ae062000"),
			),
		).toBe(0x600cf5);
	});

	it("handles a negative displacement", () => {
		expect(
			ripTarget(
				insn(
					0x400510,
					"mov eax, dword ptr [rip - 0x20]",
					"8b05e0ffffff",
				),
			),
		).toBe(0x400516 - 0x20);
	});

	it("has no target for an instruction that references no address", () => {
		expect(ripTarget(insn(0x400510, "mov rax, rax", "4889c0"))).toBeNull();
		expect(
			ripTarget(insn(0x400510, "mov eax, dword ptr [rbp - 8]", "8b4508")),
		).toBeNull();
	});
});

describe("frameOffsetOf", () => {
	it("reads the frame slot an operand names", () => {
		expect(
			frameOffsetOf(
				insn(0x1004, "mov rax, qword ptr [rbp - 0x8]", "488b45f8"),
			),
		).toBe(-8);
		expect(
			frameOffsetOf(
				insn(0x1004, "mov rax, qword ptr [rbp + 0x10]", "488b4510"),
			),
		).toBe(0x10);
	});

	it("has no offset without a frame pointer", () => {
		// `rsp`-relative is a frame, but not one with offsets anyone names, and
		// guessing which it is would put the wrong name on the operand.
		expect(
			frameOffsetOf(
				insn(0x1004, "mov rax, qword ptr [rsp + 0x10]", "488b442410"),
			),
		).toBeNull();
	});

	it("has no offset for an instruction that names no slot", () => {
		expect(
			frameOffsetOf(insn(0x1004, "mov rax, rax", "4889c0")),
		).toBeNull();
	});
});

describe("frameOffsetIn", () => {
	it("reads the slot out of a line of disassembly, with no instruction object", () => {
		// The static views have a rendered line and nothing else, and they ask
		// the same question: which name goes beside this slot?
		expect(frameOffsetIn("mov dword ptr [rbp - 4], 0xbadf00d")).toBe(-4);
		expect(
			frameOffsetIn("cmp dword ptr [rbp - 0x20], 0xc0ff33 ; local_20"),
		).toBe(-0x20);
	});

	it("has no offset without a frame pointer", () => {
		expect(frameOffsetIn("mov rax, qword ptr [rsp + 0x10]")).toBeNull();
	});
});

describe("pltSlot", () => {
	it("reads the slot a stub jumps through", () => {
		// `ff 25 10 00 00 00` at 0x1080: rip is 0x1086, plus 0x10.
		expect(pltSlot(0x1080, "ff2510000000")).toBe(0x1096);
	});

	it("reads a backwards stub, for a GOT that sits before the PLT", () => {
		// 0x2000 + 6 - 0x10
		expect(pltSlot(0x2000, "ff25f0ffffff")).toBe(0x1ff6);
	});

	it("tolerates the spaced hex the read op can return", () => {
		expect(pltSlot(0x1080, "ff 25 10 00 00 00")).toBe(0x1096);
	});

	it("has no slot for bytes that are not a PLT jump", () => {
		expect(pltSlot(0x1080, "554889e5")).toBeNull();
		expect(pltSlot(0x1080, "")).toBeNull();
	});
});

describe("shortName", () => {
	it("drops the import prefix and keeps everything else", () => {
		expect(shortName("imp.puts")).toBe("puts");
		expect(shortName("imp.__isoc99_scanf")).toBe("__isoc99_scanf");
		// An unresolved name stays visibly unresolved.
		expect(shortName("fcn_00001234")).toBe("fcn_00001234");
		expect(shortName("sym.imp.thing")).toBe("sym.imp.thing");
	});
});
