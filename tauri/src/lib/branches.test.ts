import { describe, expect, it } from "vitest";

import {
	branchVerdict,
	classifyInsn,
	peekTarget,
	testCondition,
	verdictText,
	x86Flags,
} from "./branches";

const ZF = 1 << 6;
const CF = 1 << 0;
const SF = 1 << 7;
const OF = 1 << 11;
const PF = 1 << 2;

describe("x86Flags", () => {
	it("unpacks the bits a branch reads", () => {
		const f = x86Flags(CF | ZF | SF | OF | PF);
		expect(f).toEqual({
			cf: true,
			pf: true,
			zf: true,
			sf: true,
			of: true,
			df: false,
		});
	});

	it("reads a clear flags register as all-clear", () => {
		expect(x86Flags(0)).toEqual({
			cf: false,
			pf: false,
			zf: false,
			sf: false,
			of: false,
			df: false,
		});
	});

	it("reads a missing value as all-clear rather than claiming flags", () => {
		expect(x86Flags(undefined).zf).toBe(false);
		expect(x86Flags(null).zf).toBe(false);
		expect(x86Flags(Number.NaN).zf).toBe(false);
	});
});

describe("testCondition", () => {
	it("tests the single-flag conditions", () => {
		expect(testCondition("Z", x86Flags(ZF), 0)).toBe(true);
		expect(testCondition("Z", x86Flags(0), 0)).toBe(false);
		expect(testCondition("!C", x86Flags(0), 0)).toBe(true);
		expect(testCondition("C || Z", x86Flags(ZF), 0)).toBe(true);
		expect(testCondition("C || Z", x86Flags(CF), 0)).toBe(true);
		expect(testCondition("C || Z", x86Flags(SF), 0)).toBe(false);
	});

	it("tests the signed comparisons, which compare sign with overflow", () => {
		expect(testCondition("S==O", x86Flags(SF | OF), 0)).toBe(true);
		expect(testCondition("S==O", x86Flags(SF), 0)).toBe(false);
		expect(testCondition("S!=O", x86Flags(SF), 0)).toBe(true);
		expect(testCondition("!Z && S==O", x86Flags(SF | OF), 0)).toBe(true);
		expect(testCondition("!Z && S==O", x86Flags(ZF | SF | OF), 0)).toBe(
			false,
		);
		expect(testCondition("Z || S!=O", x86Flags(ZF), 0)).toBe(true);
	});

	it("tests the counter conditions", () => {
		expect(testCondition("!$CX", x86Flags(0), 0)).toBe(true);
		expect(testCondition("!$CX", x86Flags(0), 3)).toBe(false);
		expect(testCondition("$CX", x86Flags(0), 3)).toBe(true);
		expect(testCondition("$CX && Z", x86Flags(ZF), 1)).toBe(true);
		expect(testCondition("$CX && !Z", x86Flags(ZF), 1)).toBe(false);
	});
});

describe("classifyInsn", () => {
	it("reads a conditional jump's condition and target", () => {
		expect(classifyInsn("je 0x7f1980a095e8")).toEqual({
			kind: "conditional",
			mnemonic: "je",
			condition: "Z",
			target: 0x7f1980a095e8,
		});
		expect(classifyInsn("jbe 0x7a8ab0a3f586")?.condition).toBe("C || Z");
		expect(classifyInsn("jl 0x10")?.condition).toBe("S!=O");
	});

	it("treats the aliases as the branch they are", () => {
		expect(classifyInsn("jz 0x1")?.condition).toBe(
			classifyInsn("je 0x1")?.condition,
		);
		expect(classifyInsn("jnz 0x1")?.condition).toBe("!Z");
		expect(classifyInsn("jnae 0x1")?.condition).toBe("C");
		expect(classifyInsn("jng 0x1")?.condition).toBe("Z || S!=O");
	});

	it("reads the loop family off the counter, not the flags", () => {
		expect(classifyInsn("loop 0x1")?.condition).toBe("$CX");
		expect(classifyInsn("loope 0x1")?.condition).toBe("$CX && Z");
		expect(classifyInsn("loopne 0x1")?.condition).toBe("$CX && !Z");
	});

	it("reads a plain jump and a call", () => {
		expect(classifyInsn("jmp 0x401000")).toEqual({
			kind: "jump",
			mnemonic: "jmp",
			condition: null,
			target: 0x401000,
		});
		expect(classifyInsn("call 0x710")?.kind).toBe("call");
		expect(classifyInsn("ret")?.kind).toBe("ret");
	});

	it("has no target for an indirect transfer", () => {
		expect(classifyInsn("call qword ptr [rip+0x3fb6]")?.target).toBeNull();
		expect(classifyInsn("jmp rax")?.target).toBeNull();
	});

	it("ignores trailing whitespace and comments", () => {
		expect(classifyInsn("je 0x80480a0 ; take the equal path")?.target).toBe(
			0x80480a0,
		);
		expect(classifyInsn("  je   0x80480a0  ")?.target).toBe(0x80480a0);
		expect(classifyInsn("jbe 0x1  ; jbe 0xdeadbeef")?.target).toBe(1);
	});

	it("is null for an instruction that does not branch", () => {
		expect(classifyInsn("mov rax, rdx")).toBeNull();
		expect(classifyInsn("test rax, rax")).toBeNull();
		expect(classifyInsn("")).toBeNull();
		expect(classifyInsn("; just a comment")).toBeNull();
	});
});

describe("branchVerdict", () => {
	it("reads a taken back edge off the live flags", () => {
		// `cmp rax, 0x25` with rax below the bound sets carry, and `jbe` is
		// below-or-equal: the loop is still going round.
		const b = classifyInsn("jbe 0x7a8ab0a3f586");
		expect(branchVerdict(b, x86Flags(CF), 0)).toEqual({
			taken: true,
			reason: "C || Z",
		});
		expect(branchVerdict(b, x86Flags(0), 0)?.taken).toBe(false);
	});

	it("reads an untaken branch the same way", () => {
		const b = classifyInsn("je 0x7a8ab0a3f5e8");
		expect(branchVerdict(b, x86Flags(0), 0)).toEqual({
			taken: false,
			reason: "Z",
		});
		expect(branchVerdict(b, x86Flags(ZF), 0)?.taken).toBe(true);
	});

	it("has no verdict for an unconditional transfer", () => {
		expect(
			branchVerdict(classifyInsn("jmp 0x1"), x86Flags(0), 0),
		).toBeNull();
		expect(
			branchVerdict(classifyInsn("call 0x710"), x86Flags(0), 0),
		).toBeNull();
		expect(
			branchVerdict(classifyInsn("mov rax, rdx"), x86Flags(0), 0),
		).toBeNull();
		expect(branchVerdict(null, x86Flags(0), 0)).toBeNull();
	});

	it("counts the loop family down with the counter", () => {
		expect(
			branchVerdict(classifyInsn("loop 0x1"), x86Flags(0), 0)?.taken,
		).toBe(false);
		expect(
			branchVerdict(classifyInsn("loop 0x1"), x86Flags(0), 7)?.taken,
		).toBe(true);
	});
});

describe("verdictText", () => {
	it("negates the condition when it did not hold, so both read alike", () => {
		expect(verdictText({ taken: true, reason: "C || Z" })).toBe(
			"taken [C || Z]",
		);
		expect(verdictText({ taken: false, reason: "C || Z" })).toBe(
			"not taken [!(C || Z)]",
		);
		expect(verdictText({ taken: false, reason: "!Z && S==O" })).toBe(
			"not taken [!(!Z && S==O)]",
		);
	});
});

describe("peekTarget", () => {
	it("peeks where a taken branch is about to land", () => {
		expect(
			peekTarget(classifyInsn("je 0x1"), { taken: true, reason: "Z" }),
		).toBe(1);
	});

	it("peeks nothing for a branch that is not going to be taken", () => {
		expect(
			peekTarget(classifyInsn("je 0x1"), { taken: false, reason: "Z" }),
		).toBeNull();
	});

	it("peeks a direct call's callee", () => {
		expect(peekTarget(classifyInsn("call 0x710"), null)).toBe(0x710);
		expect(
			peekTarget(classifyInsn("call qword ptr [rip+0x3f]"), null),
		).toBeNull();
	});

	it("peeks nothing for a plain jump, a return or no branch", () => {
		expect(peekTarget(classifyInsn("jmp 0x1"), null)).toBeNull();
		expect(peekTarget(classifyInsn("ret"), null)).toBeNull();
		expect(peekTarget(null, null)).toBeNull();
	});
});
