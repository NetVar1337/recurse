import { describe, expect, it } from "vitest";

import { splitComment } from "./disasm";

describe("splitComment", () => {
	it("splits an instruction from its string comment", () => {
		expect(splitComment('mov edi, 0x4007d4 ; "Hello ! "')).toEqual({
			instr: "mov edi, 0x4007d4",
			comment: '"Hello ! "',
		});
	});

	it("splits a symbol/GOT comment", () => {
		expect(splitComment("call 0x400520 ; imp.puts")).toEqual({
			instr: "call 0x400520",
			comment: "imp.puts",
		});
	});

	it("returns the whole line when there is no comment", () => {
		expect(splitComment("push rbp")).toEqual({
			instr: "push rbp",
			comment: "",
		});
	});
});
