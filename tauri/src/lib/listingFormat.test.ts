import { describe, expect, it } from "vitest";

import {
	annotationKey,
	derivedType,
	fmtAddr,
	RETURN_KEY,
	STORAGE_COLUMN,
	stackStorage,
	TYPE_COLUMN,
	typeFor,
} from "./listingFormat";

const FUNC = 0x401000;

describe("fmtAddr", () => {
	it("pads to eight digits so low addresses read as addresses", () => {
		expect(fmtAddr(0x401000)).toBe("0x00401000");
		expect(fmtAddr(0)).toBe("0x00000000");
	});

	it("leaves a wide address alone rather than truncating it", () => {
		expect(fmtAddr(0xffff_ffff_0000)).toBe("0xffffffff0000");
	});
});

describe("annotationKey", () => {
	it("scopes a datum to the function it belongs to", () => {
		// A frame offset is not an identity on its own: two functions may both
		// use -0x18 for entirely different things.
		expect(annotationKey(FUNC, -24)).toBe(`${FUNC}:-24`);
		expect(annotationKey(FUNC + 0x1000, -24)).toBe(`${FUNC + 0x1000}:-24`);
	});

	it("takes a register and the return marker as readily as an offset", () => {
		expect(annotationKey(FUNC, "rdi")).toBe(`${FUNC}:rdi`);
		expect(annotationKey(FUNC, RETURN_KEY)).toBe(`${FUNC}:${RETURN_KEY}`);
	});
});

describe("derivedType", () => {
	it("says the byte width where the instructions reveal one", () => {
		expect(derivedType(8)).toBe("undefined8");
		expect(derivedType(4)).toBe("undefined4");
		expect(derivedType(2)).toBe("undefined2");
	});

	it("says nothing more where they do not", () => {
		// A byte's width is implied by its access, and a return value or an
		// argument has no single access that reveals one.
		expect(derivedType(1)).toBe("undefined");
		expect(derivedType(0)).toBe("undefined");
	});

	it("still renders when the width is not a width", () => {
		// A NaN would otherwise reach a stylesheet as the text "undefinedNaN".
		expect(derivedType(Number.NaN)).toBe("undefined");
		expect(derivedType(-8)).toBe("undefined");
	});
});

describe("stackStorage", () => {
	it("spells a negative offset as a subtraction", () => {
		expect(stackStorage(-0x28)).toBe("Stack[-0x28]");
		expect(stackStorage(-8)).toBe("Stack[-0x8]");
	});

	it("spells a positive one as an addition", () => {
		expect(stackStorage(0x18)).toBe("Stack[+0x18]");
	});

	it("gives zero a direction rather than a bare 0", () => {
		expect(stackStorage(0)).toBe("Stack[+0x0]");
	});
});

describe("typeFor", () => {
	const types = { [annotationKey(FUNC, RETURN_KEY)]: "int" };

	it("prefers what the analyst typed", () => {
		expect(typeFor(types, FUNC, RETURN_KEY, 0)).toBe("int");
	});

	it("falls back to the derived type for everything unannotated", () => {
		// A different function, and a different datum in this one, are both
		// unannotated — the key is what says so.
		expect(typeFor(types, FUNC + 0x1000, RETURN_KEY, 0)).toBe("undefined");
		expect(typeFor(types, FUNC, -24, 8)).toBe("undefined8");
	});
});

describe("the column widths", () => {
	it("are wide enough for what they hold", () => {
		expect(TYPE_COLUMN).toBeGreaterThanOrEqual("undefined8".length);
		expect(STORAGE_COLUMN).toBeGreaterThanOrEqual("Stack[-0x28]".length);
	});
});
