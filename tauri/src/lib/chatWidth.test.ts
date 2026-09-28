import { describe, expect, it } from "vitest";

import { CHAT_DEFAULT, chatWidth } from "./chatWidth";

describe("chatWidth", () => {
	it("opens at the default on a window that can afford it", () => {
		expect(chatWidth(1920)).toBe(CHAT_DEFAULT);
		expect(chatWidth(1400)).toBe(CHAT_DEFAULT);
	});

	it("gives way on a window that cannot, rather than the code view", () => {
		// A sidebar and a centre are already spoken for; the chat is the one that
		// is optional, so it is the one that yields.
		expect(chatWidth(1000)).toBeLessThan(CHAT_DEFAULT);
		expect(chatWidth(700)).toBe(220);
	});

	it("never returns a width nothing can use", () => {
		expect(chatWidth(400)).toBe(220);
	});

	it("uses the default before the window has been measured", () => {
		expect(chatWidth(Number.NaN)).toBe(CHAT_DEFAULT);
		expect(chatWidth(0)).toBe(CHAT_DEFAULT);
	});
});
