import { describe, expect, it } from "vitest";

import {
	SIDEBAR_DEFAULT,
	SIDEBAR_MAX,
	SIDEBAR_MIN,
	sidebarWidth,
} from "./sidebarWidth";

describe("sidebarWidth", () => {
	it("takes a third of the window on an ordinary one", () => {
		expect(sidebarWidth(1200)).toBe(400);
		expect(sidebarWidth(1500)).toBe(500);
	});

	it("stops at the floor when a third would leave too little to read", () => {
		// The code view keeps its 480px whatever the sidebar asks for, so on a
		// narrow window the sidebar hits its own floor first.
		expect(sidebarWidth(600)).toBe(SIDEBAR_MIN);
		expect(sidebarWidth(400)).toBe(SIDEBAR_MIN);
	});

	it("never goes backwards as the window widens", () => {
		// A rule that handed out a *wider* sidebar on a narrower window would
		// shrink the code view the moment the window was resized down.
		let previous = 0;
		for (let w = 400; w <= 3840; w += 40) {
			const width = sidebarWidth(w);
			expect(width).toBeGreaterThanOrEqual(previous);
			previous = width;
		}
	});

	it("stops at the cap however wide the window gets", () => {
		expect(sidebarWidth(3840)).toBe(SIDEBAR_MAX);
	});

	it("never returns a width outside the bounds", () => {
		for (const w of [0, 100, 640, 1024, 2560, 7680]) {
			expect(sidebarWidth(w)).toBeGreaterThanOrEqual(SIDEBAR_MIN);
			expect(sidebarWidth(w)).toBeLessThanOrEqual(SIDEBAR_MAX);
		}
	});

	it("uses the default before the window has been measured", () => {
		expect(sidebarWidth(Number.NaN)).toBe(SIDEBAR_DEFAULT);
		expect(sidebarWidth(-1)).toBe(SIDEBAR_DEFAULT);
	});
});
