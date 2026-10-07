import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import {
	beginDragSuppressSelect,
	dragSelectClass,
	endDragSuppressSelect,
} from "./dragSelect";

describe("dragSelectClass", () => {
	it("names a class per axis, because the cursor differs", () => {
		expect(dragSelectClass("col")).toBe("dragging-suppress-select");
		expect(dragSelectClass("row")).toBe("dragging-suppress-select-row");
	});
});

describe("the suppression rules", () => {
	const css = readFileSync("src/chrome.css", "utf8");

	/**
	 * A class name that no rule matches suppresses nothing, and the drag goes on
	 * selecting every name it passes over — so the names and the stylesheet are
	 * checked against each other rather than trusted.
	 */
	it("are in the stylesheet for both axes", () => {
		for (const axis of ["col", "row"] as const) {
			expect(css).toContain(`body.${dragSelectClass(axis)}`);
		}
		expect(css).toMatch(
			/body\.dragging-suppress-select\s*\{[^}]*user-select:\s*none/,
		);
		expect(css).toMatch(
			/body\.dragging-suppress-select-row\s*\{[^}]*user-select:\s*none/,
		);
	});
});

describe("the divider highlight", () => {
	const css = readFileSync("src/chrome.css", "utf8");

	/**
	 * The handle is a 4px grab area and the line inside it is 1px. Filling the
	 * whole handle on hover — which is what it used to do — paints a band down
	 * the window and reads as a border the layout gained rather than as the edge
	 * that is draggable.
	 */
	it("is one pixel, whichever way the divider runs", () => {
		expect(css).toMatch(/\.ui-col-divider::after\s*\{[^}]*width:\s*1px/);
		expect(css).toMatch(/\.ui-row-divider::after\s*\{[^}]*height:\s*1px/);
	});

	it("leaves the handle transparent until it is used", () => {
		expect(css).toMatch(
			/\.ui-col-divider,\s*\.ui-row-divider\s*\{[^}]*background:\s*transparent/,
		);
		// Hover, keyboard focus and a drag in progress are the three states in
		// which the line is lit; the drag one matters because the pointer leaves
		// the handle continuously.
		const lit = [
			".ui-col-divider:hover::after",
			".ui-col-divider:focus-visible::after",
			".ui-col-divider[data-dragging]::after",
			".ui-row-divider:hover::after",
			".ui-row-divider:focus-visible::after",
			".ui-row-divider[data-dragging]::after",
		];
		for (const rule of lit) expect(css).toContain(rule);
	});
});

describe("in an environment with no document", () => {
	it("does not throw when a drag starts or ends", () => {
		// The node test environment has no `document`, and a component that
		// suppressed selection must still mount and drag in one.
		expect(() => beginDragSuppressSelect("col")).not.toThrow();
		expect(() => endDragSuppressSelect("row")).not.toThrow();
	});
});
