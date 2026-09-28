import { describe, expect, it } from "vitest";

import { CHAT_DEFAULT, CHAT_MAX, chatWidth } from "./chatWidth";
import { CENTRE_MIN, COLUMNS, fitColumn, readColumn } from "./resizableColumn";
import { SIDEBAR_MAX, sidebarWidth } from "./sidebarWidth";

const SIDEBAR = { min: 220, max: 640 };
const CHAT = { min: 280, max: 720 };

describe("fitColumn", () => {
	it("keeps a width that the window can afford", () => {
		expect(fitColumn(400, { ...SIDEBAR, windowWidth: 1600 })).toBe(400);
		expect(fitColumn(400, { ...CHAT, windowWidth: 1600 })).toBe(400);
	});

	it("stops a column at its own ceiling", () => {
		expect(fitColumn(5000, { ...SIDEBAR, windowWidth: 4000 })).toBe(640);
		expect(fitColumn(5000, { ...CHAT, windowWidth: 4000 })).toBe(720);
	});

	it("stops a column at its own floor", () => {
		expect(fitColumn(10, { ...SIDEBAR, windowWidth: 4000 })).toBe(220);
		expect(fitColumn(10, { ...CHAT, windowWidth: 4000 })).toBe(280);
	});

	it("yields to the centre before it yields to its own floor", () => {
		// The panel in the middle keeps its floor, so on a narrow window it is
		// the column that is reduced — the centre is the one being read.
		const windowWidth = 900;
		const width = fitColumn(640, { ...SIDEBAR, windowWidth });
		expect(width).toBe(windowWidth - CENTRE_MIN);
		expect(windowWidth - width).toBe(CENTRE_MIN);
	});

	it("prefers the column's own floor when the window cannot afford the centre", () => {
		// Too narrow for both: the column stops at its floor rather than
		// collapsing, and the centre is squeezed — a window this narrow has no
		// arrangement that gives everything room.
		expect(fitColumn(640, { ...SIDEBAR, windowWidth: 500 })).toBe(220);
	});

	it("rounds to whole pixels", () => {
		expect(fitColumn(400.6, { ...CHAT, windowWidth: 1600 })).toBe(401);
	});

	it("falls back to the floor for a width it cannot use", () => {
		expect(fitColumn(Number.NaN, { ...SIDEBAR, windowWidth: 1600 })).toBe(
			220,
		);
		expect(fitColumn(400, { ...SIDEBAR, windowWidth: Number.NaN })).toBe(
			220,
		);
	});

	it("holds for both columns at once on the same window", () => {
		// The two are dragged independently but share one window, and the centre
		// between them has one floor between them. Dragged to their maxima on a
		// 1600px window, neither may take what the other is holding.
		const windowWidth = 1600;
		const chatFirst = fitColumn(720, { ...CHAT, windowWidth });
		const sidebarAfter = fitColumn(640, {
			...SIDEBAR,
			windowWidth,
			reserved: chatFirst,
		});
		expect(chatFirst + sidebarAfter + CENTRE_MIN).toBeLessThanOrEqual(
			windowWidth,
		);
		// 640 + 720 + 480 is 1840, so the sidebar has to give way.
		expect(sidebarAfter).toBeLessThan(SIDEBAR.max);
	});
});

describe("readColumn", () => {
	/**
	 * A stub that has only the one method the reading needs, because what is being
	 * checked is the arithmetic around it and not the DOM.
	 *
	 * @param variables - What the grid is holding, as a CSS variable name and a width.
	 * @returns A stand-in for a grid element.
	 */
	function gridWith(variables: Record<string, string>) {
		return {
			style: {
				getPropertyValue: (name: string) => variables[name] ?? "",
			},
		} as unknown as HTMLDivElement;
	}

	it("reports what the column is holding", () => {
		// The width the drag wrote, not the one React last committed: a drag in
		// progress has moved the column without a render having happened yet.
		expect(
			readColumn(gridWith({ "--recurse-chat": "512px" }), "chat", 1600),
		).toBe(512);
	});

	it("reports the opening width of a column that was never sized", () => {
		// The sidebar is laid out before the chat exists, and has to answer for
		// the chat all the same — the opening width is the honest guess, where
		// zero would mean "this costs nothing", which is not true of either column.
		expect(readColumn(gridWith({}), "chat", 1920)).toBe(chatWidth(1920));
		expect(readColumn(gridWith({}), "sidebar", 1920)).toBe(
			sidebarWidth(1920),
		);
	});

	it("reports the opening width before the grid is mounted at all", () => {
		expect(readColumn(null, "chat", 1920)).toBe(CHAT_DEFAULT);
	});

	it("ignores a width that was never written, or was written as nothing", () => {
		for (const held of ["", "auto", "0", "0px", "nonsense"]) {
			expect(
				readColumn(gridWith({ "--recurse-chat": held }), "chat", 1920),
			).toBe(CHAT_DEFAULT);
		}
	});
});

describe("the columns in COLUMNS", () => {
	it("each know the other, so the centre's floor is charged once between them", () => {
		// A column that cannot name its sibling reserves nothing, and two such
		// columns can both sit at their maximum and squeeze the centre anyway:
		// 640 + 720 leaves 240px of a 1600px window.
		for (const spec of Object.values(COLUMNS)) {
			expect(spec.sibling, `${spec.key} knows no sibling`).toBeTruthy();
			expect(
				COLUMNS[spec.sibling as string],
				`${spec.sibling} is not a column`,
			).toBeTruthy();
		}
	});

	it("keep the window's floor honoured by both sides of the centre", () => {
		const windowWidth = 1600;
		const sidebar = fitColumn(SIDEBAR_MAX, {
			min: COLUMNS.sidebar.min,
			max: COLUMNS.sidebar.max,
			windowWidth,
			reserved: 0,
		});
		const chat = fitColumn(CHAT_MAX, {
			min: COLUMNS.chat.min,
			max: COLUMNS.chat.max,
			windowWidth,
			reserved: sidebar,
		});
		expect(windowWidth - sidebar - chat).toBeGreaterThanOrEqual(CENTRE_MIN);
	});
});
