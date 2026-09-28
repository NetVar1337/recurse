import { beforeEach, describe, expect, it, vi } from "vitest";

import {
	clearSections,
	groupSections,
	publishSections,
	readSections,
	sectionsFor,
	type MenuCommand,
	type MenuItem,
} from "./menuRegistry";

/**
 * A command in the shape the shared list produces, with the parts a test cares
 * about spelled out.
 *
 * @param over - What to change about it.
 * @returns A command, defaulting to one that is already runnable.
 */
function command(over: Partial<MenuCommand> = {}): MenuCommand {
	return {
		id: "one",
		title: "One",
		menu: "File",
		section: "Binary",
		run: vi.fn(),
		...over,
	};
}

describe("the published sections", () => {
	beforeEach(() => {
		clearSections();
	});

	/**
	 * A section to publish, with its parts spelled out.
	 *
	 * @param label - The heading.
	 * @param id - The one item's name.
	 * @returns A section.
	 */
	const section = (label: string, id = "a") => ({
		label,
		items: [{ id, label: id.toUpperCase(), run: vi.fn() }],
	});

	it("are what the panel said, in the order it said them", () => {
		publishSections("View", [section("Disassembly", "linear")]);
		expect(readSections("View")).toHaveLength(1);
		expect(readSections("View")[0].label).toBe("Disassembly");
	});

	it("belong to the one menu they were published to, and no other", () => {
		// A disassembly offering "Decompile" has said so about View. Published as a
		// bare list and read by every menu, the same section turned up under File
		// and Go too, so three menus all listed a panel's sections.
		publishSections("View", [section("Actions", "decompile")]);
		expect(readSections("Go")).toEqual([]);
		expect(readSections("File")).toEqual([]);
	});

	it("are replaced rather than added to", () => {
		// A panel that republishes on every render would otherwise grow the menu by
		// one copy of itself per render, and nobody would see why the View menu had
		// four identical entries.
		publishSections("View", [section("Actions", "a")]);
		publishSections("View", [section("Actions", "b")]);
		expect(readSections("View")[0].items.map((i) => i.id)).toEqual(["b"]);
	});

	it("are withdrawn when the panel that published them goes", () => {
		publishSections("View", [section("Actions")]);
		clearSections();
		expect(readSections("View")).toEqual([]);
	});
});

describe("sectionsFor", () => {
	it("groups a menu's commands under the heading each one names", () => {
		const sections = sectionsFor(
			"View",
			[
				command({
					id: "chat",
					title: "Toggle chat",
					menu: "View",
					section: "Appearance",
				}),
				command({
					id: "theme",
					title: "Dark",
					menu: "View",
					section: "Appearance",
				}),
				command({
					id: "r2",
					title: "Engine: r2",
					menu: "View",
					section: "Engine",
				}),
				command({ id: "open", title: "Open binary…", menu: "File" }),
			],
			[],
		);
		expect(sections.map((s) => s.label)).toEqual(["Appearance", "Engine"]);
		expect(sections[0].items.map((i) => i.label)).toEqual([
			"Toggle chat",
			"Dark",
		]);
	});

	it("renames a command to the menu's own wording and keeps its shortcut", () => {
		const [section] = sectionsFor(
			"File",
			[command({ title: "Open binary…", hint: "Ctrl+O" })],
			[],
		);
		expect(section.items[0]).toMatchObject({
			label: "Open binary…",
			hint: "Ctrl+O",
		});
	});

	it("carries a command's ticked state into the menu, so a menu can answer which", () => {
		// The engine in force is asked about more often than it is changed, and it
		// cannot be answered by a highlighted row the way the header's dropdown
		// answered it: a tick says it without anyone having to compare two lines.
		const [section] = sectionsFor(
			"View",
			[
				command({ id: "native", menu: "View", checked: true }),
				command({ id: "r2", menu: "View", checked: false }),
			],
			[],
		);
		expect(section.items.map((i) => i.checked)).toEqual([true, false]);
	});

	it("leaves an unticked command unticked rather than claiming it is off", () => {
		// `checked: false` and no `checked` mean different things to a screen
		// reader: one is a state, the other is a command that does a thing.
		const [section] = sectionsFor("File", [command()], []);
		expect(section.items[0]).not.toHaveProperty("checked");
	});

	it("keeps a menu free of another menu's sections", () => {
		// The whole point of publishing per menu: Go lists panels, and a disassembly
		// section under it would be a section of a menu the reader did not open.
		publishSections("View", [
			{
				label: "Actions",
				items: [{ id: "d", label: "Decompile", run: vi.fn() }],
			},
		]);
		const go = sectionsFor(
			"Go",
			[command({ menu: "Go" })],
			readSections("Go"),
		);
		expect(go.flatMap((s) => s.items).map((i) => i.id)).not.toContain("d");
	});

	it("puts a panel's sections last, so the window's own commands come first", () => {
		// A reader who opened View to change the theme should not have it below
		// eight checkboxes about a column they did not know they were hiding.
		const sections = sectionsFor(
			"View",
			[command({ menu: "View", section: "Appearance" })],
			[
				{
					label: "Actions",
					items: [
						{ id: "decompile", label: "Decompile", run: vi.fn() },
					],
				},
			],
		);
		expect(sections.map((s) => s.label)).toEqual(["Appearance", "Actions"]);
	});
});

describe("groupSections", () => {
	/**
	 * The shape of a rendered row, so a test reads as the menu reads.
	 *
	 * @param rows - What the layout produced.
	 * @returns One word per row.
	 */
	const shape = (rows: ReturnType<typeof groupSections>): string[] =>
		rows.map((row) =>
			row.kind === "item"
				? row.item.label
				: row.kind === "rule"
					? "—"
					: row.label,
		);

	it("puts a heading above its items and a rule under it", () => {
		expect(
			shape(
				groupSections([
					{
						label: "Actions",
						items: [
							{ id: "a", label: "One", run: vi.fn() },
							{ id: "b", label: "Two", run: vi.fn() },
						],
					},
				]),
			),
		).toEqual(["Actions", "—", "One", "Two"]);
	});

	it("rules between two headed groups, without doubling the rule", () => {
		const rows = shape(
			groupSections([
				{
					label: "One",
					items: [{ id: "a", label: "a", run: vi.fn() }],
				},
				{
					label: "Two",
					items: [{ id: "b", label: "b", run: vi.fn() }],
				},
			]),
		);
		expect(rows).toEqual(["One", "—", "a", "Two", "—", "b"]);
	});

	it("carries each item through untouched", () => {
		const item: MenuItem = {
			id: "a",
			label: "A",
			run: vi.fn(),
			hint: "F9",
		};
		const [row] = groupSections([{ label: "", items: [item] }]);
		expect(row).toEqual({ kind: "item", item });
	});

	it("says nothing for no sections, so a menu with nothing in it can say so", () => {
		expect(groupSections([])).toEqual([]);
	});
});
