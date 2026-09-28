import { beforeEach, describe, expect, it } from "vitest";

import { buildCommands, MENU, MENU_ORDER } from "./commands";
import {
	clearSections,
	publishSections,
	readSections,
	sectionsFor,
} from "./menuRegistry";

describe("the menus", () => {
	beforeEach(() => {
		clearSections();
	});

	/**
	 * The commands a menu holds, from the app's own list and whatever a panel has
	 * published to it.
	 *
	 * @param menu - The menu to build.
	 * @returns Its item names, in order.
	 */
	const itemsOf = (menu: string): string[] =>
		sectionsFor(menu, buildCommands(), readSections(menu))
			.flatMap((section) => section.items)
			.map((item) => item.id);

	it("name a menu that exists", () => {
		// A command filed under a menu name nothing renders is a command that has
		// quietly disappeared, and a typo is the only thing that would do it.
		for (const command of buildCommands()) {
			expect(MENU_ORDER, command.id).toContain(command.menu);
		}
	});

	it("put an option in one menu, not several", () => {
		const homes = new Map<string, Set<string>>();
		for (const command of buildCommands()) {
			const seen = homes.get(command.id) ?? new Set<string>();
			seen.add(command.menu);
			homes.set(command.id, seen);
		}
		for (const [id, menus] of homes) {
			expect([...menus], id).toHaveLength(1);
		}
	});

	it("keep the settings where a reader looks for them by name", () => {
		const settings = itemsOf(MENU.settings);
		expect(settings).toContain("model-picker");
		expect(settings).toContain("debugger-settings");
	});

	it("do not file a setting under File as well", () => {
		// Having to know that the debugger's settings live under File ▸ Settings is
		// the kind of thing you only know once.
		expect(itemsOf(MENU.file)).not.toContain("debugger-settings");
		expect(itemsOf(MENU.file)).not.toContain("model-picker");
	});

	it("put the analysis engine under Settings, not under View", () => {
		// An engine is a choice about how the work is done, not a switch that changes
		// what is on screen, so it belongs with the other settings.
		expect(itemsOf(MENU.settings)).toContain("engine-native");
		expect(itemsOf(MENU.view)).not.toContain("engine-native");
	});

	it("leave a panel's sections to the one menu that asked for them", () => {
		publishSections(MENU.view, [
			{
				label: "Actions",
				items: [{ id: "decompile", label: "Decompile", run: () => {} }],
			},
		]);
		for (const menu of MENU_ORDER) {
			expect(itemsOf(menu).includes("decompile"), menu).toBe(
				menu === MENU.view,
			);
		}
	});
});
