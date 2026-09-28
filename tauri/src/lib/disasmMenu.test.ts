import { describe, expect, it, vi } from "vitest";

import { DEFAULT_DISASM_VIEW } from "@/components/DisasmBytes";
import { disasmMenuSections, type DisasmMenuState } from "./disasmMenu";

/**
 * A disassembly holding a function, with every tool idle, which is the state a
 * reader is in most of the time.
 *
 * @param over - What to change about it.
 * @returns The state, and spies for each command so a test can check what ran.
 */
function holding(over: Partial<DisasmMenuState> = {}): {
	state: DisasmMenuState;
	spies: Record<string, ReturnType<typeof vi.fn>>;
} {
	const spies = {
		linear: vi.fn(),
		graph: vi.fn(),
		option: vi.fn(),
		decompile: vi.fn(),
		xrefs: vi.fn(),
		signature: vi.fn(),
		similar: vi.fn(),
		index: vi.fn(),
		reload: vi.fn(),
	};
	return {
		spies,
		state: {
			viewMode: "linear",
			viewOptions: { ...DEFAULT_DISASM_VIEW },
			canDecompile: true,
			decompiling: false,
			xrefsOpen: false,
			toolBusy: false,
			asmLoading: false,
			hasSelection: true,
			onViewModeChange: (mode) => spies[mode](mode),
			onOptionChange: (key, value) => spies.option(key, value),
			onDecompile: spies.decompile,
			onToggleXrefs: spies.xrefs,
			onGenerateSignature: spies.signature,
			onShowSimilar: spies.similar,
			onIndexBinary: spies.index,
			onRefresh: spies.reload,
			...over,
		},
	};
}

/**
 * One item out of a section, by id.
 *
 * @param state - The disassembly's state.
 * @param label - The section's heading.
 * @param id - The item's name.
 * @returns The item.
 */
function item(state: DisasmMenuState, label: string, id: string) {
	const section = disasmMenuSections(state).find((s) => s.label === label);
	if (!section) throw new Error(`no section ${label}`);
	const found = section.items.find((i) => i.id === id);
	if (!found) throw new Error(`no item ${id}`);
	return found;
}

describe("the disassembly's menus", () => {
	it("are how it is drawn, what of it is drawn, then what to do with it", () => {
		expect(disasmMenuSections(holding().state).map((s) => s.label)).toEqual(
			["Disassembly", "Output filters", "Actions"],
		);
	});

	it("tick the view it is showing", () => {
		const { state } = holding();
		expect(item(state, "Disassembly", "view-linear").checked).toBe(true);
		expect(item(state, "Disassembly", "view-graph").checked).toBe(false);
	});

	it("switch the view when picked", () => {
		const { state, spies } = holding();
		item(state, "Disassembly", "view-graph").run();
		expect(spies.graph).toHaveBeenCalledWith("graph");
	});

	it("tick the columns that are on, and flip only the one picked", () => {
		const { state, spies } = holding({
			viewOptions: { ...DEFAULT_DISASM_VIEW, showAscii: false },
		});
		expect(item(state, "Output filters", "filter-showAscii").checked).toBe(
			false,
		);
		expect(
			item(state, "Output filters", "filter-showComments").checked,
		).toBe(true);
		item(state, "Output filters", "filter-showAscii").run();
		expect(spies.option).toHaveBeenCalledWith("showAscii", true);
	});

	describe("the actions", () => {
		it("are offered once there is a function to act on", () => {
			const { state } = holding();
			for (const id of ["decompile", "xrefs", "signature", "similar"]) {
				expect(item(state, "Actions", id).disabled, id).toBe(false);
			}
		});

		it("say why they are unavailable rather than disappearing", () => {
			// A command that vanishes between two visits is one nobody waits for;
			// a greyed one that says "Decompile" tells the reader what is missing.
			const { state } = holding({
				hasSelection: false,
				canDecompile: false,
				toolBusy: true,
			});
			expect(item(state, "Actions", "decompile").disabled).toBe(true);
			expect(item(state, "Actions", "signature").disabled).toBe(true);
			// Indexing writes to the corpus, so it waits for the tool that is already
			// writing to it rather than running two at once.
			expect(item(state, "Actions", "index").disabled).toBe(true);
			// Reloading is only ever about the listing, so a busy tool is no reason
			// to stop the reader seeing the code again.
			expect(item(state, "Actions", "reload").disabled).toBe(false);
		});

		it("name the work in progress instead of offering to start it twice", () => {
			const { state } = holding({ decompiling: true, asmLoading: true });
			expect(item(state, "Actions", "decompile")).toMatchObject({
				label: "Decompiling…",
				disabled: true,
			});
			expect(item(state, "Actions", "reload")).toMatchObject({
				label: "Reloading…",
				disabled: true,
			});
		});

		it("offer to hide the xrefs that are open", () => {
			expect(item(holding().state, "Actions", "xrefs").label).toBe(
				"Show xrefs",
			);
			expect(
				item(holding({ xrefsOpen: true }).state, "Actions", "xrefs")
					.label,
			).toBe("Hide xrefs");
		});

		it("run what the panel registered, not a copy of it", () => {
			const { state, spies } = holding();
			item(state, "Actions", "signature").run();
			item(state, "Actions", "index").run();
			expect(spies.signature).toHaveBeenCalledOnce();
			expect(spies.index).toHaveBeenCalledOnce();
		});
	});
});
