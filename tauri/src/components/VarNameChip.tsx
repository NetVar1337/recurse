import { useMemo, useRef, useState } from "react";

import { api } from "@/api";
import { cn } from "@/lib/utils";
import { derivedName, frameOf, slotIn, type Frame } from "@/lib/debugVars";
import { useAnalysisStore } from "@/store/analysisStore";
import { useUiStore } from "@/store/uiStore";
import type { DebugInsn } from "@/types";

/** Everything a view needs to show and change one variable's name. */
export interface VarRename {
	/** The name to show when not editing: the analyst's, else the derived one. */
	shown: string;
	/** The name actually set, or undefined if the slot has never been named. */
	named: string | undefined;
	/** Whether the field is open. */
	editing: boolean;
	/** What is in the field while it is open. */
	draft: string;
	/** Record a keystroke. */
	setDraft: (text: string) => void;
	/** Open the field. */
	begin: () => void;
	/** Save and close. */
	commit: () => void;
	/** Abandon and close. */
	cancel: () => void;
	/** Whether the slot names a variable at all. */
	present: boolean;
}

/**
 * Renaming one variable, shared by every view that shows one.
 *
 * A name is keyed by the function's *static* address and the slot's offset, so it
 * is the same name in the debugger, in the function listing and in the graph: a
 * rename here is a rename everywhere, and it survives closing the binary.
 *
 * The write is optimistic and reversible on purpose. The row updates on the
 * keystroke because waiting on the host makes the field feel dead, and a name
 * that silently did not stick is worse than no name at all — so a failed write
 * hands the old one back.
 *
 * @param options.func - The function's static address.
 * @param options.slot - The slot's offset, or null if the operand names none.
 * @param options.names - Every name, keyed by `${function}:${slot}`.
 * @returns The state and handlers for one name.
 */
export function useVarRename({
	func,
	slot,
	names,
}: {
	func: number | null;
	slot: number | null;
	names: Record<string, string>;
}): VarRename {
	const [editing, setEditing] = useState(false);
	const [draft, setDraft] = useState("");
	// Escape closes the field by unmounting it, and a browser may still deliver
	// the blur on its way out — which would save the name that was just backed
	// out of. One flag, set by the cancel and spent by the commit that follows it.
	const abandoned = useRef(false);
	const key = func === null || slot === null ? null : `${func}:${slot}`;
	const named = key === null ? undefined : names[key];
	const shown = named ?? (slot === null ? "" : derivedName(slot));

	// A rename from another view, or from this one's own blur, has to reach the
	// field — but not one the analyst is halfway through typing. Adjusting the
	// draft while rendering is the documented way to derive state from a prop;
	// doing it in an effect would lag a keystroke behind.
	const [shownWhen, setShownWhen] = useState(shown);
	if (shownWhen !== shown) {
		setShownWhen(shown);
		if (!editing) setDraft(shown);
	}

	const commit = () => {
		if (abandoned.current) {
			// The blur that follows an Escape, not a save.
			abandoned.current = false;
			setEditing(false);
			return;
		}
		setEditing(false);
		const next = draft.trim();
		if (!next || next === named || func === null || slot === null) return;
		// Shown first, so the view updates on the keystroke; given back if the
		// write fails, because a name that silently did not stick is worse than
		// no name. Given back as what was there — an unnamed slot is cleared, but
		// a rename of a name the analyst chose is restored to that name, not
		// thrown away.
		const { setVariableName } = useAnalysisStore.getState();
		const previous = named ?? "";
		setVariableName(func, slot, next);
		void api.renameVariable(func, String(slot), next).catch((e) => {
			setVariableName(func, slot, previous);
			// Said out loud. A name that reverts with no explanation is
			// indistinguishable from a name that was never editable, and
			// swallowing the reason leaves nothing to fix it by.
			useUiStore
				.getState()
				.setErr(
					`could not save "${next}" for slot ${slot}: ${
						e instanceof Error ? e.message : String(e)
					}`,
				);
		});
	};

	return {
		shown,
		named,
		editing,
		draft,
		setDraft,
		begin: () => {
			// Seeded, not empty. A field that opens blank gives the analyst
			// nothing to edit: Enter and click-away both mean "keep what I see",
			// and on a blank field both quietly do nothing at all.
			abandoned.current = false;
			setDraft(shown);
			setEditing(true);
		},
		commit,
		cancel: () => {
			abandoned.current = true;
			setEditing(false);
			setDraft(named ?? shown);
		},
		present: key !== null,
	};
}

/**
 * The open field for a variable's name.
 *
 * @param props.rename - The state and handlers for this name.
 * @param props.className - Classes for the field, so a view can size it.
 * @returns The text input.
 */
export function VarNameField({
	rename,
	className,
}: {
	rename: VarRename;
	className?: string;
}) {
	return (
		<input
			autoFocus
			value={rename.draft}
			onChange={(e) => rename.setDraft(e.target.value)}
			// Selected, so typing overwrites the name being replaced instead of
			// appending to it — the field is open to change what is already there.
			onFocus={(e) => e.currentTarget.select()}
			onBlur={rename.commit}
			onKeyDown={(e) => {
				if (e.key === "Enter") e.currentTarget.blur();
				if (e.key === "Escape") {
					// The blur that follows would otherwise save the name the
					// analyst just backed out of.
					e.preventDefault();
					rename.cancel();
				}
			}}
			className={cn(
				"bg-background text-asm-symbol mx-1 w-[14ch] border px-1 py-0 font-mono text-xs",
				className,
			)}
		/>
	);
}

/**
 * The name a view shows for a slot, before or after it has one.
 *
 * @param rename - The state and handlers for this name.
 * @param props.readOnly - Show the name without offering to change it.
 * @returns The name, as a button that opens the field.
 */
export function VarNameButton({
	rename,
	readOnly = false,
}: {
	rename: VarRename;
	readOnly?: boolean;
}) {
	return (
		<button
			className={cn(
				"mx-1 font-mono text-xs",
				rename.named
					? "text-asm-symbol italic"
					: "text-muted-foreground/70",
				!readOnly &&
					"hover:bg-accent/50 hover:text-foreground rounded px-0.5",
			)}
			title={
				readOnly
					? undefined
					: rename.named
						? "Click to rename this variable"
						: "Derived from the slot's offset — click to name it"
			}
			disabled={readOnly}
			onClick={() => !readOnly && rename.begin()}
		>
			{rename.shown}
		</button>
	);
}

/**
 * A variable's name, in the disassembly, beside the operand that touches it.
 *
 * This is where an analyst looks. A slot that appears only as `[rbp - 4]` has no
 * identity to reason about or to click, so every frame reference carries its
 * derived name until it has a real one — muted, to say it is not a fact about the
 * program — and clicking it renames the variable in place, right where it is
 * used, rather than in a panel somewhere else.
 *
 * @param props.func - The function's static address; nothing renders without one.
 * @param props.insns - The function's instructions, which say how it addresses
 *   frames. Ignored when `frame` is given.
 * @param props.frame - The function's frame, when the caller has already worked it
 *   out. Reading it per chip walks the whole function once per row, which is why a
 *   view holding many rows works it out once and passes it in.
 * @param props.text - The instruction this chip belongs to.
 * @param props.readOnly - Show the name without offering to change it.
 */
export function VarNameChip({
	func,
	insns,
	frame,
	text,
	readOnly = false,
}: {
	func: number | null;
	insns?: readonly DebugInsn[];
	frame?: Frame;
	text: string;
	readOnly?: boolean;
}) {
	const names = useAnalysisStore((s) => s.variableNames);
	// A caller that already knows the frame has spared us the walk; otherwise it
	// is worked out here, once, and memoized against the instruction list.
	const ownFrame = useMemo(
		() => (frame ? null : frameOf(insns ?? [])),
		[frame, insns],
	);
	const resolved = frame ?? ownFrame;

	const rename = useVarRename({
		func,
		slot:
			func === null || resolved === null ? null : slotIn(text, resolved),
		names,
	});

	if (!rename.present) return null;
	if (rename.editing) return <VarNameField rename={rename} />;
	return <VarNameButton rename={rename} readOnly={readOnly} />;
}
