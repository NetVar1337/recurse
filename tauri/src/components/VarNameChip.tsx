import { useMemo, useState } from "react";

import { api } from "@/api";
import { cn } from "@/lib/utils";
import { derivedName, frameOf, slotIn } from "@/lib/debugVars";
import { useAnalysisStore } from "@/store/analysisStore";
import type { DebugInsn } from "@/types";

/**
 * A variable's name, in the disassembly, beside the operand that touches it.
 *
 * This is where an analyst looks. A slot that appears only as `[rbp - 4]` has no
 * identity to reason about or to click, so every frame reference carries its
 * derived name until it has a real one — muted, to say it is not a fact about
 * the program — and clicking it renames the variable in place, right where it is
 * used, rather than in a panel somewhere else.
 *
 * The name is keyed by the function's *static* address, so it is the same name in
 * the debugger, in the function listing and in the graph: a rename here is a
 * rename everywhere, and it survives closing the binary.
 *
 * @param func - The function's static address; nothing renders without one.
 * @param insns - The function's instructions, which say how it addresses frames.
 * @param text - The instruction this chip belongs to.
 */
export function VarNameChip({
	func,
	insns,
	text,
	readOnly = false,
}: {
	func: number | null;
	insns: readonly DebugInsn[] | undefined;
	text: string;
	/** Show the name without offering to change it. */
	readOnly?: boolean;
}) {
	const names = useAnalysisStore((s) => s.variableNames);
	const setVariableName = useAnalysisStore((s) => s.setVariableName);
	const [editing, setEditing] = useState(false);
	const [draft, setDraft] = useState("");
	const frame = useMemo(() => frameOf(insns ?? []), [insns]);
	const slot = func === null ? null : slotIn(text, frame);
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

	if (key === null) return null;

	if (editing) {
		return (
			<input
				autoFocus
				value={draft}
				onChange={(e) => setDraft(e.target.value)}
				onBlur={() => {
					setEditing(false);
					const next = draft.trim();
					if (!next || next === named) return;
					// Shown first, so the row updates on the keystroke; given back if
					// the write fails, because a name that silently did not stick is
					// worse than no name.
					setVariableName(func!, slot!, next);
					void api
						.renameVariable(func!, String(slot), next)
						.catch(() => setVariableName(func!, slot!, ""));
				}}
				onKeyDown={(e) => {
					if (e.key === "Enter") e.currentTarget.blur();
					if (e.key === "Escape") {
						setEditing(false);
						setDraft(named ?? shown);
					}
				}}
				className="bg-background text-asm-symbol mx-1 w-[14ch] border px-1 py-0 font-mono text-xs"
			/>
		);
	}

	return (
		<button
			className={cn(
				"mx-1 font-mono text-xs",
				named ? "text-asm-symbol italic" : "text-muted-foreground/70",
				!readOnly &&
					"hover:bg-accent/50 hover:text-foreground rounded px-0.5",
			)}
			title={
				readOnly
					? undefined
					: named
						? "Click to rename this variable"
						: "Derived from the slot's offset — click to name it"
			}
			disabled={readOnly}
			onClick={() => !readOnly && setEditing(true)}
		>
			{shown}
		</button>
	);
}
