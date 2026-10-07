import { useMemo } from "react";

import { api } from "@/api";
import { cn } from "@/lib/utils";
import { derivedName, frameOf, slotIn, type Frame } from "@/lib/debugVars";
import { annotationKey } from "@/lib/listingFormat";
import {
	AnnotationButton,
	AnnotationField,
	useAnnotationEdit,
	type AnnotationEdit,
} from "@/components/AnnotationEdit";
import { useAnalysisStore } from "@/store/analysisStore";
import { useUiStore } from "@/store/uiStore";
import type { DebugInsn } from "@/types";

/**
 * Everything a view needs to show and change one variable's name. The same
 * shape as any other annotation, under the name the disassembly views already
 * speak.
 */
export type VarRename = AnnotationEdit;

/**
 * Renaming one variable, shared by every view that shows one.
 *
 * A name is keyed by the function's *static* address and the datum's own key, so
 * it is the same name in the debugger, in the function listing, in the graph and
 * in the variables panel: a rename here is a rename everywhere, and it survives
 * closing the binary.
 *
 * The write is optimistic and reversible on purpose. The row updates on the
 * keystroke because waiting on the host makes the field feel dead, and a name
 * that silently did not stick is worse than no name at all — so a failed write
 * hands the old one back.
 *
 * @param options.func - The function's static address.
 * @param options.datum - The datum's own key: a frame offset for a local, a
 *   register for an argument. Null when the view has nothing to name.
 * @param options.fallback - The name to show until there is one. Defaults to
 *   the derived name, which only a frame offset can produce.
 * @param options.names - Every name, keyed by {@link annotationKey}.
 * @returns The state and handlers for one name.
 */
export function useVarRename({
	func,
	datum,
	fallback,
	names,
}: {
	func: number | null;
	datum: string | number | null;
	fallback?: string;
	names: Record<string, string>;
}): VarRename {
	const value =
		func === null || datum === null
			? undefined
			: names[annotationKey(func, datum)];
	const shown =
		value ??
		fallback ??
		(typeof datum === "number" ? derivedName(datum) : (datum ?? ""));

	return useAnnotationEdit({
		shown,
		value,
		persist: (next) => {
			if (func === null || datum === null) return;
			// Shown first, so the view updates on the keystroke; given back if the
			// write fails. Given back as what was there — an unnamed slot is
			// cleared, but a rename of a name the analyst chose is restored to that
			// name, not thrown away.
			const previous = value ?? "";
			useAnalysisStore
				.getState()
				.setVariableName(func, datum, next ?? "");
			void api
				.renameVariable(func, String(datum), next ?? "")
				.catch((e) => {
					useAnalysisStore
						.getState()
						.setVariableName(func, datum, previous);
					// Said out loud. A name that reverts with no explanation is
					// indistinguishable from a name that was never editable, and
					// swallowing the reason leaves nothing to fix it by.
					useUiStore
						.getState()
						.setErr(
							`could not save "${next}" for ${datum}: ${
								e instanceof Error ? e.message : String(e)
							}`,
						);
				});
		},
	});
}

/** The open field for a variable's name, at the app's usual scale. */
export function VarNameField({
	rename,
	className,
}: {
	rename: VarRename;
	className?: string;
}) {
	return (
		<AnnotationField
			edit={rename}
			className={cn("text-asm-symbol w-[14ch]", className)}
		/>
	);
}

/**
 * The name a view shows for a datum, before or after it has one.
 *
 * @param rename - The state and handlers for this name.
 * @param props.readOnly - Show the name without offering to change it.
 * @returns The name, as a button that opens the field.
 */
export function VarNameButton({
	rename,
	readOnly = false,
	className,
}: {
	rename: VarRename;
	readOnly?: boolean;
	className?: string;
}) {
	if (readOnly) {
		return (
			<span className={cn("mx-1 font-mono text-xs", className)}>
				{rename.shown}
			</span>
		);
	}
	return <AnnotationButton edit={rename} className={className} />;
}

/**
 * A datum's name, editable in place, at the listing's type scale.
 *
 * The counterpart of `TypeCell`: it reads the name record itself so a header
 * row can name a variable without subscribing to the store, which is what
 * keeps a rename from re-rendering every row of the listing around it.
 *
 * @param props.func - The function's static address.
 * @param props.datum - The datum: a frame offset, a register, or `RETURN_KEY`.
 * @param props.fallback - The name to show until the analyst gives it one.
 * @param props.className - Classes for the cell.
 * @returns The name, as a field when open and a button when not.
 */
export function NameCell({
	func,
	datum,
	fallback,
	className,
}: {
	func: number;
	datum: string | number;
	fallback: string;
	className?: string;
}) {
	const names = useAnalysisStore((s) => s.variableNames);
	const rename = useVarRename({ func, datum, fallback, names });
	if (rename.editing) {
		return (
			<VarNameField
				rename={rename}
				className={cn("mx-0 text-[11px]", className)}
			/>
		);
	}
	return <VarNameButton rename={rename} className={className} />;
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
		datum:
			func === null || resolved === null ? null : slotIn(text, resolved),
		names,
	});

	if (rename.shown === "") return null;
	if (rename.editing) return <VarNameField rename={rename} />;
	return <VarNameButton rename={rename} readOnly={readOnly} />;
}
