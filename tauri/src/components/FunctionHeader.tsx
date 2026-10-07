import { useEffect, useState, type ReactNode } from "react";

import { api } from "@/api";
import {
	argsOf,
	defaultVarName,
	frameOf,
	localsOf,
	type ArgVar,
	type Frame,
	type LocalVar,
} from "@/lib/debugVars";
import {
	annotationKey,
	fmtAddr,
	RETURN_KEY,
	STORAGE_COLUMN,
	stackStorage,
	TYPE_COLUMN,
} from "@/lib/listingFormat";
import { NameCell } from "@/components/VarNameChip";
import { TypeCell } from "@/components/TypeTag";
import { useAnalysisStore } from "@/store/analysisStore";
import type { DebugInsn, Function, Xref } from "@/types";

/** A function's derived storage: what it reads for arguments and what it names
 * on the stack. Computed once per function and cached, since it needs the
 * function's instructions and a header is re-rendered as the view scrolls. */
interface HeaderInfo {
	args: ArgVar[];
	locals: LocalVar[];
	frame: Frame;
	xrefs: Xref[];
}

const headerInfoCache = new Map<number, HeaderInfo>();

/**
 * Forget every cached header.
 *
 * The cache is keyed by address alone, which identifies a function only within
 * one target: open a second binary and `0x401000` means something else, so a
 * header carried across would describe the wrong function's arguments. Nothing
 * in an address says which binary it came from, so the whole cache goes.
 */
export function clearHeaderInfoCache(): void {
	headerInfoCache.clear();
}

/**
 * Ghidra's function banner: a boxed `FUNCTION` line, prefixed with the `;`
 * comment marker the listing uses for comments.
 *
 * @param width - Width of the box's star rules.
 * @returns The three comment lines, top rule first.
 *
 * @example
 * functionBanner(12);
 * // => ["; ************", "; * FUNCTION *", "; ************"]
 */
function functionBanner(width = 60): [string, string, string] {
	const stars = "*".repeat(width);
	const label = "FUNCTION";
	const inner = width - 2;
	const left = Math.floor((inner - label.length) / 2);
	const right = inner - label.length - left;
	return [
		`; ${stars}`,
		`; *${" ".repeat(left)}${label}${" ".repeat(right)}*`,
		`; ${stars}`,
	];
}

/**
 * Classes for a header cell that fills its column.
 *
 * The shared annotation controls carry a margin and a padding of their own, for
 * the views that hand them a bare text run. Inside a column of a fixed width
 * both shift the text, and the storage column would no longer start where the
 * header says it does — so the cell cancels them and fills the column instead,
 * leaving the inset to the column's own padding.
 */
const CELL = "mx-0 w-full px-0 text-left";

/**
 * One row of the function header: the type, the storage, then the name.
 *
 * Real cells rather than one padded string, because the first and the third of
 * them are editable and a string cannot hold a field. The widths are the same
 * character counts the padding used, so the columns land where they did.
 *
 * @param props.type - The type cell, or text for a derived one.
 * @param props.storage - Where the datum lives: a register, a stack slot, or a
 *   marker. Never editable — it is what the instructions say, not a choice.
 * @param props.name - The name cell, or a marker.
 * @returns The row element.
 */
function HeaderRow({
	type,
	storage,
	name,
}: {
	type: ReactNode;
	storage: string;
	name: ReactNode;
}) {
	return (
		<div className="text-muted-foreground flex">
			<span
				className="shrink-0 px-1"
				style={{ width: `${TYPE_COLUMN}ch` }}
			>
				{type}
			</span>
			<span
				className="shrink-0 px-1"
				style={{ width: `${STORAGE_COLUMN}ch` }}
			>
				{storage}
			</span>
			<span className="min-w-0 px-1">{name}</span>
		</div>
	);
}

/**
 * The header's signature line: the function's name, and what it returns.
 *
 * Its own component, and the only part of the header that subscribes to the
 * return type, so annotating a type re-renders this line rather than every row
 * of the header around it. Clicking navigates, as before.
 *
 * @param props.func - The function whose entry this header introduces.
 * @param props.onGoTo - Called to navigate to the function.
 * @returns The signature line.
 */
function Signature({
	func,
	onGoTo,
}: {
	func: Function;
	onGoTo?: (f: Function) => void;
}) {
	const types = useAnalysisStore((s) => s.variableTypes);
	// A return type the analyst has given is the later word on the subject, so
	// it stands in for the signature the backend recovered; without one, that
	// signature is better than anything synthesised here.
	const returns = types[annotationKey(func.addr, RETURN_KEY)];
	const signature = returns
		? `${returns} ${func.name ?? "function"}()`
		: (func.signature ?? `undefined ${func.name ?? "function"}()`);

	return (
		<button
			type="button"
			title="Go to this function"
			className="text-asm-symbol block w-full text-center hover:underline"
			onClick={() => onGoTo?.(func)}
		>
			{signature}
		</button>
	);
}

/**
 * Ghidra's function header: the banner, the signature, and the type, storage
 * and name of everything the function takes and returns.
 *
 * The argument and local lines are derived from the function's own instructions
 * (calling-convention registers and frame references), so they say what the code
 * does, not what a symbol table declares. The two editable columns are the
 * analyst's conclusions about those same facts, and they are the point of the
 * header: a return type and a variable's name are what turn a stack offset into
 * something worth reasoning about, and they belong on the line that says which
 * offset it is.
 *
 * @param props.func - The function whose entry this header introduces.
 * @param props.onGoTo - Called to navigate to the function.
 * @returns The header lines.
 */
export function FunctionHeader({
	func,
	onGoTo,
}: {
	func: Function;
	onGoTo?: (f: Function) => void;
}) {
	// Read straight from the cache during render; the only state is a counter
	// that re-renders this header once a fetch fills the cache.
	const [, forceRender] = useState(0);
	const info = headerInfoCache.get(func.addr) ?? null;

	useEffect(() => {
		if (headerInfoCache.has(func.addr)) return;
		let cancelled = false;
		Promise.all([
			api.functionDisasm(func.addr),
			api.xrefsTo(func.addr).catch(() => [] as Xref[]),
		])
			.then(([asm, xrefs]) => {
				const insns: DebugInsn[] = (asm?.ops ?? []).map((o) => ({
					addr: o.addr,
					bytes: o.bytes ?? "",
					text: o.text ?? o.disasm ?? "",
				}));
				headerInfoCache.set(func.addr, {
					args: argsOf(insns),
					locals: localsOf(insns),
					frame: frameOf(insns),
					xrefs,
				});
				if (!cancelled) forceRender((n) => n + 1);
			})
			.catch(() => {
				/* no disassembly to derive from; the header still renders */
			});
		return () => {
			cancelled = true;
		};
	}, [func.addr]);

	const xrefs = info?.xrefs ?? [];
	const xrefText = xrefs.length
		? `XREF[${xrefs.length}]:  ${xrefs
				.map((x) => `${fmtAddr(x.from)}(*)`)
				.join(", ")}`
		: "";

	return (
		<div className="text-asm-number px-3 pt-3 pb-1 font-mono text-[11px] leading-4 whitespace-pre">
			<div className="text-center">{functionBanner().join("\n")}</div>
			<Signature func={func} onGoTo={onGoTo} />
			<HeaderRow
				type={
					<TypeCell
						func={func.addr}
						datum={RETURN_KEY}
						width={0}
						className={CELL}
					/>
				}
				storage="<UNASSIGNED>"
				name="<RETURN>"
			/>
			{info?.args.map((a) => (
				<HeaderRow
					key={`arg-${a.reg}`}
					// An argument's register is the whole of its identity, so that is
					// what it is named and typed under; no single access reveals its
					// width, so the derived type says nothing more than that.
					type={
						<TypeCell
							func={func.addr}
							datum={a.reg}
							width={0}
							className={CELL}
						/>
					}
					storage={a.reg}
					name={
						<NameCell
							func={func.addr}
							datum={a.reg}
							fallback={defaultVarName(a)}
							className={CELL}
						/>
					}
				/>
			))}
			{info?.locals.map((l) => (
				<HeaderRow
					key={`local-${l.offset}`}
					type={
						<TypeCell
							func={func.addr}
							datum={l.offset}
							width={l.width}
							className={CELL}
						/>
					}
					storage={stackStorage(l.offset)}
					name={
						<NameCell
							func={func.addr}
							datum={l.offset}
							fallback={defaultVarName(l)}
							className={CELL}
						/>
					}
				/>
			))}
			<div className="text-muted-foreground">
				{`${(func.name ?? "function").padEnd(26)}${xrefText}`}
			</div>
		</div>
	);
}
