import { useMemo, useState } from "react";

import { api } from "@/api";

import { useAnalysisStore } from "@/store/analysisStore";
import { useDebugStore } from "@/store/debugStore";
import { DISASM_AFTER, windowAround } from "@/lib/debugDisasm";
import {
	argsOf,
	defaultVarName,
	describeVar,
	frameOf,
	localsOf,
	slotLabel,
} from "@/lib/debugVars";
import type { DebugInsn } from "@/types";

/** A short line of text where a list would have been. */
function Empty({ label }: { label: string }) {
	return <div className="text-muted-foreground p-3 text-xs">{label}</div>;
}

/** Persist a variable's new name, or clear it when the name is blank. */
function useRenameVar() {
	const setVariableName = useAnalysisStore((s) => s.setVariableName);
	return async (func: number, key: string, name: string) => {
		// Shown first: the view updates on the analyst's keystroke, and a failed
		// write is worth giving up the name rather than silently not sticking.
		setVariableName(func, key, name);
		try {
			await api.renameVariable(func, key, name);
		} catch (e) {
			setVariableName(func, key, "");
			throw e;
		}
	};
}

/**
 * One variable, named in place.
 *
 * The name is the point of the row, so it is editable the way a register is:
 * click it, type, commit. What the code already said about it — a pointer, a
 * byte, read and written how often — sits beside the name rather than in place
 * of it, because that part is cheap to check and the name is not.
 */
function VariableRow({
	label,
	name,
	detail,
	onRename,
}: {
	label: string;
	name: string;
	detail: string;
	onRename: (name: string) => void;
}) {
	const [editing, setEditing] = useState(false);
	const [draft, setDraft] = useState(name);
	// A rename from another view has to reach the field, but not one being typed.
	const [shownWhen, setShownWhen] = useState(name);
	if (shownWhen !== name) {
		setShownWhen(name);
		if (!editing) setDraft(name);
	}
	return (
		<div className="hover:bg-accent/40 flex items-center gap-2 px-2 py-0.5 font-mono text-xs">
			<span className="text-asm-string w-[7ch] shrink-0">{label}</span>
			{editing ? (
				<input
					autoFocus
					value={draft}
					onChange={(e) => setDraft(e.target.value)}
					onBlur={() => {
						setEditing(false);
						if (draft.trim() && draft !== name) onRename(draft);
					}}
					onKeyDown={(e) => {
						if (e.key === "Enter") e.currentTarget.blur();
						if (e.key === "Escape") {
							setDraft(name);
							setEditing(false);
						}
					}}
					className="bg-background min-w-0 flex-1 border px-1 py-0 font-mono text-xs"
				/>
			) : (
				<button
					className="text-foreground min-w-0 flex-1 truncate text-left hover:underline"
					title="Click to name this variable"
					onClick={() => setEditing(true)}
				>
					{name}
				</button>
			)}
			<span className="text-muted-foreground shrink-0 text-[10px]">
				{detail}
			</span>
		</div>
	);
}

/** How many variables a function has, for a tab label or a collapsed header. */
export function countVars(insns: readonly DebugInsn[]): number {
	return localsOf(insns).length + argsOf(insns).length;
}

/**
 * A function's variables: its arguments, and the frame slots it uses.
 *
 * Nothing in the file declares these — no symbol table has a `local_18h` — so
 * they are read out of the function's own instructions: the slots it touches,
 * through whichever register addresses them, and the argument registers it reads
 * before it writes them. Each is named by its offset until the analyst gives it
 * a real one, and from then on the name shows beside `[rbp - 0x18]` in every
 * view of the function.
 *
 * Deliberately not tied to a debug session: naming a variable is static work,
 * the instructions come from the disassembly either way, and a name recorded
 * here has to be visible in the static listing as well as in the debugger.
 *
 * @param func - The function's static address, or null when there is none.
 * @param insns - The function's instructions.
 */
export function VariableList({
	func,
	insns,
}: {
	func: number | null;
	insns: readonly DebugInsn[] | undefined;
}) {
	const names = useAnalysisStore((s) => s.variableNames);
	const renameVar = useRenameVar();
	const body = useMemo(() => insns ?? [], [insns]);
	const locals = useMemo(() => localsOf(body), [body]);
	const args = useMemo(() => argsOf(body), [body]);
	const frame = useMemo(() => frameOf(body), [body]);

	if (func === null) return <Empty label="no function" />;
	const shown = (key: string, fallback: string) =>
		names[`${func}:${key}`] ?? fallback;

	return (
		<>
			{args.length > 0 && (
				<>
					<div className="text-muted-foreground px-3 py-1 text-[10px] tracking-wider uppercase">
						Arguments
					</div>
					{args.map((a) => (
						<VariableRow
							key={a.reg}
							label={a.reg}
							name={shown(a.reg, defaultVarName(a))}
							detail={`${a.reads} read${a.reads === 1 ? "" : "s"}`}
							onRename={(n) => void renameVar(func, a.reg, n)}
						/>
					))}
				</>
			)}
			<div className="text-muted-foreground px-3 py-1 text-[10px] tracking-wider uppercase">
				Locals
			</div>
			{locals.length === 0 ? (
				<Empty label="no frame slots" />
			) : (
				locals.map((v) => (
					<VariableRow
						key={v.offset}
						label={slotLabel(v.offset, frame)}
						name={shown(String(v.offset), defaultVarName(v))}
						detail={`${describeVar(v)} · ${v.reads}r ${v.writes}w`}
						onRename={(n) =>
							void renameVar(func, String(v.offset), n)
						}
					/>
				))
			)}
		</>
	);
}

/**
 * The variables of the function the debugger's cursor is in.
 *
 * The debugger knows the cursor's *runtime* address, and a name is keyed by the
 * function's static one, so the load bias is what makes the two views agree.
 */
export function DebuggerVariableList() {
	const disasm = useDebugStore((s) => s.disasm);
	const pc = useDebugStore((s) => s.registers?.pc ?? null);
	const lastPc = useDebugStore((s) => s.lastPc);
	const bias = useDebugStore((s) => s.bias);
	const runtime = pc ?? lastPc;
	// Only the function the cursor is in: the cache holds every function the
	// session has decoded, and one unrelated `sub rsp, 0x20` in it would set this
	// function's frame depth and rename every slot in it.
	const insns = useMemo(() => {
		if (runtime === null) return [];
		return windowAround(disasm, runtime, DISASM_AFTER, DISASM_AFTER).map(
			(row) => row.insn,
		);
	}, [disasm, runtime]);
	return (
		<VariableList
			func={runtime === null ? null : runtime - bias}
			insns={insns}
		/>
	);
}

/**
 * A function's variables, in a collapsible strip above its disassembly.
 *
 * The static view is where an analyst reads a function, so it is where a
 * variable has to be nameable: a name that could only be typed with a live
 * process attached would be a name half the tool could not create, and the
 * listing below would show the name in one place and nowhere else.
 */
export function FunctionVariables({
	funcAddr,
	ops,
}: {
	funcAddr: number | null;
	ops: readonly {
		addr: number;
		bytes?: string | null;
		text?: string;
		disasm?: string;
	}[];
}) {
	const [open, setOpen] = useState(false);
	const insns = useMemo(
		() =>
			ops.map((op) => ({
				addr: op.addr,
				bytes: op.bytes ?? "",
				text: op.text ?? op.disasm ?? "",
			})),
		[ops],
	);
	const count = useMemo(() => countVars(insns), [insns]);
	if (funcAddr === null) return null;
	return (
		<div className="border-border border-b">
			<button
				className="text-muted-foreground hover:text-foreground flex w-full items-center gap-2 px-3 py-1 text-left text-[10px] font-semibold tracking-wider uppercase"
				onClick={() => setOpen((v) => !v)}
				aria-expanded={open}
			>
				<span className="w-2 shrink-0">{open ? "▾" : "▸"}</span>
				Variables
				<span className="font-normal normal-case">
					{count === 0 ? "none found" : count}
				</span>
			</button>
			{open && (
				<div className="scroll-host max-h-56 overflow-auto pb-1">
					<VariableList func={funcAddr} insns={insns} />
				</div>
			)}
		</div>
	);
}
