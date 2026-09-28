import { useEffect, useMemo, useRef } from "react";

import { DisasmComment, DisasmInstr, splitComment } from "@/lib/disasm";
import { chrome } from "@/lib/chrome";
import {
	branchVerdict,
	classifyInsn,
	peekTarget,
	verdictText,
	x86Flags,
} from "@/lib/branches";
import {
	DISASM_AFTER,
	DISASM_PEEK,
	windowAround,
	type DisasmPeek,
} from "@/lib/debugDisasm";
import { cn } from "@/lib/utils";
import { useDebugStore, isLiveState } from "@/store/debugStore";
import { useSettingsStore } from "@/store/settingsStore";

function fmtAddr(a?: number | null): string {
	return typeof a === "number" ? `0x${a.toString(16)}` : "";
}

/**
 * The CPU view: the instructions around the current program counter, decoded
 * from the debuggee's live memory.
 *
 * Addresses here are *runtime* addresses (the loader, a JIT page, or the main
 * binary), so the disassembly is what is actually mapped and needs no static
 * mapping. It is a code window anchored on the cursor: the instructions leading
 * into it are dimmed as context, and the cursor row is the only one marked.
 *
 * The rows above the cursor are *not* a record of what ran, and deliberately do
 * not pretend to be. A debugger only observes the program between stops, so on a
 * loop the code sitting just above the cursor is the middle of a body the run
 * may have left several laps ago — reading it as history is what turns a
 * backward branch into an invisible one. What actually happened is on the
 * cursor's own instruction, and it is shown there: a conditional branch is
 * labelled `taken`/`not taken` with the flag condition that decides it, and when
 * it is going to be taken its target is spliced in underneath with `↳`, so
 * standing on a loop's back edge shows the whole iteration right there.
 *
 * `debugContext` (Settings > Debugger) sets how many instructions of context
 * stay above the cursor.
 *
 * A `; ...` suffix is split out and rendered by [`DisasmComment`], so the live
 * view colours comments exactly as the static views do.
 */
export function DebugCpu() {
	const livePc = useDebugStore((s) => s.registers?.pc ?? null);
	const lastPc = useDebugStore((s) => s.lastPc);
	const registers = useDebugStore((s) => s.registers);
	const state = useDebugStore((s) => s.state);
	const disasm = useDebugStore((s) => s.disasm);
	const pending = useDebugStore((s) => s.disasmPending);
	const breakpoints = useDebugStore((s) => s.breakpoints);
	const active = useDebugStore((s) => s.active);
	const error = useDebugStore((s) => s.disasmError);
	const run = useDebugStore((s) => s.run);
	const ensureDisasm = useDebugStore((s) => s.ensureDisasm);
	const context = useSettingsStore((s) => s.debugContext);
	const pcRow = useRef<HTMLTableRowElement | null>(null);

	const live = isLiveState(state);
	// Once the process is gone there is no live pc, so the view stays anchored on
	// the last one and there are no registers left to judge a branch by.
	const anchor = livePc ?? lastPc;

	useEffect(() => {
		// Never fetch against a process that has exited: the backend would only
		// answer "no debuggee is running", and the decoded window is already here.
		if (livePc == null || !live) return;
		void ensureDisasm(livePc);
	}, [livePc, live, ensureDisasm]);

	// The cursor's own instruction is what carries the branch verdict, and the
	// verdict is what decides whether there is a target to peek.
	const cursor = anchor == null ? null : (disasm.get(anchor) ?? null);
	const branch = useMemo(
		() => (cursor ? classifyInsn(cursor.text) : null),
		[cursor],
	);
	const verdict = useMemo(
		() =>
			branch
				? branchVerdict(
						branch,
						x86Flags(registers?.values.eflags),
						registers?.values.rcx ?? 0,
					)
				: null,
		[branch, registers],
	);
	const peek = useMemo<DisasmPeek | null>(() => {
		const at = peekTarget(branch, verdict);
		return at == null ? null : { addr: at, lines: DISASM_PEEK };
	}, [branch, verdict]);

	// Anchored at the cursor: context above it, the straight decode below, or the
	// branch target when the cursor is on a branch that is about to be taken.
	const rows = useMemo(
		() => windowAround(disasm, anchor, context, DISASM_AFTER, peek),
		[disasm, anchor, context, peek],
	);

	// Where the cursor sits in the list, which is a row identity rather than an
	// address: a peek splices in code the window may already show elsewhere.
	const cursorAt = useMemo(
		() => rows.findIndex((r) => r.role === "cursor"),
		[rows],
	);

	// Keep the cursor on screen as the window slides, without yanking the view
	// when it is already visible.
	useEffect(() => {
		pcRow.current?.scrollIntoView({ block: "nearest" });
	}, [anchor, rows.length, cursorAt]);

	// Breakpoints are runtime addresses, matching these rows directly.
	const bpAt = useMemo(() => {
		const m = new Map<number, number>();
		for (const b of breakpoints) m.set(b.addr, b.id);
		return m;
	}, [breakpoints]);

	const toggle = (addr: number) => {
		const id = bpAt.get(addr);
		if (id != null) void run("unbreak", { id });
		else void run("break", { addr });
	};

	if (!active) {
		return (
			<div className="text-muted-foreground flex h-full items-center justify-center text-xs">
				no debug session — Launch… or Attach
			</div>
		);
	}

	return (
		<div className="scroll-host min-h-0 flex-1 overflow-auto font-mono text-xs">
			{error && (
				<div className="text-destructive border-destructive/40 border-b px-2 py-1">
					{error}
				</div>
			)}
			<table className="w-full border-collapse">
				<tbody>
					{rows.map((row, i) => {
						// The `; ...` suffix is a comment, not assembly, so it is
						// split out and styled like every other view rather than
						// tokenized as operands.
						const { instr, comment } = splitComment(row.insn.text);
						const isPc = live && row.role === "cursor";
						const hasBp = bpAt.has(row.addr);
						return (
							<tr
								// Positional: a peek repeats addresses the window may
								// already show, so an address is not a key here.
								key={i}
								ref={isPc ? pcRow : undefined}
								className={cn(
									"hover:bg-accent/40",
									row.role === "past" && chrome.past,
									row.role === "peek" && chrome.peek,
									isPc && chrome.selected,
								)}
							>
								<td
									className="w-4 cursor-pointer px-1 text-center select-none"
									onClick={() => toggle(row.addr)}
									title="Toggle breakpoint"
								>
									<span
										className={cn(
											"inline-block h-2 w-2 rounded-full",
											hasBp
												? "bg-red-500"
												: "bg-transparent hover:bg-red-500/40",
										)}
									/>
								</td>
								<td
									className={cn(
										"w-3 text-center select-none",
										row.role === "cursor"
											? "text-primary"
											: "text-muted-foreground",
									)}
									title={
										row.role === "peek"
											? "where this branch is about to land"
											: row.role === "cursor"
												? "about to execute"
												: undefined
									}
								>
									{row.marker === "pc"
										? "▶"
										: row.marker === "peek"
											? "↳"
											: ""}
								</td>
								<td className="nums text-asm-addr min-w-[9ch] px-1 whitespace-nowrap">
									{fmtAddr(row.addr)}
								</td>
								<td className="text-asm-bytes min-w-[16ch] px-1 whitespace-nowrap">
									{row.insn.bytes}
								</td>
								<td className="px-1 whitespace-nowrap">
									<DisasmInstr text={instr} />
									<DisasmComment comment={comment} />
									{isPc && verdict && (
										<span
											className={cn(
												"pl-3",
												verdict.taken
													? chrome.taken
													: chrome.fall,
											)}
											title="Decided by the flags at this stop"
										>
											{verdictText(verdict)}
										</span>
									)}
								</td>
							</tr>
						);
					})}
				</tbody>
			</table>
			{rows.length === 0 && (
				<div className="text-muted-foreground p-3 text-xs">
					{!live
						? "process has exited — no disassembly decoded"
						: livePc == null
							? "no program counter"
							: pending.has(livePc)
								? "disassembling…"
								: "no disassembly"}
				</div>
			)}
		</div>
	);
}
