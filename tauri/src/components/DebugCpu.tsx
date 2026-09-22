import { useEffect, useMemo, useState } from "react";
import { api } from "@/api";
import { DisasmComment, DisasmInstr, splitComment } from "@/lib/disasm";
import { cn } from "@/lib/utils";
import { useDebugStore } from "@/store/debugStore";
import type { AsmInsn } from "@/types";

/** How many instructions to show around the program counter. */
const WINDOW = 48;

function fmtAddr(a?: number | null): string {
	return typeof a === "number" ? `0x${a.toString(16)}` : "";
}

/**
 * The CPU view: disassembly around the current program counter.
 *
 * Each row has a breakpoint gutter (click to toggle) and the current
 * instruction is highlighted with a `▶`. Disassembly addresses are static, so
 * the runtime pc is mapped back by subtracting the session's load bias.
 */
export function DebugCpu() {
	const pc = useDebugStore((s) => s.registers?.pc ?? null);
	const bias = useDebugStore((s) => s.bias);
	const breakpoints = useDebugStore((s) => s.breakpoints);
	const active = useDebugStore((s) => s.active);
	const run = useDebugStore((s) => s.run);
	const [data, setData] = useState<{ pc: number; ops: AsmInsn[] } | null>(
		null,
	);
	const [err, setErr] = useState<string | null>(null);

	const staticPc = pc != null ? pc - bias : null;

	useEffect(() => {
		if (staticPc == null) return;
		let cancelled = false;
		api.disassemble(staticPc, WINDOW)
			.then((d) => {
				if (!cancelled) {
					setData({ pc: staticPc, ops: d ?? [] });
					setErr(null);
				}
			})
			.catch((e) => {
				if (!cancelled) setErr(String(e));
			});
		return () => {
			cancelled = true;
		};
	}, [staticPc]);

	// Only show disassembly fetched for the current pc, so it never goes stale.
	const ops = data && data.pc === staticPc ? data.ops : [];

	// Static address -> breakpoint id, for the gutter.
	const bpAt = useMemo(() => {
		const m = new Map<number, number>();
		for (const b of breakpoints) m.set(b.addr - bias, b.id);
		return m;
	}, [breakpoints, bias]);

	const toggle = (staticAddr: number) => {
		const id = bpAt.get(staticAddr);
		if (id != null) void run("unbreak", { id });
		else void run("break", { addr: staticAddr + bias });
	};

	if (!active) {
		return (
			<div className="text-muted-foreground flex h-full items-center justify-center text-xs">
				no debug session — Launch… or Attach
			</div>
		);
	}
	if (err) {
		return <div className="text-destructive p-3 text-[11px]">{err}</div>;
	}

	return (
		<div className="scroll-host min-h-0 flex-1 overflow-auto font-mono text-[11px]">
			<table className="w-full border-collapse">
				<tbody>
					{ops.map((op) => {
						const { instr, comment } = splitComment(
							op.text ?? op.disasm ?? "",
						);
						const isPc = op.addr === staticPc;
						const hasBp = bpAt.has(op.addr);
						return (
							<tr
								key={op.addr}
								className={cn(
									"hover:bg-accent/40",
									isPc && "bg-primary/25",
								)}
							>
								<td
									className="w-4 cursor-pointer px-1 text-center select-none"
									onClick={() => toggle(op.addr)}
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
								<td className="text-primary w-3 text-center select-none">
									{isPc ? "▶" : ""}
								</td>
								<td className="w-[9ch] px-1 whitespace-nowrap text-sky-600 dark:text-sky-400">
									{fmtAddr(op.addr)}
								</td>
								<td className="w-[16ch] px-1 whitespace-nowrap text-emerald-600 dark:text-emerald-400">
									{op.bytes ?? ""}
								</td>
								<td className="px-1 whitespace-nowrap">
									<DisasmInstr text={instr} />
									<DisasmComment comment={comment} />
								</td>
							</tr>
						);
					})}
				</tbody>
			</table>
			{ops.length === 0 && (
				<div className="text-muted-foreground p-3 text-xs">
					no disassembly
				</div>
			)}
		</div>
	);
}
