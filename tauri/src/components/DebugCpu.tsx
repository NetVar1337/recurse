import { useEffect, useMemo, useState } from "react";

import { api } from "@/api";
import { DisasmInstr } from "@/lib/disasm";
import { cn } from "@/lib/utils";
import { useDebugStore } from "@/store/debugStore";
import type { DebugInsn } from "@/types";

/** How many instructions to show around the program counter. */
const WINDOW = 48;

function fmtAddr(a?: number | null): string {
	return typeof a === "number" ? `0x${a.toString(16)}` : "";
}

/**
 * The CPU view: the instructions at the current program counter, decoded from
 * the debuggee's live memory.
 *
 * Addresses here are *runtime* addresses (the loader, a JIT page, or the main
 * binary), so the disassembly is what is actually mapped and needs no static
 * mapping. Each row has a breakpoint gutter (click to toggle) and the current
 * instruction is highlighted with a `▶`.
 */
export function DebugCpu() {
	const pc = useDebugStore((s) => s.registers?.pc ?? null);
	const breakpoints = useDebugStore((s) => s.breakpoints);
	const active = useDebugStore((s) => s.active);
	const run = useDebugStore((s) => s.run);
	const [data, setData] = useState<{ pc: number; ops: DebugInsn[] } | null>(
		null,
	);
	const [err, setErr] = useState<string | null>(null);

	useEffect(() => {
		if (pc == null || !active) return;
		let cancelled = false;
		api.debugCommand("disasm", { addr: pc, count: WINDOW })
			.then((d) => {
				if (!cancelled) {
					setData({ pc, ops: (d as DebugInsn[]) ?? [] });
					setErr(null);
				}
			})
			.catch((e) => {
				if (!cancelled) setErr(String(e));
			});
		return () => {
			cancelled = true;
		};
	}, [pc, active]);

	// Only show disassembly decoded for the current pc, so it never goes stale.
	const ops = data && data.pc === pc ? data.ops : [];

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
	if (err) {
		return <div className="text-destructive p-3 text-xs">{err}</div>;
	}

	return (
		<div className="scroll-host min-h-0 flex-1 overflow-auto font-mono text-xs">
			<table className="w-full border-collapse">
				<tbody>
					{ops.map((op) => {
						const isPc = op.addr === pc;
						const hasBp = bpAt.has(op.addr);
						return (
							<tr
								key={op.addr}
								className={cn(
									"hover:bg-accent/40",
									isPc && "ui-selected",
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
								<td className="nums text-asm-addr min-w-[9ch] px-1 whitespace-nowrap">
									{fmtAddr(op.addr)}
								</td>
								<td className="text-asm-bytes min-w-[16ch] px-1 whitespace-nowrap">
									{op.bytes}
								</td>
								<td className="px-1 whitespace-nowrap">
									<DisasmInstr text={op.text} />
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
