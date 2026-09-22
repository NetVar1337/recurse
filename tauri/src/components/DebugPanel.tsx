import {
	Bug,
	CornerDownRight,
	CornerUpRight,
	Loader2,
	Play,
	Send,
	StepForward,
	X,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { pickBinary } from "@/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useAnalysisStore } from "@/store/analysisStore";
import { useDebugStore } from "@/store/debugStore";
import type { DebugStopReason } from "@/types";

function fmtAddr(a?: number | null): string {
	return typeof a === "number" ? `0x${a.toString(16)}` : "";
}

/** Human label for a stop reason. */
function reasonLabel(r?: DebugStopReason): string {
	if (!r) return "—";
	switch (r.reason) {
		case "started":
			return "started";
		case "breakpoint":
			return `breakpoint ${fmtAddr(r.addr)}`;
		case "step":
			return "step";
		case "signal":
			return `signal ${r.name ?? r.signal ?? "?"}`;
		case "exited":
			return `exited (${r.code})`;
		case "killed":
			return `killed (signal ${r.signal})`;
		default:
			return r.reason;
	}
}

/** Jump to the function containing a backtrace frame. */
function gotoFrame(addr: number): void {
	const funcs = useAnalysisStore.getState().funcs;
	const f = funcs.find((x) => x.addr === addr);
	if (f) useAnalysisStore.getState().selectFn(f);
}

function Section({
	title,
	children,
}: {
	title: string;
	children: React.ReactNode;
}) {
	return (
		<section className="min-w-0">
			<h3 className="text-muted-foreground mb-1.5 text-[11px] font-semibold tracking-wider uppercase">
				{title}
			</h3>
			{children}
		</section>
	);
}

/**
 * Debug tab: launch/attach the target, control it, and inspect registers,
 * the stack, breakpoints, and a backtrace. All state comes from `debugStore`,
 * which is the same debug session the agent drives.
 */
export function DebugPanel() {
	const active = useDebugStore((s) => s.active);
	const pid = useDebugStore((s) => s.pid);
	const state = useDebugStore((s) => s.state);
	const stop = useDebugStore((s) => s.stop);
	const registers = useDebugStore((s) => s.registers);
	const breakpoints = useDebugStore((s) => s.breakpoints);
	const frames = useDebugStore((s) => s.frames);
	const output = useDebugStore((s) => s.output);
	const log = useDebugStore((s) => s.log);
	const busy = useDebugStore((s) => s.busy);
	const error = useDebugStore((s) => s.error);
	const run = useDebugStore((s) => s.run);
	const sendStdin = useDebugStore((s) => s.sendStdin);
	const pollOutput = useDebugStore((s) => s.pollOutput);
	const [attachPid, setAttachPid] = useState("");
	const [breakAt, setBreakAt] = useState("");
	const [stdin, setStdin] = useState("");
	const outputRef = useRef<HTMLDivElement>(null);

	// Poll the debuggee's output while it is alive, so prompts appear even when
	// a `continue` is still blocked waiting for a stop.
	useEffect(() => {
		if (!active) return;
		const id = setInterval(() => void pollOutput(), 400);
		return () => clearInterval(id);
	}, [active, pollOutput]);

	// Keep the newest output in view.
	useEffect(() => {
		if (outputRef.current) {
			outputRef.current.scrollTop = outputRef.current.scrollHeight;
		}
	}, [output]);

	const onSendStdin = async () => {
		const text = stdin;
		setStdin("");
		await sendStdin(`${text}\n`);
	};

	const onBreak = async () => {
		const spec = breakAt.trim();
		if (!spec) return;
		const isAddr = /^0x[0-9a-f]+$/i.test(spec) || /^\d+$/.test(spec);
		await run("break", isAddr ? { addr: spec } : { symbol: spec });
		setBreakAt("");
	};

	const onLaunch = async () => {
		const path = await pickBinary();
		if (path) await run("launch", { path });
	};

	const onAttach = async () => {
		const n = Number.parseInt(attachPid.trim(), 10);
		if (Number.isFinite(n) && n > 0) await run("attach", { pid: n });
	};

	const regEntries = registers
		? Object.entries(registers.values).filter(
				([k]) => !["rip", "rsp", "rbp", "pc", "sp"].includes(k),
			)
		: [];

	return (
		<div className="flex min-h-0 flex-1 flex-col">
			<div className="border-border flex flex-wrap items-center gap-1.5 border-b px-2 py-1.5">
				<Button
					size="sm"
					variant="outline"
					onClick={onLaunch}
					disabled={busy}
				>
					<Bug className="mr-1 h-3.5 w-3.5" /> Launch…
				</Button>
				<div className="flex items-center gap-1">
					<Input
						value={attachPid}
						onChange={(e) => setAttachPid(e.target.value)}
						placeholder="pid"
						className="h-7 w-20 text-xs"
					/>
					<Button
						size="sm"
						variant="outline"
						onClick={onAttach}
						disabled={busy || !attachPid.trim()}
					>
						Attach
					</Button>
				</div>
				<div className="bg-border mx-1 h-5 w-px" />
				<div className="flex items-center gap-1">
					<Input
						value={breakAt}
						onChange={(e) => setBreakAt(e.target.value)}
						onKeyDown={(e) => {
							if (e.key === "Enter") void onBreak();
						}}
						placeholder="addr or symbol"
						className="h-7 w-32 text-xs"
					/>
					<Button
						size="sm"
						variant="outline"
						onClick={onBreak}
						disabled={busy || !active || !breakAt.trim()}
						title="Set a breakpoint"
					>
						Break
					</Button>
				</div>
				<div className="bg-border mx-1 h-5 w-px" />
				<Button
					size="sm"
					variant="secondary"
					onClick={() => void run("continue")}
					disabled={busy || !active}
					title="Continue"
				>
					<Play className="mr-1 h-3.5 w-3.5" /> Continue
				</Button>
				<Button
					size="sm"
					variant="ghost"
					onClick={() => void run("step", { kind: "into" })}
					disabled={busy || !active}
					title="Step into"
				>
					<StepForward className="h-3.5 w-3.5" />
				</Button>
				<Button
					size="sm"
					variant="ghost"
					onClick={() => void run("step", { kind: "over" })}
					disabled={busy || !active}
					title="Step over"
				>
					<CornerDownRight className="h-3.5 w-3.5" />
				</Button>
				<Button
					size="sm"
					variant="ghost"
					onClick={() => void run("step", { kind: "out" })}
					disabled={busy || !active}
					title="Step out"
				>
					<CornerUpRight className="h-3.5 w-3.5" />
				</Button>
				<div className="bg-border mx-1 h-5 w-px" />
				<Button
					size="sm"
					variant="ghost"
					onClick={() => void run("detach")}
					disabled={busy || !active}
				>
					Detach
				</Button>
				<Button
					size="sm"
					variant="ghost"
					className="text-destructive"
					onClick={() => void run("kill")}
					disabled={busy || !active}
				>
					<X className="mr-1 h-3.5 w-3.5" /> Kill
				</Button>
				{busy && (
					<Loader2 className="text-muted-foreground h-3.5 w-3.5 animate-spin" />
				)}
			</div>

			<div className="text-muted-foreground flex items-center gap-3 border-b px-3 py-1 text-[11px]">
				<span>
					pid{" "}
					<span className="text-foreground font-mono">
						{pid ?? "—"}
					</span>
				</span>
				<span>
					state{" "}
					<span className="text-foreground font-mono">{state}</span>
				</span>
				<span>
					stop{" "}
					<span className="text-foreground font-mono">
						{reasonLabel(stop?.reason)}
					</span>
				</span>
			</div>

			{error && (
				<div className="border-destructive bg-destructive/10 text-destructive border-b px-3 py-1.5 text-[11px]">
					{error}
				</div>
			)}

			<div className="grid min-h-0 flex-1 grid-cols-1 gap-4 overflow-auto p-3 lg:grid-cols-3">
				<Section title="Registers">
					{registers ? (
						<div className="flex flex-col gap-1">
							<div className="bg-muted/40 rounded px-2 py-1 font-mono text-[11px]">
								pc {fmtAddr(registers.pc)}
							</div>
							<div className="bg-muted/40 rounded px-2 py-1 font-mono text-[11px]">
								sp {fmtAddr(registers.sp)}
							</div>
							<div className="bg-muted/40 rounded px-2 py-1 font-mono text-[11px]">
								fp {fmtAddr(registers.fp)}
							</div>
							<div className="mt-1 grid grid-cols-2 gap-1">
								{regEntries.map(([k, v]) => (
									<div
										key={k}
										className="bg-muted/30 flex justify-between rounded px-2 py-0.5 font-mono text-[10.5px]"
									>
										<span className="text-muted-foreground">
											{k}
										</span>
										<span>{fmtAddr(v)}</span>
									</div>
								))}
							</div>
						</div>
					) : (
						<span className="text-muted-foreground text-[11px]">
							not running
						</span>
					)}
				</Section>

				<Section title={`Backtrace · ${frames.length}`}>
					<div className="flex flex-col gap-0.5">
						{frames.map((f, i) => (
							<button
								key={`${f.addr}-${i}`}
								className="hover:bg-accent flex items-center gap-2 rounded px-2 py-0.5 text-left font-mono text-[11px]"
								onClick={() => gotoFrame(f.addr)}
								title="Go to function"
							>
								<span className="text-muted-foreground w-4 shrink-0">
									{i}
								</span>
								<span className="text-primary shrink-0">
									{fmtAddr(f.addr)}
								</span>
								<span className="truncate">
									{f.name ?? "?"}
								</span>
							</button>
						))}
						{frames.length === 0 && (
							<span className="text-muted-foreground text-[11px]">
								no frames
							</span>
						)}
					</div>
				</Section>

				<Section title={`Breakpoints · ${breakpoints.length}`}>
					<div className="flex flex-col gap-0.5">
						{breakpoints.map((b) => (
							<div
								key={b.id}
								className="hover:bg-accent group flex items-center gap-2 rounded px-2 py-0.5 font-mono text-[11px]"
							>
								<span className="text-destructive">●</span>
								<span className="text-primary">
									{fmtAddr(b.addr)}
								</span>
								<span className="text-muted-foreground">
									#{b.id}
								</span>
								<button
									className="text-muted-foreground hover:text-foreground ml-auto hidden group-hover:block"
									title="Remove breakpoint"
									onClick={() =>
										void run("unbreak", { id: b.id })
									}
								>
									<X className="h-3 w-3" />
								</button>
							</div>
						))}
						{breakpoints.length === 0 && (
							<span className="text-muted-foreground text-[11px]">
								none
							</span>
						)}
					</div>
				</Section>
			</div>

			<div className="border-border border-t">
				<div className="text-muted-foreground px-3 py-1 text-[11px] font-semibold tracking-wider uppercase">
					Program output
				</div>
				<div ref={outputRef} className="scroll-host h-32 overflow-auto">
					<pre className="p-2 font-mono text-[10.5px] whitespace-pre-wrap">
						{output.replace(/\r/g, "")}
					</pre>
				</div>
				<div className="flex items-center gap-1.5 border-t px-2 py-1.5">
					<Input
						value={stdin}
						onChange={(e) => setStdin(e.target.value)}
						onKeyDown={(e) => {
							if (e.key === "Enter") void onSendStdin();
						}}
						placeholder="type input for the target — Enter sends"
						className="h-7 flex-1 text-xs"
						disabled={!active}
					/>
					<Button
						size="sm"
						onClick={onSendStdin}
						disabled={!active || !stdin.trim()}
					>
						<Send className="h-3.5 w-3.5" />
					</Button>
				</div>
				<ScrollArea className="h-24 border-t">
					<pre className="scroll-host text-muted-foreground p-2 font-mono text-[10.5px] whitespace-pre-wrap">
						{log.join("\n")}
					</pre>
				</ScrollArea>
			</div>
		</div>
	);
}
