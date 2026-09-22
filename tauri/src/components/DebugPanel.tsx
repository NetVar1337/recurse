import {
	Bug,
	CornerDownRight,
	CornerUpRight,
	Eye,
	EyeOff,
	Loader2,
	Play,
	Send,
	StepForward,
	X,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { api, pickBinary } from "@/api";
import { DebugCpu } from "@/components/DebugCpu";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { useAnalysisStore } from "@/store/analysisStore";
import { useDebugStore } from "@/store/debugStore";
import type { DebugStopReason } from "@/types";

function fmtAddr(a?: number | null): string {
	return typeof a === "number" ? `0x${a.toString(16)}` : "";
}

/** x86-64 RFLAGS, as the set flag names. */
function flagsOf(eflags: number): string {
	const bits: [string, number][] = [
		["CF", 0],
		["PF", 2],
		["AF", 4],
		["ZF", 6],
		["SF", 7],
		["TF", 8],
		["IF", 9],
		["DF", 10],
		["OF", 11],
	];
	return bits
		.filter(([, bit]) => (eflags >> bit) & 1)
		.map(([name]) => name)
		.join(" ");
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

/** Jump to the function containing a backtrace frame (a runtime address). */
function gotoFrame(addr: number): void {
	const bias = useDebugStore.getState().bias;
	const funcs = useAnalysisStore.getState().funcs;
	const f = funcs.find((x) => x.addr === addr - bias);
	if (f) useAnalysisStore.getState().selectFn(f);
}

function Empty({ label }: { label: string }) {
	return <div className="text-muted-foreground p-3 text-[11px]">{label}</div>;
}

/** Right column, top: general registers and flags. */
function RegistersPane() {
	const regs = useDebugStore((s) => s.registers);
	if (!regs) return <Empty label="no registers" />;
	const skip = new Set(["rip", "eflags", "orig_rax", "pc", "sp"]);
	const gp = Object.entries(regs.values).filter(([k]) => !skip.has(k));
	return (
		<div className="p-2 font-mono text-[11px]">
			<div className="mb-0.5 flex justify-between">
				<span className="text-muted-foreground">rip</span>
				<span className="text-primary">{fmtAddr(regs.pc)}</span>
			</div>
			<div className="mb-0.5 flex justify-between">
				<span className="text-muted-foreground">rsp</span>
				<span>{fmtAddr(regs.sp)}</span>
			</div>
			<div className="mb-0.5 flex justify-between">
				<span className="text-muted-foreground">rbp</span>
				<span>{fmtAddr(regs.fp)}</span>
			</div>
			<div className="mt-1.5 grid grid-cols-2 gap-x-2 gap-y-0.5">
				{gp.map(([k, v]) => (
					<div key={k} className="flex justify-between gap-2">
						<span className="text-muted-foreground">{k}</span>
						<span className="truncate">{fmtAddr(v)}</span>
					</div>
				))}
			</div>
			<div className="text-muted-foreground mt-1.5">
				flags{" "}
				<span className="text-foreground">
					{flagsOf(regs.values.eflags ?? 0) || "—"}
				</span>
			</div>
		</div>
	);
}

/** Right column, bottom: the words at the stack pointer. */
function StackPane() {
	const sp = useDebugStore((s) => s.registers?.sp ?? null);
	const active = useDebugStore((s) => s.active);
	const [data, setData] = useState<{ sp: number; words: number[] } | null>(
		null,
	);

	useEffect(() => {
		if (sp == null || !active) return;
		let cancelled = false;
		api.debugCommand("read", { addr: sp, len: 256, format: "u64" })
			.then((r) => {
				if (!cancelled) {
					setData({
						sp,
						words: (r as { words?: number[] })?.words ?? [],
					});
				}
			})
			.catch(() => {});
		return () => {
			cancelled = true;
		};
	}, [sp, active]);

	if (sp == null) return <Empty label="no stack" />;
	const words = data && data.sp === sp ? data.words : [];
	return (
		<div className="scroll-host min-h-0 flex-1 overflow-auto p-1 font-mono text-[11px]">
			{words.map((w, i) => (
				<div key={i} className="flex gap-2 px-1">
					<span className="text-muted-foreground">
						{fmtAddr(sp + i * 8)}
					</span>
					<span className="text-foreground">{fmtAddr(w)}</span>
				</div>
			))}
			{words.length === 0 && <Empty label="unreadable" />}
		</div>
	);
}

/** Bottom tabs: call stack, breakpoints, threads. */
function BottomTabs() {
	const frames = useDebugStore((s) => s.frames);
	const breakpoints = useDebugStore((s) => s.breakpoints);
	const run = useDebugStore((s) => s.run);
	const active = useDebugStore((s) => s.active);
	const pid = useDebugStore((s) => s.pid);
	const [tab, setTab] = useState<"stack" | "breakpoints" | "threads">(
		"stack",
	);
	const [threads, setThreads] = useState<{
		pid: number | null;
		ids: number[];
	}>({ pid: null, ids: [] });

	useEffect(() => {
		if (tab !== "threads" || !active) return;
		let cancelled = false;
		api.debugCommand("threads")
			.then((t) => {
				if (!cancelled) setThreads({ pid, ids: (t as number[]) ?? [] });
			})
			.catch(() => {});
		return () => {
			cancelled = true;
		};
	}, [tab, active, pid]);

	const threadIds = threads.pid === pid ? threads.ids : [];

	const tabButton = (id: typeof tab, label: string, count?: number) => (
		<button
			className={cn(
				"px-2 py-1 text-[11px]",
				tab === id
					? "text-foreground border-primary border-b-2"
					: "text-muted-foreground hover:text-foreground",
			)}
			onClick={() => setTab(id)}
		>
			{label}
			{count != null ? ` · ${count}` : ""}
		</button>
	);

	return (
		<div className="flex min-h-0 flex-col">
			<div className="border-border flex items-center border-b px-1">
				{tabButton("stack", "Call stack", frames.length)}
				{tabButton("breakpoints", "Breakpoints", breakpoints.length)}
				{tabButton("threads", "Threads")}
			</div>
			<div className="scroll-host min-h-0 flex-1 overflow-auto">
				{tab === "stack" &&
					frames.map((f, i) => (
						<button
							key={`${f.addr}-${i}`}
							className="hover:bg-accent flex w-full items-center gap-2 px-2 py-0.5 text-left font-mono text-[11px]"
							onClick={() => gotoFrame(f.addr)}
							title="Go to function"
						>
							<span className="text-muted-foreground w-4">
								{i}
							</span>
							<span className="text-primary">
								{fmtAddr(f.addr)}
							</span>
							<span className="truncate">{f.name ?? "?"}</span>
						</button>
					))}
				{tab === "breakpoints" &&
					breakpoints.map((b) => (
						<div
							key={b.id}
							className="group hover:bg-accent flex items-center gap-2 px-2 py-0.5 font-mono text-[11px]"
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
				{tab === "threads" &&
					threadIds.map((t) => (
						<div
							key={t}
							className="px-2 py-0.5 font-mono text-[11px]"
						>
							{t === pid ? "▶ " : "  "}
							{fmtAddr(t)}
						</div>
					))}
			</div>
		</div>
	);
}

/**
 * Debug workspace: a CPU/disassembly view with a breakpoint
 * gutter and current-instruction highlight, a registers + stack column, and
 * call-stack / breakpoint / thread tabs. All state is shared with the agent.
 */
export function DebugPanel() {
	const active = useDebugStore((s) => s.active);
	const pid = useDebugStore((s) => s.pid);
	const state = useDebugStore((s) => s.state);
	const stop = useDebugStore((s) => s.stop);
	const output = useDebugStore((s) => s.output);
	const busy = useDebugStore((s) => s.busy);
	const error = useDebugStore((s) => s.error);
	const follow = useDebugStore((s) => s.follow);
	const run = useDebugStore((s) => s.run);
	const sendStdin = useDebugStore((s) => s.sendStdin);
	const pollOutput = useDebugStore((s) => s.pollOutput);
	const pollSnapshot = useDebugStore((s) => s.pollSnapshot);
	const setFollow = useDebugStore((s) => s.setFollow);
	const [attachPid, setAttachPid] = useState("");
	const [breakAt, setBreakAt] = useState("");
	const [stdin, setStdin] = useState("");
	const outputRef = useRef<HTMLDivElement>(null);

	useEffect(() => {
		if (!active && !follow) return;
		const id = setInterval(() => void pollOutput(), 400);
		return () => clearInterval(id);
	}, [active, follow, pollOutput]);

	useEffect(() => {
		if (!follow) return;
		void pollSnapshot();
		const id = setInterval(() => void pollSnapshot(), 500);
		return () => clearInterval(id);
	}, [follow, pollSnapshot]);

	useEffect(() => {
		if (outputRef.current) {
			outputRef.current.scrollTop = outputRef.current.scrollHeight;
		}
	}, [output]);

	const onLaunch = async () => {
		const path = await pickBinary();
		if (path) await run("launch", { path });
	};

	const onAttach = async () => {
		const n = Number.parseInt(attachPid.trim(), 10);
		if (Number.isFinite(n) && n > 0) await run("attach", { pid: n });
	};

	const onBreak = async () => {
		const spec = breakAt.trim();
		if (!spec) return;
		const isAddr = /^0x[0-9a-f]+$/i.test(spec) || /^\d+$/.test(spec);
		await run("break", isAddr ? { addr: spec } : { symbol: spec });
		setBreakAt("");
	};

	const onSendStdin = async () => {
		const text = stdin;
		setStdin("");
		await sendStdin(`${text}\n`);
	};

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
						className="h-7 w-16 text-xs"
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
				<Button
					size="sm"
					variant="secondary"
					onClick={() => void run("continue")}
					disabled={busy || !active}
					title="Run (continue)"
				>
					<Play className="mr-1 h-3.5 w-3.5" /> Run
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
				<Input
					value={breakAt}
					onChange={(e) => setBreakAt(e.target.value)}
					onKeyDown={(e) => {
						if (e.key === "Enter") void onBreak();
					}}
					placeholder="break at addr or symbol"
					className="h-7 w-44 text-xs"
				/>
				<Button
					size="sm"
					variant="outline"
					onClick={onBreak}
					disabled={busy || !active || !breakAt.trim()}
				>
					Break
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
				<Button
					size="sm"
					variant={follow ? "secondary" : "ghost"}
					onClick={() => setFollow(!follow)}
					title="Follow the debug session live — including when the agent drives it"
				>
					{follow ? (
						<Eye className="mr-1 h-3.5 w-3.5" />
					) : (
						<EyeOff className="mr-1 h-3.5 w-3.5" />
					)}
					Follow
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

			<div className="grid min-h-0 flex-1 grid-cols-[minmax(0,1fr)_330px]">
				<div className="flex min-h-0 flex-col border-r">
					<DebugCpu />
					<div className="border-border h-44 border-t">
						<BottomTabs />
					</div>
				</div>
				<div className="flex min-h-0 flex-col">
					<div className="border-border border-b">
						<RegistersPane />
					</div>
					<StackPane />
				</div>
			</div>

			<div className="border-border border-t">
				<div className="text-muted-foreground px-3 py-1 text-[11px] font-semibold tracking-wider uppercase">
					Program output
				</div>
				<div ref={outputRef} className="scroll-host h-24 overflow-auto">
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
			</div>
		</div>
	);
}
