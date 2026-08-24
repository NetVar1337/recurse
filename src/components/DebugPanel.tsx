import { useCallback, useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import {
	FastForward,
	Loader2,
	Pause,
	Play,
	RefreshCw,
	StepForward,
	TerminalSquare,
	Trash2,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { api } from "@/api";
import { useAnalysisStore } from "@/store/analysisStore";
import { useDebugStore } from "@/store/debugStore";
import type { DebugBreakpoint, DebugInsn, Registers } from "@/types";

const LOG = "[debug-ui]";
function log(msg: string, ...rest: unknown[]) {
	console.info(`${LOG} ${msg}`, ...rest);
}
function warn(msg: string, ...rest: unknown[]) {
	console.warn(`${LOG} ${msg}`, ...rest);
}

const isWindows =
	typeof navigator !== "undefined" && /Win/.test(navigator.platform);

function fmtAddr(a?: number | null) {
	return typeof a === "number" && Number.isFinite(a)
		? `0x${a.toString(16)}`
		: "";
}

function findPc(regs: Registers): number | null {
	for (const key of ["pc", "rip", "eip"]) {
		if (typeof regs[key] === "number") return regs[key];
	}
	return null;
}

function commandText(value: unknown): string {
	if (typeof value === "string") return value.trim();
	if (value == null) return "";
	try {
		return JSON.stringify(value, null, 2);
	} catch {
		return String(value);
	}
}

/** Coerce an unknown backend payload into a clean array of objects. */
function asArray<T>(value: unknown, what: string): T[] {
	if (Array.isArray(value)) {
		const bad = value.filter((x) => x == null || typeof x !== "object");
		if (bad.length > 0) {
			warn(
				`${what}: dropped ${bad.length} malformed entr${bad.length === 1 ? "y" : "ies"}`,
				bad,
			);
		}
		return value.filter((x): x is T => x != null && typeof x === "object");
	}
	if (value == null) return [];
	warn(
		`${what}: expected array, got ${typeof value} — treating as empty`,
		value,
	);
	return [];
}

/** Coerce registers payload into a plain string->number map. */
function asRegs(value: unknown): Registers {
	if (value == null) return {};
	if (typeof value !== "object" || Array.isArray(value)) {
		warn(
			`registers: expected object, got ${typeof value} — ignoring`,
			value,
		);
		return {};
	}
	const out: Record<string, number> = {};
	for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
		out[k] = typeof v === "number" ? v : Number(v);
	}
	return out;
}

export function DebugPanel() {
	// Session/run state lives in the shared debug store: the Shell tab hosts
	// the program's I/O terminal and auto-navigation reads the same truth.
	const started = useDebugStore((s) => s.started);
	const busy = useDebugStore((s) => s.busy);
	const awaitingIo = useDebugStore((s) => s.awaitingIo);
	const setStarted = useDebugStore((s) => s.setStarted);
	const beginRun = useDebugStore((s) => s.beginRun);
	const endRun = useDebugStore((s) => s.endRun);
	const focusProgram = useDebugStore((s) => s.focusProgram);

	const [regs, setRegs] = useState<Registers>({});
	const [bps, setBps] = useState<DebugBreakpoint[]>([]);
	const [insns, setInsns] = useState<DebugInsn[]>([]);
	const [pc, setPc] = useState<number | null>(null);
	const [err, setErr] = useState<string | null>(null);
	const [flavor, setFlavor] = useState<"intel" | "att">("intel");

	// Atomic selectors: returning a fresh array from one selector breaks
	// zustand's getSnapshot caching and loops React into "maximum update
	// depth exceeded".
	const selected = useAnalysisStore((s) => s.selected);
	const selectFn = useAnalysisStore((s) => s.selectFn);
	const pcRef = useRef<HTMLSpanElement>(null);

	// Lifecycle breadcrumbs.
	useEffect(() => {
		log("panel mounted");
		return () => log("panel unmounted");
	}, []);
	useEffect(() => {
		log("panel mounted");
		// Program output streams to the console in the Shell tab; here we
		// only react to it: output while a continue is in flight means the
		// program is talking (usually prompting for input) — jump over.
		const un = listen<{ data: string }>("debug-output", () => {
			useDebugStore.getState().noteIoPrompt();
		});
		return () => {
			un.then((f) => f());
			log("panel listeners detached");
		};
	}, []);

	useEffect(() => {
		log("state", { started, busy, flavor, pc });
	}, [started, busy, flavor, pc]);

	const refresh = useCallback(async () => {
		log("refresh started");
		try {
			const [r, b, d] = await Promise.all([
				api.debugRegisters(),
				api.debugBreakpoints(),
				api.debugDisassemble(24),
			]);
			log("refresh payloads", {
				registersType: r === null ? "null" : typeof r,
				breakpointsType:
					b === null ? "null" : Array.isArray(b) ? "array" : typeof b,
				disasmType:
					d === null ? "null" : Array.isArray(d) ? "array" : typeof d,
			});
			const nextRegs = asRegs(r);
			const nextBps = asArray<DebugBreakpoint>(b, "breakpoints");
			const nextInsns = asArray<DebugInsn>(d, "disassembly");
			setRegs(nextRegs);
			setBps(nextBps);
			setInsns(nextInsns);
			const nextPc = findPc(nextRegs);
			setPc(nextPc);
			setErr(null);
			log("refresh completed", {
				registers: Object.keys(nextRegs).length,
				breakpoints: nextBps.length,
				instructions: nextInsns.length,
				pc: fmtAddr(nextPc) || "(unknown)",
			});
		} catch (e) {
			console.error(`${LOG} refresh failed`, e);
			setErr(String(e));
		}
	}, []);

	useEffect(() => {
		if (pc != null) {
			log("scrolling to pc", fmtAddr(pc));
			pcRef.current?.scrollIntoView({ block: "center" });
		}
	}, [pc, insns]);

	const guard = useCallback(
		async (label: string, fn: () => Promise<unknown>): Promise<boolean> => {
			beginRun();
			log(`${label} started`);
			try {
				const result = await fn();
				if (label === "continue" || label.startsWith("step")) {
					log(
						`${label} returned (${commandText(result).length} chars of r2 status)`,
					);
				}
				await refresh();
				log(`${label} completed`);
				return true;
			} catch (e) {
				console.error(`${LOG} ${label} failed`, e);
				setErr(String(e));
				return false;
			} finally {
				// Releases busy; when a run had jumped to an I/O prompt this
				// also returns to the tab we came from.
				endRun();
				log(`${label} busy cleared`);
			}
		},
		[refresh, beginRun, endRun],
	);

	const start = () =>
		guard("start", async () => {
			log("start: spawning debug session…");
			await api.debugStart();
			log("start: session live — marking started");
			// Mark started immediately: the debugger is live server-side even
			// if the (cosmetic) syntax-flavor command below fails, and the UI
			// must not offer a second Start against a running session.
			setStarted(true);
			await api.debugCommand(`e asm.syntax=${flavor}`);
			log("start: syntax flavor applied:", flavor);
		});

	const cont = () => guard("continue", () => api.debugCommand("dc"));
	const stepIn = () => guard("step-into", () => api.debugCommand("ds"));
	const stepOver = () => guard("step-over", () => api.debugCommand("dso"));

	// Escape hatch for a continue that never returns (debuggee waiting on
	// input, infinite loop): interrupt it like Ctrl-C in an interactive r2.
	const interrupt = async () => {
		log("interrupt requested (SIGINT)");
		try {
			await api.debugInterrupt();
			log("interrupt delivered");
		} catch (e) {
			console.error(`${LOG} interrupt failed`, e);
			setErr(String(e));
		}
	};

	const stop = async () => {
		log("stop started");
		try {
			await api.debugStop();
		} catch (e) {
			console.error(`${LOG} stop failed`, e);
			setErr(String(e));
			return;
		}
		setStarted(false);
		endRun();
		setRegs({});
		setBps([]);
		setInsns([]);
		setPc(null);
		setErr(null);
		log("stop completed — state reset");
	};

	const addBp = async () => {
		if (!selected) {
			warn("toggle-breakpoint ignored: no function selected");
			return;
		}
		const exists = bps.some((b) => b.addr === selected.addr);
		log(
			`toggle-breakpoint at ${fmtAddr(selected.addr)} → ${exists ? "remove" : "add"}`,
		);
		await guard("toggle-breakpoint", () =>
			api.debugCommand(
				exists ? `db -${selected.addr}` : `db ${selected.addr}`,
			),
		);
	};

	const removeBp = (addr: number) => {
		log(`remove-breakpoint at ${fmtAddr(addr)}`);
		return guard("remove-breakpoint", () =>
			api.debugCommand(`db -${addr}`),
		);
	};

	const changeFlavor = (next: "intel" | "att") => {
		if (next === flavor || !started || busy) {
			log(`flavor change to ${next} skipped`, {
				same: next === flavor,
				started,
				busy,
			});
			return;
		}
		void guard(`flavor-${next}`, () =>
			api.debugCommand(`e asm.syntax=${next}`),
		).then((ok) => ok && setFlavor(next));
	};

	const regEntries = Object.entries(regs);

	return (
		<div className="flex min-h-0 min-w-0 flex-1 flex-col">
			{isWindows && (
				<div className="bg-amber-500/10 border-amber-500/30 text-amber-700 dark:text-amber-400 m-2 rounded-md border px-3 py-2 text-xs">
					Live debugging (r2 -d + FIFOs + signals) requires Linux or macOS — analysis,
					decompiler, agent and shells still work on Windows.
				</div>
			)}
			<div className="border-border bg-card flex flex-nowrap items-center gap-1.5 overflow-x-auto border-b px-3 py-2">
				<div className="mr-2 flex shrink-0 items-center gap-1.5 text-xs">
					<span
						className={cn(
							"h-2 w-2 rounded-full",
							started ? "bg-primary" : "bg-muted-foreground/50",
						)}
					/>
					<span className="text-muted-foreground">
						{started ? (busy ? "Working" : "Paused") : "Stopped"}
					</span>
				</div>
				<Button
					variant="default"
					size="sm"
					className="shrink-0"
					onClick={start}
					disabled={started || busy || isWindows}
					title={
						isWindows
							? "Live debugging requires Linux or macOS — analysis and agent still available on Windows"
							: "Start the program under the debugger"
					}
				>
					{busy && !started ? (
						<Loader2 className="animate-spin" />
					) : (
						<Play />
					)}
					Start
				</Button>
				<Button
					variant="ghost"
					size="sm"
					className="shrink-0"
					onClick={cont}
					disabled={!started || busy}
					title="Continue (dc)"
				>
					<FastForward /> Continue
				</Button>
				<Button
					variant="ghost"
					size="sm"
					className="shrink-0"
					onClick={stepOver}
					disabled={!started || busy}
					title="Step over (dso)"
				>
					<StepForward />
					<span className="hidden sm:inline">Step over</span>
				</Button>
				<Button
					variant="ghost"
					size="sm"
					className="shrink-0"
					onClick={stepIn}
					disabled={!started || busy}
					title="Step into (ds)"
				>
					<StepForward /> Step into
				</Button>
				<Button
					variant={
						selected && bps.some((b) => b.addr === selected.addr)
							? "secondary"
							: "ghost"
					}
					size="sm"
					className="shrink-0"
					onClick={addBp}
					disabled={!selected || !started || busy}
					title="Toggle breakpoint at selected function"
				>
					<Pause />
					{selected && bps.some((b) => b.addr === selected.addr)
						? "Remove breakpoint"
						: "Breakpoint"}
				</Button>
				<Button
					variant="ghost"
					size="icon"
					className="shrink-0"
					onClick={refresh}
					disabled={busy}
					title="Refresh"
				>
					<RefreshCw className={busy ? "animate-spin" : ""} />
				</Button>
				<div className="border-border flex shrink-0 items-center overflow-hidden rounded-md border">
					<button
						type="button"
						className={cn(
							"px-2 py-1 text-[11px]",
							flavor === "intel"
								? "bg-primary text-primary-foreground"
								: "hover:bg-accent",
						)}
						onClick={() => changeFlavor("intel")}
						title="Intel disassembly syntax"
					>
						Intel
					</button>
					<button
						type="button"
						className={cn(
							"px-2 py-1 text-[11px]",
							flavor === "att"
								? "bg-primary text-primary-foreground"
								: "hover:bg-accent",
						)}
						onClick={() => changeFlavor("att")}
						title="AT&T disassembly syntax"
					>
						AT&T
					</button>
				</div>
				<Button
					variant="ghost"
					size="sm"
					className="shrink-0"
					onClick={focusProgram}
					disabled={!started}
					title="Open the program's I/O console in the Shell tab"
				>
					<TerminalSquare /> I/O
				</Button>
				<div className="ml-auto flex shrink-0 items-center gap-1.5">
					{busy && started && (
						<Button
							variant="secondary"
							size="sm"
							className="shrink-0"
							onClick={interrupt}
							title="Interrupt the running program (SIGINT, like Ctrl-C)"
						>
							<Pause />
							Interrupt
						</Button>
					)}
					<Button
						variant="destructive"
						size="sm"
						className="shrink-0"
						onClick={stop}
						disabled={!started && !busy}
						title="Stop the debugger (interrupts a blocked continue first)"
					>
						Stop
					</Button>
				</div>
			</div>

			{err && (
				<div className="border-destructive bg-destructive/10 text-destructive m-2 rounded-md border p-2 font-mono text-[11px] whitespace-pre-wrap">
					{err}
				</div>
			)}

			{/* Program I/O lives in the Shell tab's `program` terminal; this
			    strip keeps the loop discoverable from the debugger view. */}
			{started && busy && (
				<button
					type="button"
					onClick={focusProgram}
					className={cn(
						"border-border bg-card hover:bg-accent mx-2 mt-2 flex shrink-0 items-center gap-2 rounded-md border px-2.5 py-1.5 text-left text-xs",
						awaitingIo && "text-primary border-primary/50",
					)}
				>
					<TerminalSquare className="h-3.5 w-3.5 shrink-0" />
					<span>
						{awaitingIo
							? "Program is waiting for input — Shell ▸ program"
							: "Running — program I/O in the Shell tab"}
					</span>
				</button>
			)}

			<div className="grid min-h-0 flex-1 grid-cols-[1fr_240px] overflow-hidden">
				<div className="scroll-host min-h-0 overflow-auto font-mono text-xs">
					{insns.length === 0 && !started && (
						<div className="text-muted-foreground flex h-full min-h-40 flex-col items-center justify-center gap-2 px-6 text-center text-xs">
							<Play className="text-primary h-5 w-5" />
							<span>
								Start the debugger to inspect execution.
							</span>
						</div>
					)}
					{insns.length === 0 && started && !busy && (
						<div className="text-muted-foreground px-3 py-3 text-xs">
							No instructions available at the current program
							counter.
						</div>
					)}
					{insns.map((op) => (
						<div
							key={op.addr}
							onClick={() => selectFn({ addr: op.addr } as any)}
							className={cn(
								"hover:bg-accent/50 flex cursor-pointer gap-3 px-3 py-px whitespace-nowrap",
								op.addr === pc && "bg-primary/20 text-primary",
								selected?.addr === op.addr && "bg-accent",
							)}
						>
							<span className="w-[18ch] shrink-0 overflow-hidden text-ellipsis">
								{fmtAddr(op.addr)}
							</span>
							<span className="text-muted-foreground w-[18ch] shrink-0 overflow-hidden text-ellipsis">
								{op.bytes ?? ""}
							</span>
							<span ref={op.addr === pc ? pcRef : undefined}>
								{op.text ?? op.disasm ?? ""}
							</span>
						</div>
					))}
				</div>

				<div className="border-border flex min-h-0 flex-col overflow-y-auto border-l">
					<div className="text-muted-foreground border-b px-3 py-1.5 text-[11px] font-semibold tracking-wider uppercase">
						Registers
					</div>
					{regEntries.length === 0 && (
						<div className="text-muted-foreground px-3 py-2 text-[11px]">
							no registers
						</div>
					)}
					{regEntries.map(([k, v]) => (
						<div
							key={k}
							className="hover:bg-accent flex items-center justify-between gap-2 px-3 py-px"
						>
							<span className="text-muted-foreground font-mono">
								{k}
							</span>
							<span className="font-mono">
								{fmtAddr(Number(v))}
							</span>
						</div>
					))}

					<div className="text-muted-foreground mt-3 border-t border-b px-3 py-1.5 text-[11px] font-semibold tracking-wider uppercase">
						Breakpoints
					</div>
					{bps.length === 0 && (
						<div className="text-muted-foreground px-3 py-2 text-[11px]">
							none
						</div>
					)}
					{bps.map((b, i) => (
						<div
							key={i}
							className="hover:bg-accent flex items-center gap-2 px-3 py-1 font-mono"
						>
							<span className="min-w-0 flex-1 truncate">
								{fmtAddr(b.addr)}
							</span>
							<Button
								variant="ghost"
								size="icon"
								className="h-6 w-6"
								onClick={() => void removeBp(b.addr)}
								disabled={busy}
								title={`Remove breakpoint at ${fmtAddr(b.addr)}`}
							>
								<Trash2 className="h-3.5 w-3.5" />
							</Button>
						</div>
					))}
				</div>
			</div>
		</div>
	);
}
