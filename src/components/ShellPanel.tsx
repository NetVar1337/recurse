import { useCallback, useEffect, useRef, useState } from "react";
import {
	Plus,
	SquareTerminal,
	Terminal as TerminalIcon,
	X,
} from "lucide-react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import "@xterm/xterm/css/xterm.css";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { api } from "@/api";
import { useDebugStore } from "@/store/debugStore";
import type { ShellInfo } from "@/types";

interface TermRef {
	term: Terminal;
	fit: FitAddon;
}

/** Tab keys: real shells are numeric ids; the debuggee console is pinned. */
type TabKey = number | "program";

export function ShellPanel({ active }: { active: boolean }) {
	const [tabs, setTabs] = useState<ShellInfo[]>([]);
	const started = useDebugStore((s) => s.started);
	const ioFocusTick = useDebugStore((s) => s.ioFocusTick);
	const [activeId, setActiveId] = useState<TabKey | null>(() =>
		useDebugStore.getState().started ? "program" : null,
	);
	const termsRef = useRef(new Map<number, TermRef>());
	const tabsRef = useRef<ShellInfo[]>([]);
	const hostRef = useRef<HTMLDivElement>(null);

	// React to debug-store transitions by adjusting state during render (the
	// documented pattern — no cascading effect renders): a fresh session or
	// a focus request selects the program terminal.
	const [synced, setSynced] = useState(() => ({
		started: useDebugStore.getState().started,
		tick: useDebugStore.getState().ioFocusTick,
	}));
	if (synced.started !== started || synced.tick !== ioFocusTick) {
		setSynced({ started, tick: ioFocusTick });
		if (started) setActiveId("program");
	}

	useEffect(() => {
		tabsRef.current = tabs;
	}, [tabs]);

	const removeTab = useCallback((id: number) => {
		const t = termsRef.current.get(id);
		if (t) {
			t.term.dispose();
			termsRef.current.delete(id);
		}
		const next = tabsRef.current.filter((x) => x.id !== id);
		tabsRef.current = next;
		setTabs(next);
		setActiveId((cur) =>
			cur === id ? (next[next.length - 1]?.id ?? null) : cur,
		);
	}, []);

	useEffect(() => {
		const unlisteners: UnlistenFn[] = [];
		let disposed = false;

		const track = (p: Promise<UnlistenFn>) => {
			p.then((u) => {
				if (disposed) u();
				else unlisteners.push(u);
			});
		};

		track(
			listen("shell-output", (e) => {
				const { id, data } = e.payload as { id: number; data: string };
				termsRef.current.get(id)?.term.write(data);
			}),
		);
		track(
			listen("shell-exit", (e) => {
				const { id } = e.payload as { id: number };
				removeTab(id);
			}),
		);

		return () => {
			disposed = true;
			unlisteners.forEach((u) => u());
		};
	}, [removeTab]);

	const spawn = async () => {
		try {
			const info = await api.shellSpawn();
			setTabs((t) => [...t, info]);
			setActiveId(info.id);
		} catch {
			/* ignore spawn errors */
		}
	};

	const close = (id: number) => {
		api.shellKill(id);
		removeTab(id);
	};

	const makeTerm = () => {
		const term = new Terminal({
			fontSize: 12,
			fontFamily:
				'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace',
			cursorBlink: true,
			scrollback: 5000,
			theme: {
				background: "#0c0c0c",
				foreground: "#d4d4d4",
				cursor: "#d4d4d4",
			},
		});
		const fit = new FitAddon();
		term.loadAddon(fit);
		return { term, fit };
	};

	const attachTerminal = (id: number) => (el: HTMLDivElement | null) => {
		if (!el) {
			// React 18 StrictMode remounts elements in dev: dispose the old
			// instance so the re-attach creates a terminal on the fresh DOM
			// node instead of silently keeping one bound to a discarded node.
			const t = termsRef.current.get(id);
			if (t) {
				t.term.dispose();
				termsRef.current.delete(id);
			}
			return;
		}
		if (termsRef.current.has(id)) return;
		const { term, fit } = makeTerm();
		term.open(el);
		term.onData((d) => {
			api.shellWrite(id, d);
		});
		termsRef.current.set(id, { term, fit });
		fit.fit();
		api.shellResize(id, term.rows, term.cols);
	};

	// Refit the active terminal when it becomes visible or the active shell
	// changes (display:none containers report 0 size otherwise). The program
	// terminal fits itself in ProgramHost.
	useEffect(() => {
		if (!active || typeof activeId !== "number") return;
		const raf = requestAnimationFrame(() => {
			const t = termsRef.current.get(activeId);
			if (t) {
				t.fit.fit();
				api.shellResize(activeId, t.term.rows, t.term.cols);
			}
		});
		return () => cancelAnimationFrame(raf);
	}, [active, activeId]);

	// Keep every terminal fitted on container resize.
	useEffect(() => {
		const el = hostRef.current;
		if (!el) return;
		const ro = new ResizeObserver(() => {
			for (const [id, t] of termsRef.current) {
				t.fit.fit();
				api.shellResize(id, t.term.rows, t.term.cols);
			}
		});
		ro.observe(el);
		return () => ro.disconnect();
	}, []);

	return (
		<div className="flex h-full min-h-0 flex-col">
			<div className="border-border flex items-center gap-0.5 border-b px-1.5 py-1">
				{started && (
					<div
						className={cn(
							"flex items-center gap-1 rounded px-1 py-0.5 text-xs",
							activeId === "program"
								? "bg-accent"
								: "hover:bg-accent",
						)}
					>
						<button
							type="button"
							className="flex items-center gap-1.5 px-1"
							onClick={() => setActiveId("program")}
							title="I/O console of the program being debugged"
						>
							<SquareTerminal className="text-primary h-3 w-3" />
							program
						</button>
					</div>
				)}
				{tabs.map((t) => (
					<div
						key={t.id}
						className={cn(
							"group flex items-center gap-1 rounded px-1 py-0.5 text-xs",
							t.id === activeId ? "bg-accent" : "hover:bg-accent",
						)}
					>
						<button
							type="button"
							className="flex items-center gap-1.5 px-1"
							onClick={() => setActiveId(t.id)}
						>
							<TerminalIcon className="h-3 w-3" />
							{t.name}
						</button>
						<button
							type="button"
							className="text-muted-foreground hover:text-foreground opacity-0 transition-opacity group-hover:opacity-100"
							onClick={() => close(t.id)}
							title="Close shell"
						>
							<X className="h-3 w-3" />
						</button>
					</div>
				))}
				<Button
					variant="ghost"
					size="icon"
					className="h-6 w-6"
					onClick={spawn}
					title="New shell"
				>
					<Plus className="h-3.5 w-3.5" />
				</Button>
			</div>

			<div ref={hostRef} className="relative min-h-0 flex-1 bg-black p-1">
				{tabs.length === 0 && !started && (
					<div className="text-muted-foreground flex h-full items-center justify-center">
						<Button variant="ghost" onClick={spawn}>
							<Plus /> New shell
						</Button>
					</div>
				)}
				{tabs.map((t) => (
					<div
						key={t.id}
						ref={attachTerminal(t.id)}
						className={cn(
							"absolute inset-0",
							t.id !== activeId && "hidden",
						)}
					/>
				))}
				{started && <ProgramHost active={activeId === "program"} />}
			</div>
		</div>
	);
}

const PROGRAM_THEME = {
	background: "#0c0c0c",
	foreground: "#d4d4d4",
	cursor: "#22d3ee",
};

/**
 * I/O console of the program being debugged: streams `debug-output` chunks
 * into a real terminal and feeds keystrokes back through the stdin FIFO.
 *
 * The debuggee's stdio is a FIFO pair (not a PTY), so this component
 * provides the line discipline a tty normally would: local echo with
 * backspace editing, Enter commits the line to stdin, Ctrl-C interrupts a
 * blocked continue.
 */
function ProgramHost({ active }: { active: boolean }) {
	const hostRef = useRef<HTMLDivElement>(null);
	const termRef = useRef<TermRef | null>(null);

	useEffect(() => {
		const el = hostRef.current;
		if (!el) return;

		const term = new Terminal({
			fontSize: 12,
			fontFamily:
				'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace',
			cursorBlink: true,
			scrollback: 5000,
			theme: PROGRAM_THEME,
		});
		const fit = new FitAddon();
		term.loadAddon(fit);
		term.open(el);
		termRef.current = { term, fit };

		// Subscribe first, then bootstrap: chunks arriving during the seed
		// fetch are queued so nothing is lost or printed twice.
		const pending: string[] = [];
		let streaming = false;
		let disposed = false;
		let unlisten: UnlistenFn | null = null;

		void listen<{ data: string }>("debug-output", (ev) => {
			if (!ev.payload?.data) return;
			if (streaming) {
				term.write(ev.payload.data);
			} else {
				pending.push(ev.payload.data);
			}
		}).then((u) => {
			if (disposed) {
				u();
				return;
			}
			unlisten = u;
			api.debugOutputGet()
				.then((seed) => {
					if (disposed) return;
					if (seed) term.write(seed);
				})
				.catch(() => {})
				.finally(() => {
					for (const chunk of pending.splice(0)) {
						term.write(chunk);
					}
					streaming = true;
				});
		});

		let lineBuf = "";
		const dataSub = term.onData((d) => {
			for (const ch of d) {
				if (ch === "\r") {
					term.write("\r\n");
					const line = lineBuf;
					lineBuf = "";
					api.debugStdin(`${line}\n`).catch(() => {});
				} else if (ch === "\u007f") {
					if (lineBuf.length > 0) {
						lineBuf = lineBuf.slice(0, -1);
						term.write("\b \b");
					}
				} else if (ch === "\u0003") {
					term.write("^C\r\n");
					api.debugInterrupt().catch(() => {});
				} else if (ch >= " ") {
					lineBuf += ch;
					term.write(ch);
				}
			}
		});

		const ro = new ResizeObserver(() => {
			if (!active) return;
			fit.fit();
		});
		ro.observe(el);

		return () => {
			disposed = true;
			unlisten?.();
			dataSub.dispose();
			ro.disconnect();
			term.dispose();
			termRef.current = null;
		};
		// Mount-scoped: one terminal per debug session (parent unmounts us
		// when the session stops). eslint-disable because `active` is
		// deliberately excluded from deps.
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, []);

	// Refit when revealed by a tab switch (0-size while display:none).
	useEffect(() => {
		if (!active) return;
		const raf = requestAnimationFrame(() => termRef.current?.fit.fit());
		return () => cancelAnimationFrame(raf);
	}, [active]);

	return (
		<div
			ref={hostRef}
			className={cn("absolute inset-0", !active && "hidden")}
		/>
	);
}
