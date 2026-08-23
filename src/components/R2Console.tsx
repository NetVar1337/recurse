import { useCallback, useEffect, useRef, useState } from "react";
import { CornerDownLeft, Trash2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import { api } from "@/api";

interface Line {
	cmd: string;
	out: string;
	err?: boolean;
}

const HISTORY_KEY = "recurse.r2History";
const MAX_LINES = 400;

function loadHistory(): string[] {
	try {
		const raw = localStorage.getItem(HISTORY_KEY);
		const arr = raw ? (JSON.parse(raw) as unknown) : [];
		return Array.isArray(arr) ? arr.filter((x): x is string => typeof x === "string") : [];
	} catch {
		return [];
	}
}

/**
 * Raw r2 passthrough console — the escape hatch exposing the full radare2
 * command surface from the UI. Commands run against the analysis session.
 */
export function R2Console() {
	const [lines, setLines] = useState<Line[]>([]);
	const [input, setInput] = useState("");
	const [running, setRunning] = useState(false);
	const [history, setHistory] = useState<string[]>(loadHistory);
	const [histIdx, setHistIdx] = useState<number | null>(null);
	const endRef = useRef<HTMLDivElement>(null);

	useEffect(() => {
		endRef.current?.scrollIntoView({ block: "end" });
	}, [lines]);

	const send = useCallback(
		async (cmd: string) => {
			const trimmed = cmd.trim();
			if (!trimmed || running) return;
			setRunning(true);
			setInput("");
			setHistIdx(null);
			try {
				const out = await api.raw(trimmed);
				const text = typeof out === "string" ? out : JSON.stringify(out, null, 1);
				setLines((prev) =>
					[...prev, { cmd: trimmed, out: text || "(empty)" }].slice(-MAX_LINES),
				);
				const next = [trimmed, ...history.filter((h) => h !== trimmed)].slice(0, 100);
				setHistory(next);
				localStorage.setItem(HISTORY_KEY, JSON.stringify(next));
			} catch (e) {
				setLines((prev) =>
					[...prev, { cmd: trimmed, out: String(e), err: true }].slice(-MAX_LINES),
				);
			} finally {
				setRunning(false);
			}
		},
		[history, running],
	);

	const onKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
		if (e.key === "Enter" && !e.shiftKey) {
			e.preventDefault();
			void send(input);
		} else if (e.key === "ArrowUp" && history.length > 0) {
			e.preventDefault();
			const next = histIdx === null ? 0 : Math.min(histIdx + 1, history.length - 1);
			setHistIdx(next);
			setInput(history[next]);
		} else if (e.key === "ArrowDown" && histIdx !== null) {
			e.preventDefault();
			const next = histIdx - 1;
			if (next < 0) {
				setHistIdx(null);
				setInput("");
			} else {
				setHistIdx(next);
				setInput(history[next]);
			}
		}
	};

	return (
		<div className="flex h-full min-h-0 flex-col">
			<div className="scroll-host min-h-0 flex-1 overflow-auto font-mono text-xs">
				{lines.length === 0 && (
					<div className="text-muted-foreground px-3 py-3">
						Raw radare2 passthrough. Examples: <code>aflj</code>,{" "}
						<code>pdf @ sym.main</code>, <code>axtj @ 0x401000</code>,{" "}
						<code>iz~password</code>. Output is JSON when the command ends in{" "}
						<code>j</code>.
					</div>
				)}
				{lines.map((l, i) => (
					<div key={i} className="px-3 py-0.5 whitespace-pre-wrap break-all">
						<span className="text-primary">&gt; </span>
						<span className="text-foreground">{l.cmd}</span>
						<pre
							className={
								l.err
									? "text-destructive mt-0.5"
									: "text-muted-foreground mt-0.5"
							}
						>
							{l.out}
						</pre>
					</div>
				))}
				<div ref={endRef} />
			</div>
			<div className="border-border flex items-start gap-2 border-t px-2 py-2">
				<textarea
					value={input}
					onChange={(e) => setInput(e.target.value)}
					onKeyDown={onKeyDown}
					rows={1}
					placeholder="r2 command…"
					className="h-8 min-h-8 resize-none bg-transparent px-1 py-1 font-mono text-xs focus-visible:ring-0"
				/>
				<Button
					size="icon"
					variant="ghost"
					className="h-7 w-7 shrink-0"
					onClick={() => setLines([])}
					title="Clear output"
				>
					<Trash2 className="h-3.5 w-3.5" />
				</Button>
				<Button
					size="icon"
					className="h-7 w-7 shrink-0"
					onClick={() => void send(input)}
					disabled={!input.trim() || running}
					title="Run (Enter)"
				>
					<CornerDownLeft className="h-3.5 w-3.5" />
				</Button>
			</div>
		</div>
	);
}
