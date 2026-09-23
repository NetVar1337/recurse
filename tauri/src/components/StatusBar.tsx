import { useAnalysisStore } from "@/store/analysisStore";
import { useBinaryStore } from "@/store/binaryStore";
import { useDebugStore } from "@/store/debugStore";
import { useSettingsStore } from "@/store/settingsStore";

function fmtAddr(a?: number | null): string {
	return typeof a === "number" ? `0x${a.toString(16)}` : "";
}

function Item({ children }: { children: React.ReactNode }) {
	return <span className="whitespace-nowrap">{children}</span>;
}

/**
 * The bottom status strip: backend, architecture, analysis counts, the current
 * selection, and live debug state. One line of high-signal facts, always
 * visible, so the toolbar can stay clean.
 */
export function StatusBar() {
	const bin = useBinaryStore((s) => s.binary);
	const funcCount = useAnalysisStore((s) => s.funcs.length);
	const stringCount = useAnalysisStore((s) => s.strings.length);
	const selected = useAnalysisStore((s) => s.selected);
	const backend = useSettingsStore((s) => s.backend);
	const indexing = useBinaryStore((s) => s.indexing);
	const dbgActive = useDebugStore((s) => s.active);
	const dbgState = useDebugStore((s) => s.state);
	const pc = useDebugStore((s) => s.registers?.pc ?? null);

	const info = bin?.info?.bin;
	const file = bin?.path.split(/[\\/]/).pop();

	return (
		<footer className="border-border bg-card text-muted-foreground nums text-2xs flex h-[var(--status-h)] shrink-0 items-center gap-3 border-t px-3">
			<Item>
				<span className="text-brand font-medium">{backend}</span>
			</Item>
			{bin && (
				<>
					<span className="opacity-40">·</span>
					<Item>
						{info?.arch ?? "?"}{" "}
						{info?.bits ? `${info.bits}bit` : ""}
					</Item>
					<span className="opacity-40">·</span>
					<Item>
						{funcCount}
						{indexing ? "+" : ""} funcs
					</Item>
					<Item>{stringCount} strings</Item>
				</>
			)}

			<div className="ml-auto flex items-center gap-3">
				{file && <Item>{file}</Item>}
				{selected && (
					<Item>
						sel{" "}
						<span className="text-foreground">
							{fmtAddr(selected.addr)}
						</span>
					</Item>
				)}
				{dbgActive && (
					<Item>
						<span className="text-brand">●</span> {dbgState}
						{pc != null ? ` ${fmtAddr(pc)}` : ""}
					</Item>
				)}
			</div>
		</footer>
	);
}
