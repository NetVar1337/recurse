import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";
import { Slider } from "@/components/ui/slider";
import { chrome } from "@/lib/chrome";
import { cn } from "@/lib/utils";
import {
	DEBUG_CONTEXT_DEFAULT,
	DEBUG_CONTEXT_MAX,
	DEBUG_CONTEXT_MIN,
	useSettingsStore,
} from "@/store/settingsStore";

/**
 * Debugger settings, opened from the header's Settings menu.
 *
 * The CPU view's context depth is a drag rather than a stepper because the
 * useful range is wide — none at all, a couple of instructions to orient by, or
 * most of the pane for a long block — and the interesting values are spread
 * across it. Dragging covers the whole range in one gesture while the native
 * control keeps arrow keys, Home/End and page steps working.
 *
 * The value is written to the store on every change rather than on release, so
 * the CPU view updates live under the dialog as the slider moves.
 */
export function DebuggerSettingsDialog({
	open,
	onOpenChange,
}: {
	open: boolean;
	onOpenChange: (open: boolean) => void;
}) {
	const depth = useSettingsStore((s) => s.debugContext);
	const setDepth = useSettingsStore((s) => s.setDebugContext);
	const reset = useSettingsStore((s) => s.resetDebugContext);

	return (
		<Dialog open={open} onOpenChange={onOpenChange}>
			<DialogContent className="max-w-sm gap-4 p-4">
				<DialogTitle className={chrome.label}>Debugger</DialogTitle>

				<div className="flex flex-col gap-1.5">
					<div className="flex items-baseline justify-between gap-2">
						<label
							htmlFor="debug-context-depth"
							className="text-xs font-medium"
						>
							Context above PC
						</label>
						<span
							className={cn(
								chrome.nums,
								"text-foreground text-xs",
								depth === DEBUG_CONTEXT_DEFAULT &&
									"text-muted-foreground",
							)}
						>
							{depth}
						</span>
					</div>
					<Slider
						id="debug-context-depth"
						label="Context above PC"
						value={depth}
						min={DEBUG_CONTEXT_MIN}
						max={DEBUG_CONTEXT_MAX}
						onValueChange={setDepth}
					/>
					<div className="text-muted-foreground text-2xs flex justify-between">
						<span>{DEBUG_CONTEXT_MIN}</span>
						<span>
							keep {depth} instruction{depth === 1 ? "" : "s"} of
							context above the program counter
						</span>
						<span>{DEBUG_CONTEXT_MAX}</span>
					</div>
					<p className="text-muted-foreground text-2xs">
						Those rows are the code that leads into the program
						counter, not a record of what ran — a debugger only sees
						the program between stops. The instruction the counter
						is on says which way it is about to go, and shows the
						branch target inline.
					</p>
				</div>

				<div className="flex justify-end">
					<button
						type="button"
						onClick={reset}
						disabled={depth === DEBUG_CONTEXT_DEFAULT}
						className="text-muted-foreground hover:text-foreground text-xs disabled:opacity-50"
					>
						Reset to {DEBUG_CONTEXT_DEFAULT}
					</button>
				</div>
			</DialogContent>
		</Dialog>
	);
}
