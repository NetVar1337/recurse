import { Loader2 } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api } from "@/api";
import { cn } from "@/lib/utils";
import { useAnalysisStore } from "@/store/analysisStore";

const ROW_BYTES = 16;
const DEFAULT_LEN = 256;
/** The most a single read will return, however large a length is asked for. */
const MAX_LEN = 4096;

/**
 * The byte being typed into, and what has been typed so far.
 *
 * Held apart from `edits` so a half-typed nibble is not mistaken for a value: a
 * staged edit is a fact about the file, and a draft is a fact about the field.
 */
interface Draft {
	offset: number;
	text: string;
}

/**
 * Format a byte as the two hex digits the view shows.
 *
 * @param b - The byte value.
 * @returns Two lowercase hex digits.
 *
 * @example
 * hexByte(0x0a); // => "0a"
 */
function hexByte(b: number): string {
	return b.toString(16).padStart(2, "0");
}

/**
 * Read a staged two-digit hex field, or null when it is not a byte yet.
 *
 * @param text - What is in the field.
 * @returns The byte, or null if the text is not one.
 *
 * @example
 * parseByte("ff"); // => 255
 * parseByte("z");  // => null
 */
function parseByte(text: string): number | null {
	if (!/^[0-9a-fA-F]{1,2}$/.test(text)) return null;
	const v = parseInt(text, 16);
	return Number.isFinite(v) && v >= 0 && v <= 255 ? v : null;
}

function fmtAddr(a: number): string {
	return `0x${a.toString(16).padStart(8, "0")}`;
}

function toAscii(b: number): string {
	return b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".";
}

/**
 * Read-and-patch hex view over `Engine::read_bytes`/`write_bytes`. Edits
 * are staged locally (shown with a highlight) until "Apply patch", which
 * writes the changed bytes straight to the file on disk — the session's
 * cached analysis is not re-derived from the patch (see the host's
 * `write_bytes` doc comment), so disassembly/decompile elsewhere in the
 * app will not reflect it until the binary is reopened. That is called
 * out in the panel itself, not left implicit.
 */
export function HexPanel() {
	const selected = useAnalysisStore((s) => s.selected);
	// Seeded once from whatever function is selected when the panel first
	// mounts (a lazy initializer, not an effect — it never re-seeds on a
	// later selection change, matching the original "only on first mount"
	// intent without a synchronous setState-in-effect).
	const [addrInput, setAddrInput] = useState(() =>
		selected ? fmtAddr(selected.addr) : "",
	);
	const [lenInput, setLenInput] = useState(String(DEFAULT_LEN));
	const [baseAddr, setBaseAddr] = useState<number | null>(null);
	const [bytes, setBytes] = useState<number[] | null>(null);
	const [edits, setEdits] = useState<Map<number, number>>(new Map());
	const [draft, setDraft] = useState<Draft | null>(null);
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [status, setStatus] = useState<string | null>(null);

	const parseAddr = (s: string): number | null => {
		const t = s.trim();
		if (!t) return null;
		const n = t.startsWith("0x") ? parseInt(t, 16) : parseInt(t, 10);
		return Number.isFinite(n) ? n : null;
	};

	const load = async () => {
		const addr = parseAddr(addrInput);
		const len = parseInt(lenInput, 10);
		if (addr === null || !Number.isFinite(len) || len <= 0) {
			setError("enter a valid address and length");
			return;
		}
		setLoading(true);
		setError(null);
		setStatus(null);
		try {
			const data = await api.readBytes(addr, Math.min(len, MAX_LEN));
			setBaseAddr(addr);
			setBytes(data);
			setEdits(new Map());
			setDraft(null);
		} catch (e) {
			setError(String(e));
		} finally {
			setLoading(false);
		}
	};

	// One field is live at a time, not one per byte. A 4 KB read is four thousand
	// controlled inputs, and typing a single hex digit re-reconciled every one of
	// them; here the draft is the only input in the view and nothing else moves.
	const beginEdit = (offset: number, current: number) => {
		setDraft({ offset, text: hexByte(current) });
	};

	const commitDraft = () => {
		if (draft === null) return;
		const value = parseByte(draft.text);
		setDraft(null);
		if (value === null) return;
		setEdits((prev) => {
			const next = new Map(prev);
			next.set(draft.offset, value);
			return next;
		});
	};

	const cancelDraft = () => setDraft(null);

	const applyPatch = async () => {
		if (baseAddr === null || edits.size === 0) return;
		setStatus(null);
		setError(null);
		// Patch contiguous runs so a scattered edit set becomes as few
		// write_bytes calls as possible, in ascending address order.
		const offsets = [...edits.keys()].sort((a, b) => a - b);
		try {
			let i = 0;
			while (i < offsets.length) {
				let j = i;
				while (
					j + 1 < offsets.length &&
					offsets[j + 1] === offsets[j] + 1
				) {
					j++;
				}
				const runOffsets = offsets.slice(i, j + 1);
				const runBytes = runOffsets.map((o) => edits.get(o) ?? 0);
				await api.writeBytes(baseAddr + runOffsets[0], runBytes);
				i = j + 1;
			}
			setStatus(
				`patched ${edits.size} byte${edits.size === 1 ? "" : "s"} on disk — reopen the binary to see it reflected in disassembly`,
			);
			setEdits(new Map());
			await load();
		} catch (e) {
			setError(String(e));
		}
	};

	const rows: { addr: number; row: number[] }[] = [];
	if (bytes && baseAddr !== null) {
		for (let i = 0; i < bytes.length; i += ROW_BYTES) {
			rows.push({
				addr: baseAddr + i,
				row: bytes.slice(i, i + ROW_BYTES),
			});
		}
	}

	return (
		<div className="flex min-h-0 flex-1 flex-col">
			<div className="border-border bg-card flex items-center gap-2 border-b px-3 py-1.5">
				<Input
					value={addrInput}
					onChange={(e) => setAddrInput(e.target.value)}
					placeholder="address (0x…)"
					className="h-7 w-36 font-mono text-xs"
					onKeyDown={(e) => e.key === "Enter" && void load()}
				/>
				<Input
					value={lenInput}
					onChange={(e) => setLenInput(e.target.value)}
					placeholder="length"
					className="h-7 w-20 font-mono text-xs"
					onKeyDown={(e) => e.key === "Enter" && void load()}
				/>
				<Button size="sm" variant="outline" onClick={() => void load()}>
					Load
				</Button>
				{edits.size > 0 && (
					<>
						<div className="bg-border mx-1 h-5 w-px" />
						<span className="text-muted-foreground text-[11px]">
							{edits.size} unsaved edit
							{edits.size === 1 ? "" : "s"}
						</span>
						<Button size="sm" onClick={() => void applyPatch()}>
							Apply patch
						</Button>
						<Button
							size="sm"
							variant="ghost"
							onClick={() => {
								setEdits(new Map());
								setDraft(null);
							}}
						>
							Discard
						</Button>
					</>
				)}
				{loading && (
					<Loader2 className="text-muted-foreground h-3.5 w-3.5 animate-spin" />
				)}
			</div>

			{error && (
				<div className="border-destructive bg-destructive/10 text-destructive border-b px-3 py-2 text-[11px]">
					{error}
				</div>
			)}
			{status && (
				<div className="border-border bg-primary/10 border-b px-3 py-2 text-[11px]">
					{status}
				</div>
			)}

			<div className="scroll-host min-h-0 flex-1 overflow-auto p-3 font-mono text-[11px]">
				{!bytes ? (
					<div className="text-muted-foreground">
						Enter an address and length, then Load. Try editing a
						byte's hex value and Apply patch to write it directly to
						the file on disk.
					</div>
				) : (
					<table className="border-separate border-spacing-y-0.5">
						<tbody>
							{rows.map(({ addr, row }) => (
								<tr key={addr} className="offscreen-row">
									<td className="text-muted-foreground pr-3 align-top select-none">
										{fmtAddr(addr)}
									</td>
									<td className="pr-1.5 align-top whitespace-pre">
										{row.map((b, i) => {
											const offset = addr - baseAddr! + i;
											const edited = edits.has(offset);
											const value =
												edits.get(offset) ?? b;
											const editing =
												draft?.offset === offset;
											return (
												<span
													key={i}
													onClick={() =>
														beginEdit(offset, value)
													}
													className={cn(
														"w-[2ch] cursor-text text-center",
														edited &&
															"text-primary font-bold underline decoration-dotted",
													)}
												>
													{editing ? (
														<input
															autoFocus
															value={draft.text}
															onChange={(e) =>
																setDraft({
																	offset,
																	text: e.target.value.slice(
																		0,
																		2,
																	),
																})
															}
															onFocus={(e) =>
																e.currentTarget.select()
															}
															onBlur={commitDraft}
															onKeyDown={(e) => {
																if (
																	e.key ===
																	"Enter"
																)
																	commitDraft();
																if (
																	e.key ===
																	"Escape"
																)
																	cancelDraft();
															}}
															maxLength={2}
															className="text-primary w-[2ch] bg-transparent text-center font-bold outline-none"
														/>
													) : (
														hexByte(value)
													)}
												</span>
											);
										})}
									</td>
									<td className="text-muted-foreground pl-3 align-top select-none">
										{row
											.map((b, i) =>
												toAscii(
													edits.get(
														addr - baseAddr! + i,
													) ?? b,
												),
											)
											.join("")}
									</td>
								</tr>
							))}
						</tbody>
					</table>
				)}
			</div>
		</div>
	);
}
