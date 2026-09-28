import {
	DropdownMenu,
	DropdownMenuContent,
	DropdownMenuItem,
	DropdownMenuLabel,
	DropdownMenuSeparator,
	DropdownMenuShortcut,
	DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { WindowControls } from "@/components/WindowControls";
import { buildCommands, MENU_ORDER, type MenuName } from "@/lib/commands";
import { chrome } from "@/lib/chrome";
import {
	groupSections,
	readSections,
	sectionsFor,
	type MenuItem,
} from "@/lib/menuRegistry";

/**
 * The rows of one menu.
 *
 * Read when the menu opens rather than when the bar renders: a dropdown's content
 * is only mounted while it is open, and the commands answer to what is open right
 * now, so a bar that resolved them once at mount would offer a project that was
 * closed an hour ago.
 */
function MenuRows({ menu }: { menu: MenuName }) {
	const rows = groupSections(
		sectionsFor(menu, buildCommands(), readSections()),
	);
	if (rows.length === 0) {
		return <DropdownMenuItem disabled>Nothing here yet</DropdownMenuItem>;
	}
	return (
		<>
			{rows.map((row, i) => {
				if (row.kind === "label") {
					return (
						<DropdownMenuLabel key={`label-${row.label}-${i}`}>
							{row.label}
						</DropdownMenuLabel>
					);
				}
				if (row.kind === "rule") {
					return <DropdownMenuSeparator key={`rule-${i}`} />;
				}
				return <Row key={row.item.id} item={row.item} />;
			})}
		</>
	);
}

/** One menu item, with a tick for the items that show a mode rather than do a thing. */
function Row({ item }: { item: MenuItem }) {
	return (
		<DropdownMenuItem
			disabled={item.disabled}
			onSelect={item.run}
			className={item.checked === undefined ? undefined : "pl-7"}
		>
			<span
				aria-hidden
				className="text-brand -ml-5 w-4 shrink-0 text-center"
			>
				{item.checked ? "✓" : ""}
			</span>
			<span className="truncate">{item.label}</span>
			{item.hint && (
				<DropdownMenuShortcut className="ml-auto">
					{item.hint}
				</DropdownMenuShortcut>
			)}
		</DropdownMenuItem>
	);
}

/** One menu and its trigger. */
function Menu({ menu }: { menu: MenuName }) {
	return (
		<DropdownMenu>
			<DropdownMenuTrigger asChild>
				<button type="button" className={chrome.menuItem}>
					{menu}
				</button>
			</DropdownMenuTrigger>
			<DropdownMenuContent align="start" className="w-64">
				<MenuRows menu={menu} />
			</DropdownMenuContent>
		</DropdownMenu>
	);
}

/**
 * The menu bar across the top of the window.
 *
 * Every command the app has is reachable from here, so the panels below it do not
 * each need a button for their own: a disassembly that offers "Reload" offers it
 * here too, and its toolbar is left holding only what is specific to the thing on
 * screen.
 *
 * A menu with nothing in it is not rendered. `Selection`, `Terminal` and `Help`
 * are absent because nothing is behind them yet, and will appear the moment
 * something is — a header that opens onto an empty panel is worse than no header,
 * because it claims there is nothing here and is right.
 *
 * @example
 * <MenuBar />
 */
export function MenuBar() {
	// Resolved once per render, not per menu: the same command list answers for
	// every menu, and building it four times is four times the store reads.
	const commands = buildCommands();
	const published = readSections();
	const menus = MENU_ORDER.filter(
		(menu) => sectionsFor(menu, commands, published).length > 0,
	);
	if (menus.length === 0) return null;
	return (
		<div className={chrome.menuBar} role="menubar" aria-label="Main menu">
			{menus.map((menu) => (
				<Menu key={menu} menu={menu} />
			))}
			{/* The empty half of the bar drags the window, so the bar behaves like
			    the title bar it replaced. */}
			<div data-tauri-drag-region className="flex-1" />
			<WindowControls />
		</div>
	);
}
