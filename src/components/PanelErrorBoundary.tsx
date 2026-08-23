import { Component, type ErrorInfo, type ReactNode } from "react";

import { Button } from "@/components/ui/button";

interface Props {
	children: ReactNode;
	/** Short label shown in the fallback card (e.g. the panel name). */
	label: string;
}

interface State {
	error: Error | null;
}

/**
 * Local error boundary for lazy panels: a crash in one panel (bad payload,
 * render-time throw) degrades to an inline error card instead of
 * white-screening the whole app. Remounts its subtree when `label` changes or
 * when the user hits Retry.
 */
export class PanelErrorBoundary extends Component<Props, State> {
	state: State = { error: null };

	static getDerivedStateFromError(error: Error): State {
		return { error };
	}

	componentDidCatch(error: Error, info: ErrorInfo) {
		console.error(`[${this.props.label}] crashed:`, error, info.componentStack);
	}

	render() {
		const { error } = this.state;
		if (error) {
			return (
				<div className="border-destructive bg-destructive/10 m-2 flex flex-col items-start gap-2 rounded-md border p-3">
					<div className="text-destructive text-xs font-semibold">
						{this.props.label} crashed
					</div>
					<pre className="text-destructive/80 max-h-32 overflow-auto font-mono text-[11px] whitespace-pre-wrap">
						{error.message}
					</pre>
					<Button
						size="sm"
						variant="secondary"
						onClick={() => this.setState({ error: null })}
					>
						Retry
					</Button>
				</div>
			);
		}
		return this.props.children;
	}
}
