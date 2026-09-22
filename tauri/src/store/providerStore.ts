import { create } from "zustand";

import { api } from "../api";
import type { ProviderStatus } from "../types";

type LoginStage =
	| "idle"
	| "anthropic-waiting-for-code"
	| "anthropic-exchanging"
	| "copilot-waiting-for-approval"
	| "error";

interface ProviderState {
	providers: ProviderStatus[];
	loading: boolean;
	error: string | null;

	// Anthropic (Claude Pro/Max) OAuth flow state.
	loginStage: LoginStage;
	loginError: string | null;
	anthropicAuthorizeUrl: string | null;
	anthropicVerifier: string | null;

	// GitHub Copilot device-flow state.
	copilotUserCode: string | null;
	copilotVerificationUri: string | null;

	refresh: () => Promise<void>;
	saveApiKey: (id: string, key: string) => Promise<void>;
	clearCredential: (id: string) => Promise<void>;
	setActive: (id: string) => Promise<void>;

	startAnthropicLogin: () => Promise<void>;
	submitAnthropicCode: (pastedCode: string) => Promise<void>;
	cancelLogin: () => void;

	startCopilotLogin: () => Promise<void>;
}

export const useProviderStore = create<ProviderState>((set, get) => ({
	providers: [],
	loading: false,
	error: null,

	loginStage: "idle",
	loginError: null,
	anthropicAuthorizeUrl: null,
	anthropicVerifier: null,

	copilotUserCode: null,
	copilotVerificationUri: null,

	refresh: async () => {
		set({ loading: true, error: null });
		try {
			const providers = await api.providersList();
			set({ providers });
		} catch (e) {
			set({ error: String(e) });
		} finally {
			set({ loading: false });
		}
	},

	saveApiKey: async (id, key) => {
		await api.providerSaveApiKey(id, key);
		await api.providerSetActive(id);
		await get().refresh();
	},

	clearCredential: async (id) => {
		await api.providerClearCredential(id);
		await get().refresh();
	},

	setActive: async (id) => {
		await api.providerSetActive(id);
		await get().refresh();
	},

	startAnthropicLogin: async () => {
		set({
			loginStage: "anthropic-waiting-for-code",
			loginError: null,
			anthropicAuthorizeUrl: null,
			anthropicVerifier: null,
		});
		try {
			const start = await api.anthropicOauthStart();
			set({
				anthropicAuthorizeUrl: start.authorize_url,
				anthropicVerifier: start.verifier,
			});
			// Best-effort: open the system browser. The URL is also shown
			// in the UI so the user can copy it manually if this fails
			// (e.g. no default browser registered).
			window.open(start.authorize_url, "_blank", "noopener,noreferrer");
		} catch (e) {
			set({ loginStage: "error", loginError: String(e) });
		}
	},

	submitAnthropicCode: async (pastedCode) => {
		const verifier = get().anthropicVerifier;
		if (!verifier) {
			set({ loginStage: "error", loginError: "no login in progress" });
			return;
		}
		set({ loginStage: "anthropic-exchanging", loginError: null });
		try {
			await api.anthropicOauthFinish(pastedCode.trim(), verifier);
			set({
				loginStage: "idle",
				anthropicAuthorizeUrl: null,
				anthropicVerifier: null,
			});
			await get().refresh();
		} catch (e) {
			set({ loginStage: "error", loginError: String(e) });
		}
	},

	cancelLogin: () =>
		set({
			loginStage: "idle",
			loginError: null,
			anthropicAuthorizeUrl: null,
			anthropicVerifier: null,
			copilotUserCode: null,
			copilotVerificationUri: null,
		}),

	startCopilotLogin: async () => {
		set({
			loginStage: "copilot-waiting-for-approval",
			loginError: null,
			copilotUserCode: null,
			copilotVerificationUri: null,
		});
		try {
			const start = await api.githubCopilotDeviceStart();
			set({
				copilotUserCode: start.user_code,
				copilotVerificationUri: start.verification_uri,
			});
			window.open(
				start.verification_uri,
				"_blank",
				"noopener,noreferrer",
			);
			// One long-lived await: the backend polls internally until the
			// user approves (or the code expires) and resolves once, so
			// there is no frontend-side polling loop to manage.
			await api.githubCopilotDeviceFinish(
				start.device_code,
				start.interval_secs,
				start.expires_in_secs,
			);
			set({
				loginStage: "idle",
				copilotUserCode: null,
				copilotVerificationUri: null,
			});
			await get().refresh();
		} catch (e) {
			set({ loginStage: "error", loginError: String(e) });
		}
	},
}));
