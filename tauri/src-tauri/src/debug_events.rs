//! The debugger's push surface: what the window is told, as it happens.
//!
//! The UI used to learn about a stop by asking. Output came from a 400 ms poll,
//! the session's own view from a 500 ms poll, and the trace from a 1 s poll —
//! so a stop was up to half a second late, the transcript trailed a program
//! that was trying to talk to you, and an idle `continue` still cost a poll
//! every 400 ms for as long as it ran.
//!
//! None of that is a property of the data. A view of the session is republished
//! by the thread that owns it, and the debuggee's output arrives on its reader
//! thread, so both are already produced whether anyone is listening. This
//! module carries them out to the window: a [`Channel`] the UI registers once,
//! and one forwarding thread per debug session that pumps the session's own
//! event stream into it.
//!
//! The stream is a broadcast, not a second reader. The agent's `output` op still
//! drains the buffer, and the window still sees everything printed: two
//! listeners for one program's output is the point, not a race.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use serde::Serialize;
use tauri::ipc::Channel;

use crate::AppState;

/// What the window is told, as it happens.
///
/// A superset of the session's own events, because one thing worth watching
/// happens outside the session: the stop timeline grows, and it can be cleared.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum DebugEvent {
    /// The session published a new view of itself.
    Snapshot { snapshot: serde_json::Value },
    /// The debuggee printed this.
    Output { text: String },
    /// A stop was appended to the timeline.
    TraceAppended { entry: serde_json::Value },
    /// The timeline was cleared.
    TraceCleared,
}

/// One event, stamped with the session that produced it.
///
/// A forwarder can have an event in flight when a relaunch replaces the session
/// under it, and the window's transcript is per process. The stamp is what lets
/// the window drop what belongs to a session that has gone, which is the same
/// thing a polled reply had to be careful about.
#[derive(Clone, Debug, Serialize)]
pub struct Envelope {
    /// Counts the debug sessions this window has been sent events for.
    pub gen: u64,
    #[serde(flatten)]
    pub event: DebugEvent,
}

/// The window's end of the push surface, registered once per view.
pub type EventChannel = Channel<Envelope>;

/// The state behind [`Events`].
#[derive(Default)]
struct Inner {
    /// The window's channel, if one is listening.
    channel: Mutex<Option<EventChannel>>,
    /// The session the running forwarder was started for, and which generation
    /// it stamps its events with. Held weakly: a forwarder ends because its
    /// session is dropped, so this must not be what keeps that session alive.
    forwarding: Mutex<Option<(Weak<recurse_debug::Debugger>, u64)>>,
    /// Counts sessions, so a stale event can be recognised as stale.
    gen: AtomicU64,
}

/// A cheap handle to the push surface, shareable with the forwarding thread.
#[derive(Clone, Default)]
pub struct Events(Arc<Inner>);

impl Events {
    /// Nothing registered yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register the window's channel.
    pub fn subscribe(&self, on_event: EventChannel) {
        if let Ok(mut slot) = self.0.channel.lock() {
            *slot = Some(on_event);
        }
    }

    /// Forget the window's channel, so a closed view is not written to.
    pub fn unsubscribe(&self) {
        if let Ok(mut slot) = self.0.channel.lock() {
            *slot = None;
        }
    }

    /// Send `event` for the session currently being forwarded.
    pub fn send(&self, event: DebugEvent) {
        let gen = self
            .0
            .forwarding
            .lock()
            .ok()
            .and_then(|f| f.as_ref().map(|(_, gen)| *gen))
            .unwrap_or(0);
        self.send_as(gen, event);
    }

    /// Send `event`, stamped as belonging to session `gen`.
    ///
    /// A send that fails means the window has gone; the session carries on
    /// without it, so this is a no-op rather than an error.
    pub fn send_as(&self, gen: u64, event: DebugEvent) {
        let channel = self.0.channel.lock().ok().and_then(|c| c.clone());
        if let Some(channel) = channel {
            let _ = channel.send(Envelope { gen, event });
        }
    }

    /// Start a forwarder for the active session, unless one is already running
    /// for it.
    ///
    /// Called after an operation and when a window subscribes. It is idempotent
    /// by identity rather than by flag, so a relaunch — which replaces the
    /// session — gets a new forwarder and a repeated call does not.
    pub fn ensure_forwarding(&self, state: &AppState) {
        let Ok(session) = state.debug.lock() else {
            return;
        };
        let Some(dbg) = session.clone() else {
            return;
        };
        let already = self
            .0
            .forwarding
            .lock()
            .ok()
            .and_then(|f| f.as_ref().and_then(|(w, _)| w.upgrade()));
        if already.is_some_and(|running| Arc::ptr_eq(&running, &dbg)) {
            return;
        }
        let gen = self.0.gen.fetch_add(1, Ordering::Relaxed) + 1;
        if let Ok(mut slot) = self.0.forwarding.lock() {
            *slot = Some((Arc::downgrade(&dbg), gen));
        }
        // Subscribed here, not in the thread: the debuggee is already running by
        // the time this runs, and its first prompt must not be able to land in
        // the gap between the command returning and the thread starting.
        self.forward(dbg.subscribe(), gen);
        // The window is told the new session's generation and view straight
        // away, rather than waiting for the session to publish something. That
        // is also what lets it recognise a straggler from the session it just
        // replaced: the stamp is already out of date by the time it lands.
        if let Ok(snapshot) = serde_json::to_value(dbg.snapshot()) {
            self.send_as(gen, DebugEvent::Snapshot { snapshot });
        }
    }

    /// Pump an already-subscribed event stream to the window until it ends.
    ///
    /// The session owns the senders behind the stream, so dropping the session
    /// closes it and this thread ends on its own: no teardown to arrange, and a
    /// relaunch simply gets a new thread.
    fn forward(&self, events: recurse_debug::SessionEvents, gen: u64) {
        // The thread holds its own handle, so it ends when the session does
        // rather than needing to be told.
        let owner = self.clone();
        let _ = std::thread::Builder::new()
            .name("recurse-debug-events".to_string())
            .spawn(move || {
                while let Ok(event) = events.recv() {
                    let out = match event {
                        recurse_debug::SessionEvent::Snapshot { snapshot } => {
                            match serde_json::to_value(snapshot) {
                                Ok(snapshot) => DebugEvent::Snapshot { snapshot },
                                Err(_) => continue,
                            }
                        }
                        recurse_debug::SessionEvent::Output { text } => DebugEvent::Output { text },
                    };
                    owner.send_as(gen, out);
                }
            });
    }
}

/// Register the window's channel and start forwarding, if a session is live.
///
/// # Errors
/// Never; the lock failures are swallowed because a missing forwarder only
/// costs the window the events it would have polled for.
#[tauri::command]
pub fn debug_subscribe(
    on_event: EventChannel,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    state.debug_events.subscribe(on_event);
    state.debug_events.ensure_forwarding(&state);
    Ok(())
}
