//! The tier run: the only way to execute an eval YAML.
//!
//! Deliberately a **binary, not a test** — a paid, multi-minute agent run must
//! never be triggered by `cargo test`. `cargo test` covers the harness
//! headlessly (config parsing, selection, grading, mock-LLM loop); this runs
//! the real agent against real crackmes.
//!
//! ```sh
//! just eval-run                                   # evals/easy.yaml
//! EVAL_CONFIG=evals/medium.yaml just eval-run     # another tier
//! ```
//!
//! Everything printed is also written to `<trace_dir>/run.log`, alongside the
//! per-task turn traces (`<trace_dir>/<hexid>.json`). Both default under the
//! workspace `target/` dir.
//!
//! Exit codes: 0 all tasks passed · 1 some task failed · 2 setup error
//! (missing key, unusable config, selection that can't be satisfied).

use std::io::Write;
use std::path::{Path, PathBuf};

use recurse_eval::config::EvalConfig;
use recurse_eval::corpus::{ensure_dataset_jsonl, ensure_task_binary};
use recurse_eval::runner::{run_task, EvalOpts};
use recurse_eval::select::{load_records, select_tasks};
use recurse_eval::{
    crate_relative, default_trace_dir, env_path, env_string, load_dotenv, rate_label, Task,
};

/// Mirrors every line to stdout and to the run log.
struct RunLog {
    file: Option<std::fs::File>,
}

impl RunLog {
    fn create(path: &Path) -> Self {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        // Best-effort: an unwritable log must not abort the run.
        Self {
            file: std::fs::File::create(path).ok(),
        }
    }

    fn log(&mut self, line: impl AsRef<str>) {
        let line = line.as_ref();
        println!("{line}");
        if let Some(f) = self.file.as_mut() {
            let _ = writeln!(f, "{line}");
        }
    }
}

fn die(message: impl AsRef<str>) -> ! {
    eprintln!("error: {}", message.as_ref());
    std::process::exit(2);
}

fn r2_available() -> bool {
    std::process::Command::new("r2")
        .arg("-v")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[tokio::main]
async fn main() {
    load_dotenv();

    let config_path = crate_relative(
        env_string("EVAL_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("evals/easy.yaml")),
    );
    let cfg = EvalConfig::load(&config_path)
        .unwrap_or_else(|e| die(format!("{e} (set EVAL_CONFIG to pick a tier)")));

    let corpus_dir = env_path("EVAL_CORPUS")
        .unwrap_or_else(|| crate_relative(cfg.corpus_dir.as_deref().unwrap_or("corpus")));
    let trace_base = env_path("EVAL_TRACES")
        .or_else(|| cfg.trace_dir.as_deref().map(crate_relative))
        .unwrap_or_else(default_trace_dir);
    let trace_dir = trace_base.join(&cfg.tier);

    // Setup failures are loud here (unlike a test): an explicit run that can't
    // run must not look like a pass.
    let api_key = librecurse::agent::LlmConfig::default()
        .api_key
        .filter(|k| !k.is_empty())
        .unwrap_or_else(|| {
            die(format!(
                "no API key. Add RECURSE_LLM_API_KEY to {}\n\
                 (or export OPENROUTER_API_KEY)",
                crate_relative(".env").display()
            ))
        });
    if !r2_available() {
        die("radare2 (`r2`) not on PATH — the agent cannot analyze binaries");
    }

    let mut log = RunLog::create(&trace_dir.join("run.log"));
    let started = std::time::Instant::now();
    log.log(format!(
        "=== recurse eval / tier {} ===\nconfig: {}\ncorpus: {}\ntraces: {}\nstarted: {}",
        cfg.tier,
        config_path.display(),
        corpus_dir.display(),
        trace_dir.display(),
        timestamp()
    ));
    if !cfg.description.is_empty() {
        log.log(format!("description: {}", cfg.description));
    }

    let jsonl_cache = crate_relative(&cfg.dataset.jsonl_cache);
    if let Err(e) = ensure_dataset_jsonl(&jsonl_cache, &cfg.dataset.jsonl_url).await {
        die(format!("dataset: {e}"));
    }
    let records = match load_records(&jsonl_cache) {
        Ok(r) => r,
        Err(e) => die(format!("dataset: {e}")),
    };
    let tasks = match select_tasks(&records, &cfg.select, &cfg.binaries) {
        Ok(t) => t,
        Err(e) => die(format!("selection: {e}")),
    };

    let mut opts = match EvalOpts::from_env(corpus_dir.clone(), trace_dir.clone()) {
        Ok(o) => o,
        Err(e) => die(e),
    };
    opts.api_key = api_key;
    // Precedence: env > YAML > built-in defaults.
    if env_string("EVAL_MODEL").is_none() && !cfg.run.model.is_empty() {
        opts.model = cfg.run.model.clone();
    }
    if env_string("EVAL_MAX_TURNS").is_none() {
        opts.max_turns = cfg.run.max_turns;
    }
    if env_string("EVAL_TIMEOUT_SECS").is_none() {
        opts.timeout_secs = cfg.run.timeout_secs;
    }

    log.log(format!(
        "tasks: {}\nmodel: {}\nendpoint: {}\nmax_turns: {}\ntimeout: {}s\n",
        tasks.len(),
        opts.model,
        opts.endpoint,
        opts.max_turns,
        opts.timeout_secs
    ));
    for task in &tasks {
        log.log(format!(
            "  · {} {} (difficulty {:.2}, {} {}, {})",
            task.hexid, task.name, task.difficulty, task.platform, task.arch, task.language
        ));
    }
    log.log("");

    let mut passed = 0usize;
    let mut failed: Vec<String> = Vec::new();
    let mut total_in = 0u64;
    let mut total_out = 0u64;
    let mut total_cost = 0.0;

    for task in &tasks {
        let binary = match fetch_binary(&corpus_dir, task, &mut log).await {
            Ok(p) => p,
            Err(e) => {
                log.log(format!("[FAIL] {} corpus: {e}", task.hexid));
                failed.push(format!("{}: corpus: {e}", task.hexid));
                continue;
            }
        };
        match run_task(task, &binary, &opts).await {
            Ok(o) => {
                total_in += o.est_in_tokens;
                total_out += o.est_out_tokens;
                total_cost += o.cost_usd;
                let status = if o.pass { "PASS" } else { "FAIL" };
                log.log(format!(
                    "[{status}] {} {} turns={} tools_in={} out={} ${:.3} err={}",
                    o.hexid,
                    o.name,
                    o.turns,
                    o.est_in_tokens,
                    o.est_out_tokens,
                    o.cost_usd,
                    o.error.as_deref().unwrap_or("-")
                ));
                if !o.models.is_empty() {
                    log.log(format!("       served: {}", o.models.join(", ")));
                }
                log.log(format!("       trace: {}", o.trace_path.display()));
                log.log(format!("       answer: {}", first_line(&o.final_answer)));
                if o.pass {
                    passed += 1;
                } else {
                    failed.push(format!(
                        "{}: no flag (turns={}, err={:?})",
                        task.hexid, o.turns, o.error
                    ));
                }
            }
            Err(e) => {
                log.log(format!("[FAIL] {} harness: {e}", task.hexid));
                failed.push(format!("{}: harness: {e}", task.hexid));
            }
        }
    }

    let elapsed = started.elapsed().as_secs();
    log.log(format!(
        "\n=== {}: {passed}/{} passed in {}s ({:.0}s/task) ===\nin={total_in} out={total_out} cost=${total_cost:.2} ({})",
        cfg.tier,
        tasks.len(),
        elapsed,
        elapsed as f64 / tasks.len().max(1) as f64,
        rate_label(&opts.model)
    ));
    if failed.is_empty() {
        log.log("all tasks produced the expected flag");
        log.log(format!("log: {}", trace_dir.join("run.log").display()));
        return;
    }
    log.log(format!("{} failed task(s):", failed.len()));
    for f in &failed {
        log.log(format!("  - {f}"));
    }
    log.log(format!("log: {}", trace_dir.join("run.log").display()));
    std::process::exit(1);
}

/// Fetch the task binary if it isn't cached yet, announcing the download so a
/// slow fetch doesn't look like a hang. Mirrors the cache check in
/// [`ensure_task_binary`]: a pinned `binary` path, or the `.fetched` marker
/// when the binary was located by magic bytes.
async fn fetch_binary(corpus_dir: &Path, task: &Task, log: &mut RunLog) -> Result<PathBuf, String> {
    let dir = corpus_dir.join(&task.hexid);
    let cached = if task.binary.is_empty() {
        dir.join(".fetched").is_file()
    } else {
        dir.join(&task.binary).is_file()
    };
    if !cached {
        log.log(format!("[fetch] {} ...", task.hexid));
    }
    ensure_task_binary(corpus_dir, task).await
}

fn first_line(s: &str) -> String {
    let line = s
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim();
    line.chars().take(120).collect()
}

fn timestamp() -> String {
    // Seconds since epoch: no chrono dependency for a log header.
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| format!("{} (unix)", d.as_secs()))
        .unwrap_or_else(|_| "unknown".to_string())
}
