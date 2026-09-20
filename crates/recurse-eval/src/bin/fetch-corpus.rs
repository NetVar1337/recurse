//! Fetch everything a tier config needs: the dataset JSONL plus every
//! selected task's binary. Rust only.
//!
//! Usage: `cargo run -p recurse-eval --bin fetch-corpus [-- tier.yaml]`
//! (`EVAL_CONFIG` / `EVAL_CORPUS` also respected, plus a repo-root `.env`).
//! Relative paths resolve against the crate dir, so this behaves the same
//! from the repo root, `tauri/`, or the crate dir.

use std::path::PathBuf;

use recurse_eval::config::EvalConfig;
use recurse_eval::corpus::{ensure_dataset_jsonl, ensure_task_binary};
use recurse_eval::select::{load_records, select_tasks};
use recurse_eval::{crate_relative, env_path, load_dotenv};

#[tokio::main]
async fn main() {
    load_dotenv();
    let config_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .or_else(|| std::env::var("EVAL_CONFIG").ok().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("evals/easy.yaml"));
    let config_path = crate_relative(config_path);
    let cfg = EvalConfig::load(&config_path).unwrap_or_else(|e| {
        eprintln!("config load failed: {e}");
        std::process::exit(2);
    });
    let corpus_dir = env_path("EVAL_CORPUS")
        .unwrap_or_else(|| crate_relative(cfg.corpus_dir.as_deref().unwrap_or("corpus")));
    let jsonl_cache = crate_relative(&cfg.dataset.jsonl_cache);

    ensure_dataset_jsonl(&jsonl_cache, &cfg.dataset.jsonl_url)
        .await
        .unwrap_or_else(|e| {
            eprintln!("dataset fetch failed: {e}");
            std::process::exit(2);
        });
    let records = load_records(&jsonl_cache).unwrap_or_else(|e| {
        eprintln!("dataset parse failed: {e}");
        std::process::exit(2);
    });
    let tasks = select_tasks(&records, &cfg.select, &cfg.binaries).unwrap_or_else(|e| {
        eprintln!("selection failed: {e}");
        std::process::exit(2);
    });
    println!("tier {}: {} tasks", cfg.tier, tasks.len());
    let mut failed = 0;
    for task in &tasks {
        match ensure_task_binary(&corpus_dir, task).await {
            Ok(path) => println!("ok   {} -> {}", task.hexid, path.display()),
            Err(e) => {
                failed += 1;
                eprintln!("FAIL {}: {e}", task.hexid);
            }
        }
    }
    if failed > 0 {
        eprintln!("{failed} tasks failed");
        std::process::exit(1);
    }
}
