//! Fetch everything a tier config needs: the dataset JSONL plus every
//! selected task's binary. Rust only.
//!
//! Usage: `cargo run -p recurse-eval --bin fetch-corpus [-- tier.yaml]`
//! (`EVAL_CONFIG` / `EVAL_CORPUS` also respected). Paths resolve against the
//! crate dir unless absolute, so this works from the repo root and the crate
//! dir alike.

use std::path::PathBuf;

use recurse_eval::config::EvalConfig;
use recurse_eval::corpus::{ensure_dataset_jsonl, ensure_task_binary};
use recurse_eval::select::{load_records, select_tasks};

fn crate_relative(p: PathBuf) -> PathBuf {
    if p.is_absolute() || p.exists() {
        p
    } else {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(p)
    }
}

#[tokio::main]
async fn main() {
    let config_path = crate_relative(
        std::env::args()
            .nth(1)
            .map(PathBuf::from)
            .or_else(|| std::env::var("EVAL_CONFIG").ok().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("evals/easy.yaml")),
    );
    let cfg = EvalConfig::load(&config_path).unwrap_or_else(|e| {
        eprintln!("config load failed: {e}");
        std::process::exit(2);
    });
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let corpus_dir = std::env::var("EVAL_CORPUS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let p = PathBuf::from(cfg.corpus_dir.as_deref().unwrap_or("corpus"));
            if p.is_absolute() {
                p
            } else {
                here.join(p)
            }
        });
    let jsonl_cache = {
        let p = PathBuf::from(cfg.dataset.jsonl_cache.clone());
        if p.is_absolute() {
            p
        } else {
            here.join(p)
        }
    };

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
