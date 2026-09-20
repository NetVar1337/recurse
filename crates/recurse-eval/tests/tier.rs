//! The configurable tier run: one test, driven entirely by a YAML config.
//! Selects tasks from the dataset, fetches binaries, runs the agent on each,
//! grades, and reports. Swap tiers with `EVAL_CONFIG` — no code changes.
//!
//! Needs `RECURSE_LLM_API_KEY` (or `OPENROUTER_API_KEY`) and `r2` on PATH;
//! skips gracefully without them so plain `cargo test` stays green.
//!
//! Run: `npm run eval:run` (or `EVAL_CONFIG=evals/medium.yaml npm run eval:run`)

use std::path::PathBuf;

use recurse_eval::config::EvalConfig;
use recurse_eval::corpus::{ensure_dataset_jsonl, ensure_task_binary};
use recurse_eval::runner::{run_task, EvalOpts};
use recurse_eval::select::{load_records, select_tasks};

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn crate_relative(p: PathBuf) -> PathBuf {
    if p.is_absolute() || p.exists() {
        p
    } else {
        crate_dir().join(p)
    }
}

fn r2_available() -> bool {
    std::process::Command::new("r2")
        .arg("-v")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[tokio::test]
async fn tier_run() {
    if librecurse::agent::LlmConfig::default().api_key.is_none() {
        println!("skipping tier run: no API key (RECURSE_LLM_API_KEY/OPENROUTER_API_KEY)");
        return;
    }
    if !r2_available() {
        println!("skipping tier run: r2 not on PATH");
        return;
    }
    let config_path = crate_relative(
        std::env::var("EVAL_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("evals/easy.yaml")),
    );
    let cfg = EvalConfig::load(&config_path).expect("load eval config");
    let here = crate_dir();
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
    let trace_dir = std::env::var("EVAL_TRACES")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let p = PathBuf::from(cfg.trace_dir.as_deref().unwrap_or("target/eval-traces"));
            if p.is_absolute() {
                p
            } else {
                here.join(p).join(&cfg.tier)
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
        .expect("dataset fetch");
    let records = load_records(&jsonl_cache).expect("dataset parse");
    let tasks = select_tasks(&records, &cfg.select, &cfg.binaries).expect("selection");

    let mut opts = EvalOpts::from_env(corpus_dir.clone(), trace_dir.clone()).expect("eval opts");
    // Precedence: env > YAML > built-in defaults.
    if std::env::var("EVAL_MODEL").is_err() && !cfg.run.model.is_empty() {
        opts.model = cfg.run.model.clone();
    }
    if std::env::var("EVAL_MAX_TURNS").is_err() {
        opts.max_turns = cfg.run.max_turns;
    }
    if std::env::var("EVAL_TIMEOUT_SECS").is_err() {
        opts.timeout_secs = cfg.run.timeout_secs;
    }
    println!(
        "tier {} ({}): {} tasks, model={}, max_turns={}, timeout={}s",
        cfg.tier,
        cfg.description,
        tasks.len(),
        opts.model,
        opts.max_turns,
        opts.timeout_secs
    );

    let mut passed = 0;
    let mut failed: Vec<String> = Vec::new();
    let mut total_in = 0u64;
    let mut total_out = 0u64;
    let mut total_cost = 0.0;
    for task in &tasks {
        let binary = match ensure_task_binary(&corpus_dir, task).await {
            Ok(p) => p,
            Err(e) => {
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
                println!(
                    "[{status}] {} {} turns={} in={} out={} ${:.3} err={:?} trace={}",
                    o.hexid,
                    o.name,
                    o.turns,
                    o.est_in_tokens,
                    o.est_out_tokens,
                    o.cost_usd,
                    o.error,
                    o.trace_path.display()
                );
                if o.pass {
                    passed += 1;
                } else {
                    failed.push(format!(
                        "{}: no flag (turns={}, err={:?})",
                        task.hexid, o.turns, o.error
                    ));
                }
            }
            Err(e) => failed.push(format!("{}: harness: {e}", task.hexid)),
        }
    }
    println!(
        "tier {}: {passed}/{} pass, in={total_in} out={total_out} ${total_cost:.2}",
        cfg.tier,
        tasks.len()
    );
    assert!(failed.is_empty(), "failed tasks:\n{}", failed.join("\n"));
}
