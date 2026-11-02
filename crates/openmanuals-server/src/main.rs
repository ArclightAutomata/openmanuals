//! openmanuals-server binary; the library holds everything else.
use anyhow::Result;
use clap::Parser;
use openmanuals_server::{fold, router, schedule, verify, Cli, Cmd, State};
use std::time::Duration;

/// Builds parse facts on many threads and free them on another; mimalloc
/// handles that far better than the system allocator (2.4x faster builds).
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> Result<()> {
    // `openmanuals-server __scan <file>`: a scan worker (see openmanuals_server::scan), started by
    // the verifier with resource limits. It runs before the async runtime
    // exists: no runtime threads, config, key or logging in the worker.
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if args.len() == 3 && args[1] == openmanuals_server::scan::WORKER_ARG {
        std::process::exit(openmanuals_server::scan::worker_main(std::path::Path::new(&args[2])));
    }
    tokio::runtime::Builder::new_multi_thread().enable_all().build()?.block_on(run())
}

async fn run() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into())).init();
    if let Ok(exe) = std::env::current_exe() {
        openmanuals_server::scan::use_worker_process(exe);
    }
    let cli = Cli::parse();
    let state = State::new(cli.paths)?;
    match cli.cmd.unwrap_or(Cmd::Serve { bind: "127.0.0.1:8000".into(), fold_interval: 3600, fold_debounce: 5, fold_max_delay: 60, verify_interval: 900 }) {
        Cmd::Whoami => {
            println!("{}\n{}", state.fingerprint, state.key.public_key().to_openssh());
        }
        Cmd::Import { path } => {
            let text = std::fs::read_to_string(&path)?;
            let mut facts = Vec::new();
            if text.trim_start().starts_with('[') {
                facts = serde_json::from_str(&text)?;
            } else {
                for line in text.lines().filter(|l| !l.trim().is_empty()) {
                    let v: serde_json::Value = serde_json::from_str(line)?;
                    let f = v.get("fact").cloned().unwrap_or(v);
                    facts.push(serde_json::from_value::<openmanuals_core::Fact>(f)?);
                }
            }
            let (mut acc, mut dup, mut rej) = (0, 0, 0);
            for chunk in facts.chunks(5000) {
                let r = state.inbox.accept(chunk, |_| Ok(()))?;
                acc += r.accepted.len();
                dup += r.duplicate.len();
                rej += r.rejected.len();
                for e in r.rejected.iter().take(5) {
                    eprintln!("rejected #{}: {}", e.index, e.error);
                }
            }
            println!("imported {acc} facts ({dup} duplicate, {rej} rejected)");
        }
        Cmd::Fold => {
            let (n, stats) = fold::fold_and_build(state).await?;
            match stats {
                Some(stats) => println!("folded {n} facts; snapshot: {stats:?}"),
                None => println!("nothing to fold; snapshot is current"),
            }
        }
        Cmd::Build { verify, full } => {
            let stats = tokio::task::spawn_blocking(move || fold::build_snapshot(&state, verify, full)).await??;
            println!("{stats:?}");
        }
        Cmd::Verify { max_locations } => {
            let n = verify::run_once(state, max_locations).await?;
            println!("recorded {n} verifier facts");
        }
        Cmd::Serve { bind, fold_interval, fold_debounce, fold_max_delay, verify_interval } => {
            let secs = Duration::from_secs;
            let s = schedule::Schedule {
                debounce: secs(fold_debounce),
                max_delay: secs(fold_max_delay),
                interval: secs(fold_interval),
                // Facts imported by another process (`openmanuals-server import`).
                poll: if fold_debounce > 0 { secs(5) } else { Duration::ZERO },
            };
            if fold_interval > 0 || fold_debounce > 0 {
                schedule::spawn(state.clone(), s);
            }
            {
                let st = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = openmanuals_server::avatar::refresh(st).await {
                        tracing::warn!(error = %e, "avatar refresh failed");
                    }
                });
            }
            if verify_interval > 0 {
                let st = state.clone();
                tokio::spawn(async move {
                    let mut t = tokio::time::interval(Duration::from_secs(verify_interval));
                    loop {
                        t.tick().await;
                        match verify::run_once(st.clone(), 200).await {
                            // Its verdicts and identity links are facts too.
                            Ok(n) if n > 0 => st.fold_trigger.poke(),
                            Ok(_) => {}
                            Err(e) => tracing::error!(error = %e, "verifier failed"),
                        }
                        // Retry failed URL avatars; drop unused pictures.
                        if let Err(e) = openmanuals_server::avatar::refresh(st.clone()).await {
                            tracing::warn!(error = %e, "avatar refresh failed");
                        }
                    }
                });
            }
            let listener = tokio::net::TcpListener::bind(&bind).await?;
            tracing::info!(%bind, fingerprint = %state.fingerprint, "listening");
            axum::serve(listener, router(state)).await?;
        }
    }
    Ok(())
}
