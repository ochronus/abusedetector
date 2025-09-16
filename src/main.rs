use abusedetector::app::App;
use abusedetector::cli::Cli;

/// Binary entrypoint kept intentionally minimal.
///
/// Responsibilities:
/// 1. Parse CLI args
/// 2. Delegate full workflow to `App::run` (architectural façade)
/// 3. Exit with the returned process code
///
/// All substantial orchestration logic now lives in `app::App` per
/// improvement plan item 1.1 (reduce `main.rs` size).
#[tokio::main]
async fn main() {
    let cli = Cli::from_args();

    // Execute application workflow
    match App::run(&cli).await {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("Fatal error: {e}");
            // Non-zero to signal failure (distinct from logical "no results" cases
            // which are intentionally surfaced via exit code 0 inside App).
            std::process::exit(1);
        }
    }
}
