//! Thin entry point; the logic is in the library so tests run it in-process.

use std::io::IsTerminal;
use std::time::{SystemTime, UNIX_EPOCH};

use tidegard_cli::config::ProcessEnvironment;
use tidegard_cli::{run, Io};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let now_micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_micros()).unwrap_or(i64::MAX)
        });
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("Error: cannot start: {error}");
            std::process::exit(tidegard_cli::exit::FAILURE);
        }
    };
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    // A prompt reads stdin only when a person is there to answer it.
    let stdin = std::io::stdin();
    let mut stdin_lock = stdin.lock();
    let input: Option<&mut dyn std::io::BufRead> = if stdin.is_terminal() {
        Some(&mut stdin_lock)
    } else {
        None
    };
    let mut io = Io {
        out: &mut stdout,
        err: &mut stderr,
        input,
        now_micros,
    };
    let code = runtime.block_on(run(&args, &ProcessEnvironment, &mut io));
    // `exit` runs no destructors, so buffered output is flushed first.
    let _ = io.out.flush();
    let _ = io.err.flush();
    std::process::exit(code);
}
