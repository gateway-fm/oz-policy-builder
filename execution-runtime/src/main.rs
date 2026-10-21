#![forbid(unsafe_code)]

use ozpb_execution_runtime::{
    execute, prepare, read_frame, InteractiveSigner, NativeJob, PreparedFrame, DEADLINE,
    MAX_START_BYTES,
};
use std::io::{self, BufReader};

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let preparation_only = match args.as_slice() {
        [] => false,
        [mode] if mode == "--prepare" => true,
        _ => return Err("expected no arguments or exactly --prepare".into()),
    };
    let mut reader = BufReader::new(io::stdin().lock());
    let start = read_frame(&mut reader, MAX_START_BYTES)?;
    let job: NativeJob = serde_json::from_slice(&start).map_err(|e| e.to_string())?;
    let prepared = prepare(job)?;
    let mut protocol = InteractiveSigner::new(reader, io::stdout().lock());
    protocol.emit(&PreparedFrame::from_execution(&prepared)?)?;
    if preparation_only {
        return Ok(());
    }
    let result = execute(&prepared, &mut protocol)?;
    protocol.emit(&result)?;
    if result.passed {
        Ok(())
    } else {
        Err("account execution did not pass".into())
    }
}

fn main() {
    // The watchdog also bounds a peer that never finishes a frame. The operator
    // must additionally kill the process group on cancellation and bound stderr.
    std::thread::spawn(|| {
        std::thread::sleep(DEADLINE);
        eprintln!("execution deadline exceeded");
        std::process::exit(124);
    });
    std::panic::set_hook(Box::new(|_| eprintln!("native execution aborted")));
    let result =
        std::panic::catch_unwind(run).unwrap_or_else(|_| Err("native execution aborted".into()));
    if let Err(message) = result {
        eprintln!("{message}");
        std::process::exit(1);
    }
}
