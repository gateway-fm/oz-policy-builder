#![forbid(unsafe_code)]

use ozpb_execution_runtime::{
    execute, execute_captured, prepare, prepare_captured, read_frame, CapturedPreparedFrame,
    CapturedTargetJob, InteractiveSigner, NativeJob, PreparedFrame, DEADLINE, MAX_START_BYTES,
};
use std::io::{self, BufReader};

/// The fixed operating modes. No argument selects an executable, endpoint, path or key.
enum Mode {
    Native { preparation_only: bool },
    Captured { preparation_only: bool },
}

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let mode = match args.as_slice() {
        [] => Mode::Native {
            preparation_only: false,
        },
        [mode] if mode == "--prepare" => Mode::Native {
            preparation_only: true,
        },
        [mode] if mode == "--captured" => Mode::Captured {
            preparation_only: false,
        },
        [mode] if mode == "--prepare-captured" => Mode::Captured {
            preparation_only: true,
        },
        _ => return Err(
            "expected no arguments, or exactly one of --prepare, --captured, --prepare-captured"
                .into(),
        ),
    };
    let mut reader = BufReader::new(io::stdin().lock());
    let start = read_frame(&mut reader, MAX_START_BYTES)?;
    match mode {
        Mode::Native { preparation_only } => {
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
        Mode::Captured { preparation_only } => {
            let job: CapturedTargetJob =
                serde_json::from_slice(&start).map_err(|e| e.to_string())?;
            let prepared = prepare_captured(job)?;
            let mut protocol = InteractiveSigner::new(reader, io::stdout().lock());
            protocol.emit(&CapturedPreparedFrame::from_prepared(&prepared)?)?;
            if preparation_only {
                return Ok(());
            }
            let result = execute_captured(&prepared, &mut protocol)?;
            protocol.emit(&result)?;
            if result.passed {
                Ok(())
            } else {
                Err("captured target execution did not pass".into())
            }
        }
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
    std::panic::set_hook(Box::new(|_| eprintln!("execution worker aborted")));
    let result =
        std::panic::catch_unwind(run).unwrap_or_else(|_| Err("execution worker aborted".into()));
    if let Err(message) = result {
        eprintln!("{message}");
        std::process::exit(1);
    }
}
