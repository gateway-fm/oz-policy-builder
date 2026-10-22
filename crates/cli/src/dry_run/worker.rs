//! Running the operator's native worker under the coordinator's own bounds.
//!
//! The executable is operator configuration, never request input, and gets only a fixed mode
//! argument, an empty environment apart from a fixed `PATH` and `LANG`, and `/` as its working
//! directory. It runs in its own process group. A deadline, enforced by a watchdog thread that
//! kills the whole group, bounds every blocking point, including a worker that stops reading;
//! stdout frames, total stdout and stderr are bounded; and a run that leaves any process in the
//! group is refused, as is any frame the protocol does not allow at that point.

use ozpb_toolkit::dry_run_report::WorkerExit;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

/// The worker's own watchdog deadline; the coordinator holds each run to the same bound.
pub const DEADLINE: Duration = Duration::from_secs(120);
/// The start frame (the job) limit the worker reads.
pub const MAX_START_BYTES: usize = 16 * 1024 * 1024;
const MAX_FRAME_BYTES: usize = 256 * 1024;
const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_STDERR_BYTES: usize = 64 * 1024;
/// How much of the worker's stderr is kept to explain a failed run to the operator.
const KEPT_STDERR_BYTES: usize = 4 * 1024;

/// The worker's fixed operating modes; nothing else reaches its argument list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Prepare,
    Execute,
    PrepareCaptured,
    ExecuteCaptured,
}

impl Mode {
    fn args(self) -> &'static [&'static str] {
        match self {
            Self::Prepare => &["--prepare"],
            Self::Execute => &[],
            Self::PrepareCaptured => &["--prepare-captured"],
            Self::ExecuteCaptured => &["--captured"],
        }
    }

    fn preparation_only(self) -> bool {
        matches!(self, Self::Prepare | Self::PrepareCaptured)
    }
}

/// How one worker run ended.
#[derive(Debug)]
pub enum Outcome {
    /// The coordinator stopped the run; the stable reason says why.
    Refused(&'static str),
    /// The worker ran to its own exit with every frame it sent accepted so far.
    Exited {
        exit: WorkerExit,
        prepared: Option<serde_json::Value>,
        result: Option<serde_json::Value>,
    },
}

/// The operator's worker executable.
#[derive(Clone, Debug)]
pub struct Worker {
    executable: PathBuf,
    deadline: Duration,
}

enum Event {
    Frame(Vec<u8>),
    Eof,
    Refused(&'static str),
}

impl Worker {
    pub fn new(executable: &Path) -> Result<Self, &'static str> {
        if !executable.is_absolute() {
            return Err("the native worker must be an absolute path");
        }
        Ok(Self {
            executable: executable.to_path_buf(),
            deadline: DEADLINE,
        })
    }

    #[cfg(test)]
    pub fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    /// Run the worker once over `job` (one compact JSON line). `check_prepared` decides the
    /// first frame; `sign` answers each signature request of an executing mode. Worker stderr
    /// beyond the kept prefix is counted, not stored.
    pub fn run(
        &self,
        mode: Mode,
        job: &[u8],
        check_prepared: &mut dyn FnMut(&serde_json::Value) -> Result<(), &'static str>,
        sign: &mut dyn FnMut(&serde_json::Value) -> Result<serde_json::Value, &'static str>,
    ) -> (Outcome, Vec<u8>) {
        if job.is_empty() || job.len() >= MAX_START_BYTES || job.contains(&b'\n') {
            return (Outcome::Refused("job_exceeds_worker_bounds"), Vec::new());
        }
        let mut command = Command::new(&self.executable);
        command
            .args(mode.args())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C")
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let Ok(mut child) = command.spawn() else {
            return (Outcome::Refused("worker_spawn_failed"), Vec::new());
        };
        let group = child.id();
        let (events, received) = mpsc::channel::<Event>();
        let (stop_watchdog, watchdog_stopped) = mpsc::channel::<()>();
        let deadline_hit = Arc::new(AtomicBool::new(false));
        let watchdog = {
            let deadline_hit = deadline_hit.clone();
            let deadline = self.deadline;
            std::thread::spawn(move || {
                if let Err(mpsc::RecvTimeoutError::Timeout) =
                    watchdog_stopped.recv_timeout(deadline)
                {
                    deadline_hit.store(true, Ordering::SeqCst);
                    kill_group(group);
                }
            })
        };
        let stdout = child.stdout.take().map(|stdout| {
            let events = events.clone();
            std::thread::spawn(move || read_frames(stdout, &events))
        });
        let stderr = child.stderr.take().map(|stderr| {
            let events = events.clone();
            std::thread::spawn(move || read_stderr(stderr, &events))
        });
        drop(events);
        let mut stdin = child.stdin.take();
        let mut line = job.to_vec();
        line.push(b'\n');
        let mut refused = match stdin.as_mut().map(|input| input.write_all(&line)) {
            Some(Ok(())) => None,
            _ => Some("worker_input_closed"),
        };
        if mode.preparation_only() {
            stdin = None;
        }
        let mut prepared = None;
        let mut result = None;
        while refused.is_none() {
            let Ok(event) = received.recv() else { break };
            match event {
                Event::Eof => break,
                Event::Refused(reason) => refused = Some(reason),
                Event::Frame(bytes) => {
                    refused = self
                        .receive(
                            mode,
                            &bytes,
                            &mut prepared,
                            &mut result,
                            &mut stdin,
                            check_prepared,
                            sign,
                        )
                        .err();
                }
            }
        }
        drop(stdin);
        if refused.is_some() {
            kill_group(group);
        }
        let status = child.wait();
        // The readers end at EOF, which the group kill above or the worker's exit brings.
        let kept_stderr = stderr.and_then(|t| t.join().ok()).unwrap_or_default();
        if let Some(t) = stdout {
            let _ = t.join();
        }
        let _ = stop_watchdog.send(());
        let _ = watchdog.join();
        // A late frame or limit seen while the readers drained still refuses the run.
        while let Ok(event) = received.try_recv() {
            match event {
                Event::Refused(reason) if refused.is_none() => refused = Some(reason),
                Event::Frame(_) if refused.is_none() => refused = Some("worker_protocol_violation"),
                _ => {}
            }
        }
        if deadline_hit.load(Ordering::SeqCst) {
            refused = Some("worker_deadline_exceeded");
        }
        if group_has_members(group) {
            kill_group(group);
            refused.get_or_insert("worker_left_processes_running");
        }
        let outcome = match (refused, status) {
            (Some(reason), _) => Outcome::Refused(reason),
            (None, Err(_)) => Outcome::Refused("worker_wait_failed"),
            (None, Ok(status)) => Outcome::Exited {
                exit: exit_of(status),
                prepared,
                result,
            },
        };
        (outcome, kept_stderr)
    }

    #[allow(clippy::too_many_arguments)]
    fn receive(
        &self,
        mode: Mode,
        bytes: &[u8],
        prepared: &mut Option<serde_json::Value>,
        result: &mut Option<serde_json::Value>,
        stdin: &mut Option<std::process::ChildStdin>,
        check_prepared: &mut dyn FnMut(&serde_json::Value) -> Result<(), &'static str>,
        sign: &mut dyn FnMut(&serde_json::Value) -> Result<serde_json::Value, &'static str>,
    ) -> Result<(), &'static str> {
        let frame: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| "worker_protocol_violation")?;
        let kind = frame
            .as_object()
            .and_then(|object| object.get("type"))
            .and_then(|kind| kind.as_str())
            .ok_or("worker_protocol_violation")?
            .to_owned();
        if result.is_some() {
            return Err("worker_protocol_violation");
        }
        if prepared.is_none() {
            if kind != "prepared" {
                return Err("worker_protocol_violation");
            }
            check_prepared(&frame).map_err(|_| "worker_preparation_refused")?;
            *prepared = Some(frame);
            return Ok(());
        }
        if mode.preparation_only() {
            return Err("worker_protocol_violation");
        }
        match kind.as_str() {
            "sign_request" => {
                let answer = sign(&frame).map_err(|_| "signing_request_refused")?;
                let mut line =
                    serde_json::to_vec(&answer).map_err(|_| "signing_request_refused")?;
                line.push(b'\n');
                let input = stdin.as_mut().ok_or("worker_protocol_violation")?;
                input
                    .write_all(&line)
                    .and_then(|()| input.flush())
                    .map_err(|_| "worker_input_closed")
            }
            "result" => {
                *result = Some(frame);
                *stdin = None;
                Ok(())
            }
            _ => Err("worker_protocol_violation"),
        }
    }
}

fn exit_of(status: std::process::ExitStatus) -> WorkerExit {
    match status.code() {
        Some(0) => WorkerExit::Success,
        Some(code) => WorkerExit::Code(code),
        None => WorkerExit::Signal,
    }
}

fn read_frames(stdout: std::process::ChildStdout, events: &mpsc::Sender<Event>) {
    let mut reader = BufReader::new(stdout);
    let mut total = 0usize;
    loop {
        // A frame and its newline fit in `MAX_FRAME_BYTES`, as the worker bounds its own.
        let mut frame = Vec::new();
        let read = (&mut reader)
            .take(MAX_FRAME_BYTES as u64)
            .read_until(b'\n', &mut frame);
        match read {
            Ok(0) => {
                let _ = events.send(Event::Eof);
                return;
            }
            Ok(count) => {
                total = total.saturating_add(count);
                if total > MAX_OUTPUT_BYTES {
                    let _ = events.send(Event::Refused("worker_output_limit_exceeded"));
                    return;
                }
                if frame.last() != Some(&b'\n') {
                    // Longer than a frame, or a final line without its terminator.
                    let reason = if frame.len() == MAX_FRAME_BYTES {
                        "worker_output_limit_exceeded"
                    } else {
                        "worker_protocol_violation"
                    };
                    let _ = events.send(Event::Refused(reason));
                    return;
                }
                frame.pop();
                if events.send(Event::Frame(frame)).is_err() {
                    return;
                }
            }
            Err(_) => {
                let _ = events.send(Event::Refused("worker_protocol_violation"));
                return;
            }
        }
    }
}

fn read_stderr(mut stderr: std::process::ChildStderr, events: &mpsc::Sender<Event>) -> Vec<u8> {
    let mut kept = Vec::new();
    let mut total = 0usize;
    let mut chunk = [0u8; 4096];
    loop {
        match stderr.read(&mut chunk) {
            Ok(0) | Err(_) => return kept,
            Ok(count) => {
                total = total.saturating_add(count);
                let room = KEPT_STDERR_BYTES.saturating_sub(kept.len());
                kept.extend_from_slice(&chunk[..count.min(room)]);
                if total > MAX_STDERR_BYTES {
                    let _ = events.send(Event::Refused("worker_stderr_limit_exceeded"));
                    return kept;
                }
            }
        }
    }
}

#[cfg(unix)]
fn kill_group(group: u32) {
    use nix::sys::signal::{killpg, Signal};
    use nix::unistd::Pid;
    if let Ok(raw) = i32::try_from(group) {
        let _ = killpg(Pid::from_raw(raw), Signal::SIGKILL);
    }
}

#[cfg(not(unix))]
fn kill_group(_: u32) {}

/// Whether any process is still in the worker's group after the worker itself was reaped.
/// Probed with signal 0; a member the caller may not signal still counts.
#[cfg(unix)]
fn group_has_members(group: u32) -> bool {
    use nix::errno::Errno;
    use nix::sys::signal::killpg;
    use nix::unistd::Pid;
    let Ok(raw) = i32::try_from(group) else {
        return false;
    };
    match killpg(Pid::from_raw(raw), None) {
        Ok(()) => true,
        Err(Errno::EPERM) => true,
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn group_has_members(_: u32) -> bool {
    false
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn script(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("worker.sh");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn accept(_: &serde_json::Value) -> Result<(), &'static str> {
        Ok(())
    }

    fn never_sign(_: &serde_json::Value) -> Result<serde_json::Value, &'static str> {
        Err("no signature expected")
    }

    fn run(worker: &Worker, mode: Mode) -> Outcome {
        worker
            .run(mode, b"{\"job\":1}", &mut accept, &mut never_sign)
            .0
    }

    #[test]
    fn the_runner_bounds_time_stderr_and_stray_processes_and_keeps_the_exit_status() {
        let dir = tempfile::tempdir().unwrap();
        // A clean preparation: one frame, exit zero.
        let worker = Worker::new(&script(
            dir.path(),
            "read job; echo '{\"type\":\"prepared\"}'",
        ))
        .unwrap();
        assert!(matches!(
            run(&worker, Mode::Prepare),
            Outcome::Exited {
                exit: WorkerExit::Success,
                prepared: Some(_),
                result: None
            }
        ));
        // A nonzero exit is kept for the report, not hidden.
        let worker = Worker::new(&script(
            dir.path(),
            "read job; echo '{\"type\":\"prepared\"}'; exit 3",
        ))
        .unwrap();
        assert!(matches!(
            run(&worker, Mode::Prepare),
            Outcome::Exited {
                exit: WorkerExit::Code(3),
                ..
            }
        ));
        // A worker that never answers is killed at the deadline, with its group.
        let worker = Worker::new(&script(dir.path(), "sleep 30 & sleep 30"))
            .unwrap()
            .with_deadline(Duration::from_millis(300));
        let started = std::time::Instant::now();
        assert!(matches!(
            run(&worker, Mode::Execute),
            Outcome::Refused("worker_deadline_exceeded")
        ));
        assert!(started.elapsed() < Duration::from_secs(10));
        // Stderr past its bound refuses the run.
        let worker = Worker::new(&script(
            dir.path(),
            "read job; head -c 70000 /dev/zero >&2; sleep 5",
        ))
        .unwrap();
        assert!(matches!(
            run(&worker, Mode::Prepare),
            Outcome::Refused("worker_stderr_limit_exceeded")
        ));
        // A process left behind in the group refuses even a clean exit.
        let worker = Worker::new(&script(
            dir.path(),
            "read job; echo '{\"type\":\"prepared\"}'; (sleep 30 >/dev/null 2>&1 </dev/null &) ; exit 0",
        ))
        .unwrap();
        assert!(matches!(
            run(&worker, Mode::Prepare),
            Outcome::Refused("worker_left_processes_running")
        ));
        // A second frame in preparation mode, or an unknown first frame, is a violation.
        let worker = Worker::new(&script(
            dir.path(),
            "read job; echo '{\"type\":\"prepared\"}'; echo '{\"type\":\"result\"}'",
        ))
        .unwrap();
        assert!(matches!(
            run(&worker, Mode::Prepare),
            Outcome::Refused("worker_protocol_violation")
        ));
        // A refused signature request ends the run.
        let worker = Worker::new(&script(
            dir.path(),
            "read job; echo '{\"type\":\"prepared\"}'; echo '{\"type\":\"sign_request\"}'; read answer",
        ))
        .unwrap();
        assert!(matches!(
            run(&worker, Mode::Execute),
            Outcome::Refused("signing_request_refused")
        ));
        assert!(Worker::new(Path::new("relative/worker")).is_err());
    }
}
