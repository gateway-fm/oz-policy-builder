//! Running the operator's native worker under the coordinator's own bounds.
//!
//! The executable is operator configuration, never request input, and gets only a fixed mode
//! argument, an empty environment apart from a fixed `PATH` and `LANG`, and `/` as its working
//! directory. It runs in its own process group. Input is written by its own thread, so a worker
//! that stops reading blocks nothing here. At the deadline a watchdog kills the group and wakes
//! the coordinator, which kills the worker itself too, and once the worker has ended its pipes
//! get a short grace period to close: neither a worker nor a descendant that left the group can
//! hold the coordinator past either bound.
//! Stdout frames, total stdout and stderr are bounded; and a run that leaves any process in the
//! group, or its pipes open, is refused, as is any frame the protocol does not allow at that
//! point.

use ozpb_toolkit::dry_run_report::WorkerExit;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

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

/// How long the coordinator waits for the worker's pipes to close once the worker has exited
/// or been killed. A descendant that left the group can hold them open indefinitely.
const PIPE_GRACE: Duration = Duration::from_secs(5);

/// The operator's worker executable.
#[derive(Clone, Debug)]
pub struct Worker {
    executable: PathBuf,
    // Retain one private byte snapshot across preparation and execution, including clones.
    _pinned: Arc<tempfile::TempDir>,
    deadline: Duration,
    grace: Duration,
}

enum Event {
    Frame(Vec<u8>),
    StdoutClosed,
    StderrClosed,
    Refused(&'static str),
    Deadline,
}

impl Worker {
    /// The worker runs unsandboxed as the caller and can read anything the caller can,
    /// including the delegate key file, so it must be a binary the caller trusts. A binary that
    /// someone other than the caller or root could replace is refused.
    pub fn new(executable: &Path) -> Result<Self, &'static str> {
        if !executable.is_absolute() {
            return Err("the native worker must be an absolute path");
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits());
        }
        let mut source = options
            .open(executable)
            .map_err(|_| "the native worker cannot be opened")?;
        let metadata = source
            .metadata()
            .map_err(|_| "the native worker cannot be read")?;
        if !metadata.is_file() {
            return Err("the native worker is not a regular file");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.mode() & 0o022 != 0 {
                return Err("the native worker is writable by its group or others");
            }
            if metadata.mode() & 0o111 == 0 {
                return Err("the native worker is not executable");
            }
            if metadata.uid() != nix::unistd::getuid().as_raw() && metadata.uid() != 0 {
                return Err("the native worker is owned by neither the caller nor root");
            }
        }
        let pinned = tempfile::Builder::new()
            .prefix("ozpb-worker-")
            .tempdir()
            .map_err(|_| "the native worker snapshot cannot be created")?;
        let snapshot = pinned.path().join("worker");
        {
            let mut destination = std::fs::File::create(&snapshot)
                .map_err(|_| "the native worker snapshot cannot be opened")?;
            std::io::copy(&mut source, &mut destination)
                .map_err(|_| "the native worker snapshot cannot be copied")?;
        } // Close the writable handle before exec (also required by Linux's ETXTBSY rule).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(pinned.path(), std::fs::Permissions::from_mode(0o700))
                .and_then(|()| {
                    std::fs::set_permissions(&snapshot, std::fs::Permissions::from_mode(0o500))
                })
                .map_err(|_| "the native worker snapshot cannot be protected")?;
        }
        Ok(Self {
            executable: snapshot,
            _pinned: Arc::new(pinned),
            deadline: DEADLINE,
            grace: PIPE_GRACE,
        })
    }

    #[cfg(test)]
    pub fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    #[cfg(test)]
    pub fn with_grace(mut self, grace: Duration) -> Self {
        self.grace = grace;
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
            let events = events.clone();
            std::thread::spawn(move || {
                if let Err(mpsc::RecvTimeoutError::Timeout) =
                    watchdog_stopped.recv_timeout(deadline)
                {
                    deadline_hit.store(true, Ordering::SeqCst);
                    kill_group(group);
                    let _ = events.send(Event::Deadline);
                }
            })
        };
        let kept_stderr = Arc::new(Mutex::new(Vec::new()));
        if let Some(stdout) = child.stdout.take() {
            let events = events.clone();
            std::thread::spawn(move || read_frames(stdout, &events));
        } else {
            let _ = events.send(Event::StdoutClosed);
        }
        if let Some(stderr) = child.stderr.take() {
            let (events, kept) = (events.clone(), kept_stderr.clone());
            std::thread::spawn(move || read_stderr(stderr, &events, &kept));
        } else {
            let _ = events.send(Event::StderrClosed);
        }
        // Input goes through its own thread; dropping `stdin` closes the worker's input once
        // every queued line is written.
        let mut stdin = child.stdin.take().map(|mut input| {
            let (lines, queued) = mpsc::channel::<Vec<u8>>();
            let events = events.clone();
            std::thread::spawn(move || {
                for line in queued {
                    if input.write_all(&line).and_then(|()| input.flush()).is_err() {
                        let _ = events.send(Event::Refused("worker_input_closed"));
                        return;
                    }
                }
            });
            lines
        });
        drop(events);
        let mut line = job.to_vec();
        line.push(b'\n');
        let mut refused = match stdin.as_ref().map(|input| input.send(line)) {
            Some(Ok(())) => None,
            _ => Some("worker_input_closed"),
        };
        if mode.preparation_only() {
            stdin = None;
        }
        let (mut stdout_open, mut stderr_open) = (true, true);
        let mut prepared = None;
        let mut result = None;
        let mut exited = None;
        let mut exited_at = None;
        // Observe child exit independently of stdout EOF: a detached descendant may retain
        // that pipe. Its grace starts when the worker exits, not when the pipe finally closes.
        while refused.is_none() && stdout_open {
            if exited.is_none() {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        exited = Some(status);
                        exited_at = Some(Instant::now());
                    }
                    Ok(None) => {}
                    Err(_) => {
                        refused = Some("worker_exit_unavailable");
                        break;
                    }
                }
            }
            if exited_at.is_some_and(|at| at.elapsed() >= self.grace) {
                refused = Some("worker_left_processes_running");
                break;
            }
            match received.recv_timeout(Duration::from_millis(10)) {
                Ok(Event::Frame(bytes)) => {
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
                Ok(Event::StdoutClosed) => stdout_open = false,
                Ok(Event::StderrClosed) => stderr_open = false,
                Ok(Event::Refused(reason)) => refused = Some(reason),
                Ok(Event::Deadline) => refused = Some("worker_deadline_exceeded"),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        drop(stdin);
        if refused.is_some() {
            kill_group(group);
            // The worker itself too, in case it left its group. `Child::kill` never signals a
            // reaped process, so a reused process ID is never hit.
            let _ = child.kill();
        }
        // Polled rather than waited on, so the deadline still applies to a worker that closed
        // its output but did not exit.
        let status = loop {
            if let Some(status) = exited {
                break Ok(status);
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    exited_at = Some(Instant::now());
                    break Ok(status);
                }
                Ok(None) => {
                    if deadline_hit.load(Ordering::SeqCst) {
                        kill_group(group);
                        let _ = child.kill();
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => break Err(error),
            }
        };
        // The pipes close when every holder ends; a holder outside the group gets a grace period.
        let grace_ends = exited_at.unwrap_or_else(Instant::now) + self.grace;
        while stdout_open || stderr_open {
            let remaining = grace_ends.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                refused.get_or_insert("worker_left_processes_running");
                break;
            }
            match received.recv_timeout(remaining) {
                Ok(Event::StdoutClosed) => stdout_open = false,
                Ok(Event::StderrClosed) => stderr_open = false,
                Ok(Event::Refused(reason)) => {
                    refused.get_or_insert(reason);
                }
                Ok(Event::Frame(_)) => {
                    refused.get_or_insert("worker_protocol_violation");
                }
                Ok(Event::Deadline) => {
                    refused.get_or_insert("worker_deadline_exceeded");
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        let _ = stop_watchdog.send(());
        let _ = watchdog.join();
        // A late frame or limit seen after the pipes closed still refuses the run.
        while let Ok(event) = received.try_recv() {
            match event {
                Event::Refused(reason) => {
                    refused.get_or_insert(reason);
                }
                Event::Frame(_) => {
                    refused.get_or_insert("worker_protocol_violation");
                }
                Event::StdoutClosed | Event::StderrClosed | Event::Deadline => {}
            }
        }
        if deadline_hit.load(Ordering::SeqCst) {
            refused = Some("worker_deadline_exceeded");
        }
        if group_has_members(group) {
            kill_group(group);
            refused.get_or_insert("worker_left_processes_running");
        }
        let kept_stderr = kept_stderr
            .lock()
            .map(|kept| kept.clone())
            .unwrap_or_default();
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
        stdin: &mut Option<mpsc::Sender<Vec<u8>>>,
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
                stdin
                    .as_ref()
                    .ok_or("worker_protocol_violation")?
                    .send(line)
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
                let _ = events.send(Event::StdoutClosed);
                return;
            }
            Ok(count) => {
                total = total.saturating_add(count);
                if total > MAX_OUTPUT_BYTES {
                    let _ = events.send(Event::Refused("worker_output_limit_exceeded"));
                    let _ = events.send(Event::StdoutClosed);
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
                    let _ = events.send(Event::StdoutClosed);
                    return;
                }
                frame.pop();
                if events.send(Event::Frame(frame)).is_err() {
                    return;
                }
            }
            Err(_) => {
                let _ = events.send(Event::Refused("worker_protocol_violation"));
                let _ = events.send(Event::StdoutClosed);
                return;
            }
        }
    }
}

fn read_stderr(
    mut stderr: std::process::ChildStderr,
    events: &mpsc::Sender<Event>,
    kept: &Mutex<Vec<u8>>,
) {
    let mut total = 0usize;
    let mut chunk = [0u8; 4096];
    loop {
        match stderr.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(count) => {
                total = total.saturating_add(count);
                if let Ok(mut kept) = kept.lock() {
                    let room = KEPT_STDERR_BYTES.saturating_sub(kept.len());
                    kept.extend_from_slice(&chunk[..count.min(room)]);
                }
                if total > MAX_STDERR_BYTES {
                    let _ = events.send(Event::Refused("worker_stderr_limit_exceeded"));
                    break;
                }
            }
        }
    }
    let _ = events.send(Event::StderrClosed);
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
    fn validating_a_worker_fifo_does_not_block() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("worker.fifo");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRUSR).unwrap();
        let (done, finished) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = done.send(Worker::new(&fifo));
        });
        let result = finished
            .recv_timeout(Duration::from_secs(5))
            .expect("validating a FIFO must not block");
        assert_eq!(
            result.unwrap_err(),
            "the native worker is not a regular file"
        );
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

    #[test]
    fn replacement_after_validation_and_between_modes_never_changes_the_worker() {
        let dir = tempfile::tempdir().unwrap();
        let path = script(
            dir.path(),
            "read job; echo '{\"type\":\"prepared\",\"identity\":\"original\"}'; \
             if [ \"$1\" != \"--prepare\" ]; then echo '{\"type\":\"result\"}'; fi",
        );
        let worker = Worker::new(&path).unwrap();
        let marker = dir.path().join("untrusted-ran");
        script(dir.path(), &format!("touch '{}'; exit 9", marker.display()));
        let prepared = run(&worker, Mode::Prepare);
        assert!(
            matches!(
                prepared,
                Outcome::Exited {
                    exit: WorkerExit::Success,
                    ..
                }
            ),
            "{prepared:?}"
        );
        // Even replacing the path a second time cannot change execution after preparation.
        script(dir.path(), &format!("touch '{}'; exit 8", marker.display()));
        let executed = run(&worker.clone(), Mode::Execute);
        assert!(
            matches!(
                executed,
                Outcome::Exited {
                    exit: WorkerExit::Success,
                    ..
                }
            ),
            "{executed:?}"
        );
        assert!(!marker.exists());
    }

    #[test]
    fn a_detached_pipe_holder_is_refused_at_exit_grace_before_the_main_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let worker = Worker::new(&script(
            dir.path(),
            "read job; echo '{\"type\":\"prepared\"}'; \
             /usr/bin/perl -e 'use POSIX; POSIX::setsid(); select(undef,undef,undef,0.8)' & exit 0",
        ))
        .unwrap()
        .with_deadline(Duration::from_secs(5))
        .with_grace(Duration::from_millis(100));
        let started = Instant::now();
        let outcome = run(&worker, Mode::Prepare);
        assert!(
            matches!(outcome, Outcome::Refused("worker_left_processes_running")),
            "{outcome:?}"
        );
        assert!(started.elapsed() < Duration::from_millis(650));
    }

    #[test]
    fn a_worker_binary_others_can_replace_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = script(dir.path(), "exit 0");
        assert!(Worker::new(&path).is_ok());
        for mode in [0o720, 0o702, 0o777] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(Worker::new(&path).is_err(), "mode {mode:o}");
        }
        // A system binary only root can write is acceptable; a missing one or a directory is not.
        assert!(Worker::new(Path::new("/bin/sh")).is_ok());
        assert!(Worker::new(&dir.path().join("absent")).is_err());
        assert!(Worker::new(dir.path()).is_err());
    }

    #[test]
    fn the_runner_returns_when_a_descendant_leaves_the_group_holding_its_output() {
        let dir = tempfile::tempdir().unwrap();
        // A descendant in its own session keeps the worker's stdout open after the worker has
        // exited, where the group kill cannot reach it. The run must still end, refused.
        let worker = Worker::new(&script(
            dir.path(),
            "read job; echo '{\"type\":\"prepared\"}'; \
             /usr/bin/perl -e 'use POSIX; POSIX::setsid(); sleep 12' & exit 0",
        ))
        .unwrap()
        .with_deadline(Duration::from_millis(500))
        .with_grace(Duration::from_millis(500));
        let started = std::time::Instant::now();
        let outcome = run(&worker, Mode::Prepare);
        assert!(matches!(outcome, Outcome::Refused(_)), "{outcome:?}");
        assert!(
            started.elapsed() < Duration::from_secs(6),
            "{:?}",
            started.elapsed()
        );
        // The same with the worker itself never reading its input: the job is larger than a
        // pipe buffer, and the run still ends at the deadline.
        let worker = Worker::new(&script(
            dir.path(),
            "/usr/bin/perl -e 'use POSIX; POSIX::setsid(); sleep 12' & sleep 12",
        ))
        .unwrap()
        .with_deadline(Duration::from_millis(500))
        .with_grace(Duration::from_millis(500));
        let job = format!("{{\"job\":\"{}\"}}", "x".repeat(1 << 20));
        let started = std::time::Instant::now();
        let outcome = worker
            .run(Mode::Prepare, job.as_bytes(), &mut accept, &mut never_sign)
            .0;
        assert!(matches!(outcome, Outcome::Refused(_)), "{outcome:?}");
        assert!(
            started.elapsed() < Duration::from_secs(6),
            "{:?}",
            started.elapsed()
        );
        // A worker that moves itself into its parent's group, out of reach of the group kill,
        // and keeps its output open is still stopped at the deadline.
        let worker = Worker::new(&script(
            dir.path(),
            "exec /usr/bin/perl -e 'use POSIX; setpgid(0, getpgrp(getppid())) or die; sleep 12'",
        ))
        .unwrap()
        .with_deadline(Duration::from_millis(500))
        .with_grace(Duration::from_millis(500));
        let started = std::time::Instant::now();
        let outcome = run(&worker, Mode::Prepare);
        assert!(
            matches!(outcome, Outcome::Refused("worker_deadline_exceeded")),
            "{outcome:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(6),
            "{:?}",
            started.elapsed()
        );
    }
}
