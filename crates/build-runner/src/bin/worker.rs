//! One job on stdin and one bounded response on stdout; runtime supplies containment.
#![forbid(unsafe_code)]

fn main() {
    if ozpb_build_runner::worker::serve_one(std::io::stdin().lock(), std::io::stdout().lock())
        .is_err()
    {
        eprintln!("disposable build job failed");
        std::process::exit(1);
    }
}
