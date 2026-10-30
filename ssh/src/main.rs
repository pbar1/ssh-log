pub mod classify;

use std::env;
use std::ffi;
use std::io;
use std::os::unix::process::CommandExt as _;
use std::process;

const SSH: &str = "/usr/bin/ssh";
const ENV_SUPPRESS: &str = "SSH_LOG_SUPPRESS";

fn main() {
    let args: Vec<ffi::OsString> = env::args_os().skip(1).collect();

    let code = if env::var_os(ENV_SUPPRESS).is_some() {
        run_original(&args)
    } else {
        let _config = configuration(&args).expect("TODO");
        run_logged(&args)
    };

    process::exit(code.unwrap_or(255));
}

fn run_original(args: &[ffi::OsString]) -> io::Result<i32> {
    Err(process::Command::new(SSH).args(args).exec())
}

fn run_logged(args: &[ffi::OsString]) -> io::Result<i32> {
    let (_, path) = tempfile::Builder::new()
        .prefix("ssh-")
        .suffix(".log")
        .tempfile()?
        .keep()?;

    eprintln!("{}", path.display());

    Err(process::Command::new(SSH)
        .arg("-oLogLevel=DEBUG3")
        .arg("-E")
        .arg(path)
        .args(args)
        .exec())
}

fn configuration(args: &[ffi::OsString]) -> io::Result<process::Output> {
    process::Command::new(SSH)
        .arg("-G")
        .args(args)
        .stdin(process::Stdio::inherit())
        .stderr(process::Stdio::null())
        .output()
}
