pub mod classify;

use std::env;
use std::ffi;
use std::fs;
use std::io;
use std::os::unix::process::CommandExt as _;
use std::process;
use std::sync::mpsc;
use std::thread;
use std::time;

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

fn configuration(args: &[ffi::OsString]) -> io::Result<process::Output> {
    process::Command::new(SSH)
        .arg("-G")
        .args(args)
        .stdin(process::Stdio::inherit())
        .stderr(process::Stdio::null())
        .output()
}

fn run_original(args: &[ffi::OsString]) -> io::Result<i32> {
    Err(process::Command::new(SSH).args(args).exec())
}

fn run_logged(args: &[ffi::OsString]) -> io::Result<i32> {
    let (file, path) = tempfile::Builder::new()
        .prefix("ssh-")
        .suffix(".log")
        .tempfile()?
        .keep()?;

    eprintln!("{}", path.display());

    let (done, stopped) = mpsc::channel();
    let tail = thread::spawn(move || -> io::Result<()> {
        let mut log = classify::Decoder::new(LogTailer {
            file,
            done: stopped,
        });
        while let Some(message) = log.read_message()? {
            if message.level < classify::Level::Verbose {
                io::Write::write_all(&mut io::stderr().lock(), message.bytes)?;
            }
        }
        Ok(())
    });

    let status = process::Command::new(SSH)
        .arg("-oLogLevel=DEBUG3")
        .arg("-E")
        .arg(path)
        .args(args)
        .status();

    drop(done);
    tail.join()
        .unwrap()
        .and(status)
        .map(|status| status.code().unwrap_or(255))
}

struct LogTailer {
    file: fs::File,
    done: mpsc::Receiver<()>,
}

impl io::Read for LogTailer {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        loop {
            let count = io::Read::read(&mut self.file, bytes)?;
            if count != 0 || bytes.is_empty() {
                return Ok(count);
            }
            match self.done.recv_timeout(time::Duration::from_millis(10)) {
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                _ => return io::Read::read(&mut self.file, bytes),
            }
        }
    }
}
