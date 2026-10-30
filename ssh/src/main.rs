use std::env;
use std::ffi;
use std::fs;
use std::io;
use std::os::unix;
use std::process;
use std::thread;
use std::time;

const SSH: &str = "/usr/bin/ssh";

fn main() {
    process::exit(run().unwrap_or(255));
}

fn configuration(args: &[ffi::OsString]) -> io::Result<process::Output> {
    process::Command::new(SSH)
        .arg("-G")
        .args(args)
        .stdin(process::Stdio::inherit())
        .stderr(process::Stdio::null())
        .output()
}

fn visible(line: &[u8], level: &str, channel_dump: &mut bool) -> bool {
    let text = line.trim_ascii_end();
    let continuation = *channel_dump && (line.starts_with(b"  #") || text.is_empty());
    *channel_dump = if continuation {
        !text.is_empty()
    } else {
        line.starts_with(b"debug3: channel ")
            && text.ends_with(b": status: The following connections are open:")
    };
    if continuation {
        return level == "DEBUG3";
    }
    if [
        b"Authenticated to ".as_slice(),
        b"Transferred: sent ",
        b"Bytes per second: sent ",
    ]
    .iter()
    .any(|prefix| line.starts_with(prefix))
    {
        return matches!(level, "VERBOSE" | "DEBUG" | "DEBUG1" | "DEBUG2" | "DEBUG3");
    }
    match level {
        "QUIET" => false,
        "DEBUG3" => true,
        "DEBUG2" => !line.starts_with(b"debug3: "),
        "DEBUG" | "DEBUG1" => !line.starts_with(b"debug2: ") && !line.starts_with(b"debug3: "),
        _ => {
            !line.starts_with(b"debug1: ")
                && !line.starts_with(b"debug2: ")
                && !line.starts_with(b"debug3: ")
        }
    }
}

fn run() -> io::Result<i32> {
    let original: Vec<_> = env::args_os().skip(1).collect();
    let mut command = process::Command::new(SSH);
    if env::var_os("SSH_LOG_SUPPRESS").is_some() {
        return Err(unix::process::CommandExt::exec(command.args(original)));
    }
    let config = configuration(&original)?;
    let config_text = String::from_utf8_lossy(&config.stdout);
    let level = config_text
        .lines()
        .find_map(|line| line.strip_prefix("loglevel "));
    let Some(level) = level.filter(|_| config.status.success()) else {
        return Err(unix::process::CommandExt::exec(command.args(original)));
    };
    let (log, path) = tempfile::Builder::new()
        .prefix("ssh-log-")
        .suffix(".log")
        .tempfile()?
        .keep()?;
    let child = command
        .arg("-oLogLevel=DEBUG3")
        .arg("-E")
        .arg(path)
        .args(&original)
        .spawn()?;
    capture(child, log, level)
}

fn capture(mut child: process::Child, log: fs::File, level: &str) -> io::Result<i32> {
    let mut reader = io::BufReader::new(log);
    let mut line = Vec::new();
    let mut channel_dump = false;
    loop {
        let status = child.try_wait()?;
        while io::BufRead::read_until(&mut reader, b'\n', &mut line)? != 0 {
            if line.ends_with(b"\n") {
                if visible(&line, level, &mut channel_dump) {
                    let _ = io::Write::write_all(&mut io::stderr(), &line);
                }
                line.clear();
            }
        }
        if let Some(status) = status {
            if !line.is_empty() && visible(&line, level, &mut channel_dump) {
                let _ = io::Write::write_all(&mut io::stderr(), &line);
            }
            return Ok(status.code().unwrap_or_else(|| {
                128 + unix::process::ExitStatusExt::signal(&status).unwrap_or(0)
            }));
        }
        thread::sleep(time::Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn unprefixed_verbose_messages() {
        for line in [
            b"Authenticated to 10.0.0.54 ([10.0.0.54]:22) using \"publickey\".\r\n".as_slice(),
            b"Transferred: sent 4180, received 3876 bytes, in 4.2 seconds\r\n",
            b"Bytes per second: sent 995.5, received 923.1\r\n",
        ] {
            for level in [
                "QUIET", "FATAL", "ERROR", "INFO", "VERBOSE", "DEBUG", "DEBUG1", "DEBUG2", "DEBUG3",
            ] {
                assert_eq!(
                    super::visible(line, level, &mut false),
                    matches!(level, "VERBOSE" | "DEBUG" | "DEBUG1" | "DEBUG2" | "DEBUG3"),
                    "{level}: {line:?}",
                );
            }
        }
    }

    #[test]
    fn multiline_channel_status() {
        for level in ["QUIET", "INFO", "VERBOSE", "DEBUG1", "DEBUG2", "DEBUG3"] {
            let mut channel_dump = false;
            for line in [
                b"debug3: channel 0: status: The following connections are open:\r\n".as_slice(),
                b"  #0 client-session (t4 [session] r0 nm0 i3/0 o3/0 e[write]/0 fd -1/-1/7 sock -1 cc -1 nc0 io 0x00/0x00 RTI)\r\n",
                b"  #1 direct-tcpip (t4 [session])\r\n",
                b"\r\n",
            ] {
                assert_eq!(super::visible(line, level, &mut channel_dump), level == "DEBUG3");
            }
            assert!(!channel_dump);
        }
    }

    #[test]
    fn channel_rows_require_the_dump_header() {
        let mut channel_dump = false;
        assert!(super::visible(
            b"  #0 unrelated\r\n",
            "INFO",
            &mut channel_dump
        ));
        assert!(!super::visible(
            b"debug3: channel 0: status: The following connections are open:\n",
            "INFO",
            &mut channel_dump
        ));
        assert!(super::visible(
            b"Connection to 10.0.0.54 closed.\r\n",
            "INFO",
            &mut channel_dump
        ));
        assert!(super::visible(
            b"  #0 unrelated\r\n",
            "INFO",
            &mut channel_dump
        ));
    }
}
