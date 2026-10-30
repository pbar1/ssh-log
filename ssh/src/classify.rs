use std::io;
use std::sync;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Unknown,
    Fatal,
    Error,
    Info,
    Verbose,
    Debug1,
    Debug2,
    Debug3,
}

#[derive(Debug)]
pub struct Message<'a> {
    pub level: Level,
    pub bytes: &'a [u8],
}

pub struct Decoder<R> {
    reader: R,
    buffer: bytes::BytesMut,
    consumed: usize,
    eof: bool,
}

impl<R: io::Read> Decoder<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            buffer: bytes::BytesMut::with_capacity(8192),
            consumed: 0,
            eof: false,
        }
    }

    pub fn read_message(&mut self) -> io::Result<Option<Message<'_>>> {
        bytes::Buf::advance(&mut self.buffer, self.consumed);
        self.consumed = 0;
        let Some(mut end) = self.line_end(0)? else {
            return Ok(None);
        };
        let (level, mut tail) = sniff(self.buffer[..end].trim_ascii_end());
        while !matches!(tail, Tail::None) {
            let Some(next) = self.line_end(end)? else {
                break;
            };
            if !tail.accept(self.buffer[end..next].trim_ascii_end()) {
                break;
            }
            end = next;
        }
        self.consumed = end;
        Ok(Some(Message {
            level,
            bytes: &self.buffer[..end],
        }))
    }

    fn line_end(&mut self, start: usize) -> io::Result<Option<usize>> {
        let mut scan = start;
        loop {
            if let Some(offset) = self.buffer[scan..].iter().position(|&b| b == b'\n') {
                return Ok(Some(scan + offset + 1));
            }
            let len = self.buffer.len();
            if self.eof {
                return Ok((len > start).then_some(len));
            }
            scan = len;
            self.buffer.resize(len + 8192, 0);
            let result = self.reader.read(&mut self.buffer[len..]);
            self.buffer
                .truncate(len + result.as_ref().copied().unwrap_or(0));
            match result {
                Ok(0) => self.eof = true,
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }
}

enum Tail {
    None,
    Lines(u8),
    Channels,
    ArtStart,
    Art,
    HostKey,
    MatchingKey,
}

impl Tail {
    fn accept(&mut self, line: &[u8]) -> bool {
        match self {
            Self::None => false,
            Self::Lines(remaining) => {
                *remaining -= 1;
                if *remaining == 0 {
                    *self = Self::None;
                }
                true
            }
            Self::Channels => {
                if line.is_empty() {
                    *self = Self::None;
                    true
                } else {
                    line.starts_with(b"  #")
                }
            }
            Self::ArtStart => {
                if art_border(line) {
                    *self = Self::Art;
                    true
                } else {
                    false
                }
            }
            Self::Art => {
                if art_border(line) {
                    *self = Self::None;
                    true
                } else {
                    line.starts_with(b"|") && line.ends_with(b"|")
                }
            }
            Self::HostKey => {
                *self = Self::MatchingKey;
                line.starts_with(b"Offending key for IP in ")
            }
            Self::MatchingKey => {
                *self = Self::None;
                line.starts_with(b"Matching host key in ")
            }
        }
    }
}

fn art_border(line: &[u8]) -> bool {
    line.len() == 19 && line.starts_with(b"+") && line.ends_with(b"+")
}

fn sniff(line: &[u8]) -> (Level, Tail) {
    if line.starts_with(b"debug3: channel ")
        && line.ends_with(b": status: The following connections are open:")
    {
        return (Level::Debug3, Tail::Channels);
    }
    if line.starts_with(b"Host key fingerprint is: ") {
        return (Level::Unknown, Tail::ArtStart);
    }
    if art_border(line) {
        return (Level::Unknown, Tail::Art);
    }
    if line.starts_with(b"The fingerprint for the ")
        && line.ends_with(b" key sent by the remote host is")
    {
        return (Level::Unknown, Tail::Lines(1));
    }
    if line.starts_with(b"WARNING: ") && contains(line, b" key found for host ") {
        return (Level::Unknown, Tail::Lines(2));
    }
    if line.starts_with(b"Warning: the ")
        && contains(line, b"differs from the key for the IP address")
    {
        return (Level::Unknown, Tail::HostKey);
    }
    for (prefix, level) in [
        (b"debug1: ", Level::Debug1),
        (b"debug2: ", Level::Debug2),
        (b"debug3: ", Level::Debug3),
    ] {
        if line.starts_with(prefix) {
            return (level, Tail::None);
        }
    }
    let level = if VERBOSE.is_match(line) {
        Level::Verbose
    } else {
        Level::Unknown
    };
    (level, Tail::None)
}

fn contains(line: &[u8], needle: &[u8]) -> bool {
    line.windows(needle.len()).any(|part| part == needle)
}

// OpenSSH portable e4d03fb, unambiguous VERBOSE formats.
static VERBOSE: sync::LazyLock<regex::bytes::RegexSet> = sync::LazyLock::new(|| {
    regex::bytes::RegexSetBuilder::new(include_str!("classify/verbose.regex").lines())
        .unicode(false)
        .build()
        .expect("invalid built-in SSH log matcher")
});
