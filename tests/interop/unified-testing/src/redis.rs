//! Just enough RESP for the interop harnesses' coordination keys.
//!
//! The suites disagree on the key's type: transport and test-plans use a
//! list (`RPUSH` / `BLPOP`), relay and hole-punch a string (`SET` / `GET`).
//! [`Redis::command`] sends either; [`Redis::wait_get`] is the string side's
//! polling read.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use crate::Result;

pub struct Redis {
    reader: BufReader<TcpStream>,
}

impl Redis {
    pub fn connect(addr: &str) -> Result<Self> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match TcpStream::connect(addr) {
                Ok(stream) => {
                    return Ok(Self {
                        reader: BufReader::new(stream),
                    });
                }
                Err(e) if Instant::now() >= deadline => {
                    return Err(format!("redis {addr}: {e}").into());
                }
                Err(_) => std::thread::sleep(Duration::from_millis(200)),
            }
        }
    }

    /// Sends one command; returns the reply's bulk strings (empty for an
    /// integer, simple-string or null reply).
    pub fn command(&mut self, args: &[&str]) -> Result<Vec<String>> {
        let mut request = format!("*{}\r\n", args.len());
        for arg in args {
            request.push_str(&format!("${}\r\n{arg}\r\n", arg.len()));
        }
        self.reader.get_mut().write_all(request.as_bytes())?;
        self.read_reply()
    }

    /// Polls `GET key` until another container has set it.
    pub fn wait_get(&mut self, key: &str, timeout: Duration) -> Result<String> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(value) = self.command(&["GET", key])?.pop() {
                return Ok(value);
            }
            if Instant::now() >= deadline {
                return Err(format!("timed out waiting for redis key {key}").into());
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    fn read_reply(&mut self) -> Result<Vec<String>> {
        let line = self.read_line()?;
        let (kind, rest) = line.split_at(1);
        match kind {
            "+" | ":" => Ok(Vec::new()),
            "-" => Err(format!("redis: {rest}").into()),
            "$" => Ok(self.read_bulk(rest.parse()?)?.into_iter().collect()),
            "*" => {
                let n: i64 = rest.parse()?;
                let mut items = Vec::new();
                for _ in 0..n.max(0) {
                    let header = self.read_line()?;
                    let len = header
                        .strip_prefix('$')
                        .ok_or("redis: expected bulk string")?;
                    items.extend(self.read_bulk(len.parse()?)?);
                }
                Ok(items)
            }
            _ => Err(format!("redis: unexpected reply {line:?}").into()),
        }
    }

    fn read_bulk(&mut self, len: i64) -> Result<Option<String>> {
        if len < 0 {
            return Ok(None);
        }
        let mut buf = vec![0; usize::try_from(len)? + 2];
        self.reader.read_exact(&mut buf)?;
        buf.truncate(buf.len() - 2);
        Ok(Some(String::from_utf8(buf)?))
    }

    fn read_line(&mut self) -> Result<String> {
        let mut line = String::new();
        if self.reader.read_line(&mut line)? == 0 {
            return Err("redis closed the connection".into());
        }
        Ok(line.trim_end_matches("\r\n").to_owned())
    }
}
