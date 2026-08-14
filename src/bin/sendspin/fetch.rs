// ABOUTME: Fetching a source over HTTP so `serve --source` takes a URL as well as a path, with
// ABOUTME: a request small enough not to be worth a dependency.

//! A one-request HTTP client.
//!
//! Deliberately not a general one. All this has to do is issue a `GET`, follow a redirect or
//! two, skip the headers and hand back the body — for a stream that may never end. A crate that
//! did it properly would bring a runtime's worth of machinery for a server-side convenience,
//! and the point of `serve` living behind its own feature is that a player build carries none
//! of it.
//!
//! What it does not do: chunked transfer coding, compression, cookies, authentication. A source
//! that needs any of those is better fetched by something else and handed over as a file.

use std::io::{BufRead, BufReader, Read};
use std::net::TcpStream;

/// How many redirects to follow before deciding a server is playing games.
const MAX_REDIRECTS: usize = 3;

/// A body being read, over whichever transport the scheme called for.
pub enum Body {
    /// Plain HTTP.
    Plain(BufReader<TcpStream>),
    /// HTTP over TLS.
    #[cfg(feature = "native-tls")]
    Tls(Box<BufReader<native_tls::TlsStream<TcpStream>>>),
}

impl Read for Body {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buffer),
            #[cfg(feature = "native-tls")]
            Self::Tls(stream) => stream.read(buffer),
        }
    }
}

/// Whether a source is a URL this module can fetch.
pub fn is_url(source: &str) -> bool {
    source.starts_with("http://") || source.starts_with("https://")
}

/// Issue a `GET` and return the body with the length the server declared, if any.
///
/// The length is what separates a file from a broadcast: a track has one and is played from
/// its beginning, a stream has none and is played from wherever it is now.
///
/// Blocking, because it is called once at startup before anything is playing, and the reader
/// it returns is driven from a thread of its own.
pub fn get(url: &str) -> Result<(Body, Option<usize>), String> {
    let mut url = url.to_string();
    for _ in 0..=MAX_REDIRECTS {
        match request(&url)? {
            Fetched::Body(body, length) => return Ok((body, length)),
            Fetched::Redirect(location) => {
                log::info!("Source redirected to {location}");
                url = location;
            }
        }
    }
    Err(format!("{url} redirected more than {MAX_REDIRECTS} times"))
}

enum Fetched {
    Body(Body, Option<usize>),
    Redirect(String),
}

fn request(url: &str) -> Result<Fetched, String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| format!("{url} is not a URL"))?;
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        // An IPv6 literal's colons are inside brackets, so a colon after the closing one is
        // the port and any other belongs to the address.
        Some((host, port)) if !host.contains('[') || host.contains(']') => (
            host,
            port.parse::<u16>()
                .map_err(|_| format!("{port:?} is not a port"))?,
        ),
        _ => (authority, if scheme == "https" { 443 } else { 80 }),
    };

    let stream = TcpStream::connect((host, port))
        .map_err(|e| format!("could not reach {host}:{port}: {e}"))?;
    // The request a stream server expects and nothing more. `Icy-MetaData` is deliberately not
    // asked for: metadata interleaved into the audio would have to be stripped back out, and a
    // title is not what this is fetching.
    let head = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: sendspin-rs\r\nConnection: close\r\n\
         Accept: */*\r\n\r\n"
    );

    match scheme {
        "http" => {
            let mut reader = BufReader::new(stream);
            write_request(reader.get_mut(), &head)?;
            finish(reader).map(|either| match either {
                Ok((reader, length)) => Fetched::Body(Body::Plain(reader), length),
                Err(location) => Fetched::Redirect(location),
            })
        }
        #[cfg(feature = "native-tls")]
        "https" => {
            let connector =
                native_tls::TlsConnector::new().map_err(|e| format!("could not start TLS: {e}"))?;
            let stream = connector
                .connect(host, stream)
                .map_err(|e| format!("TLS handshake with {host} failed: {e}"))?;
            let mut reader = BufReader::new(stream);
            write_request(reader.get_mut(), &head)?;
            finish(reader).map(|either| match either {
                Ok((reader, length)) => Fetched::Body(Body::Tls(Box::new(reader)), length),
                Err(location) => Fetched::Redirect(location),
            })
        }
        #[cfg(not(feature = "native-tls"))]
        "https" => Err(format!(
            "{url} needs TLS, which this build has not got. Rebuild with the `native-tls` \
             feature, or fetch it with something else and pass the file."
        )),
        other => Err(format!("{other}:// is not a scheme this can fetch")),
    }
}

fn write_request(stream: &mut impl std::io::Write, head: &str) -> Result<(), String> {
    stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.flush())
        .map_err(|e| format!("could not send the request: {e}"))
}

/// Read the status line and headers, leaving the reader at the first byte of the body.
///
/// `Err(location)` is a redirect rather than a failure; the caller follows it.
#[allow(clippy::type_complexity)]
fn finish<R: Read>(
    mut reader: BufReader<R>,
) -> Result<Result<(BufReader<R>, Option<usize>), String>, String> {
    let mut status = String::new();
    reader
        .read_line(&mut status)
        .map_err(|e| format!("could not read the response: {e}"))?;
    // `ICY 200 OK` where a stream server answers in its own dialect rather than HTTP's; the
    // shape is the same and the code is in the same place.
    let code = status
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| {
            format!(
                "the server answered {:?}, which is not a status",
                status.trim()
            )
        })?;

    let mut location = None;
    let mut length = None;
    loop {
        let mut line = String::new();
        let read = reader
            .read_line(&mut line)
            .map_err(|e| format!("could not read the response headers: {e}"))?;
        if read == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("location") {
                location = Some(value.trim().to_string());
            } else if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse::<usize>().ok();
            }
        }
    }

    match code {
        200 | 206 => Ok(Ok((reader, length))),
        301 | 302 | 303 | 307 | 308 => match location {
            Some(location) => Ok(Err(location)),
            None => Err(format!("the server sent {code} with no Location to follow")),
        },
        other => Err(format!("the server answered {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_is_not_mistaken_for_a_url() {
        assert!(is_url("http://example/stream"));
        assert!(is_url("https://example/stream"));
        assert!(!is_url("/music/track.flac"));
        assert!(!is_url("track.flac"));
        // A Windows drive letter has a colon too, and is still a path.
        assert!(!is_url("C:/music/track.wav"));
    }

    /// A stream server that answers in ICY's dialect rather than HTTP's is still answering.
    #[test]
    fn an_icy_status_line_is_read_like_an_http_one() {
        let response = b"ICY 200 OK\r\nicy-name: Test\r\n\r\nBODY".to_vec();
        let reader = BufReader::new(std::io::Cursor::new(response));
        let (mut body, _) = finish(reader).unwrap().unwrap();
        let mut rest = Vec::new();
        body.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"BODY");
    }

    #[test]
    fn a_redirect_is_handed_back_rather_than_followed_here() {
        let response = b"HTTP/1.1 302 Found\r\nLocation: http://elsewhere/s\r\n\r\n".to_vec();
        let reader = BufReader::new(std::io::Cursor::new(response));
        let redirect = finish(reader).unwrap().unwrap_err();
        assert_eq!(redirect, "http://elsewhere/s");
    }

    /// The length is what tells a track from a broadcast, so it has to survive the headers.
    #[test]
    fn a_declared_length_is_carried_out_of_the_headers() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 4242\r\n\r\nBODY".to_vec();
        let reader = BufReader::new(std::io::Cursor::new(response));
        let (_, length) = finish(reader).unwrap().unwrap();
        assert_eq!(length, Some(4242));

        // A broadcast declares none, and that absence is the signal.
        let response = b"ICY 200 OK\r\nicy-name: Test\r\n\r\nBODY".to_vec();
        let reader = BufReader::new(std::io::Cursor::new(response));
        let (_, length) = finish(reader).unwrap().unwrap();
        assert_eq!(length, None);
    }

    #[test]
    fn a_refusal_says_what_the_server_answered() {
        let response = b"HTTP/1.1 404 Not Found\r\n\r\n".to_vec();
        let reader = BufReader::new(std::io::Cursor::new(response));
        let error = finish(reader).unwrap_err();
        assert!(error.contains("404"), "{error}");
    }
}
