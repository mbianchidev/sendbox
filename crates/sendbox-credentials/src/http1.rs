use std::str::FromStr;

use http::{HeaderName, HeaderValue, Method, Uri};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    time::timeout,
};

use crate::{BrokerLimits, CredentialBrokerError};

const HEADER_END: &[u8] = b"\r\n\r\n";
const READ_CHUNK_BYTES: usize = 1024;

#[derive(Debug)]
pub(crate) struct ParsedRequest {
    pub method: Method,
    pub target: String,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub body: Vec<u8>,
}

pub(crate) async fn read_request(
    reader: &mut (impl AsyncRead + Unpin),
    limits: &BrokerLimits,
    max_body_bytes: usize,
    cancellation: &sendbox_runtime::CancellationToken,
) -> Result<ParsedRequest, CredentialBrokerError> {
    let read = async {
        tokio::select! {
            result = read_request_inner(reader, limits, max_body_bytes) => result,
            () = cancellation.cancelled() => Err(CredentialBrokerError::Cancelled),
        }
    };
    timeout(limits.request_read_timeout, read)
        .await
        .map_err(|_| CredentialBrokerError::RequestTimeout)?
}

async fn read_request_inner(
    reader: &mut (impl AsyncRead + Unpin),
    limits: &BrokerLimits,
    max_body_bytes: usize,
) -> Result<ParsedRequest, CredentialBrokerError> {
    let mut bytes = Vec::with_capacity(limits.max_header_bytes.min(8 * 1024));
    let header_end = loop {
        if let Some(index) = find_header_end(&bytes) {
            break index;
        }
        if bytes.len() >= limits.max_header_bytes {
            return Err(CredentialBrokerError::InvalidRequest(
                "request headers exceed the configured limit",
            ));
        }
        let remaining = limits.max_header_bytes.saturating_sub(bytes.len());
        let mut chunk = [0_u8; READ_CHUNK_BYTES];
        let read_limit = chunk.len().min(remaining);
        let read = reader.read(&mut chunk[..read_limit]).await?;
        if read == 0 {
            return Err(CredentialBrokerError::InvalidRequest(
                "request ended before the headers were complete",
            ));
        }
        bytes.extend_from_slice(&chunk[..read]);
    };

    let content_length = parse_head(
        &bytes[..header_end],
        limits.max_request_line_bytes,
        limits.max_header_count,
    )?
    .1;
    if content_length > max_body_bytes {
        return Err(CredentialBrokerError::InvalidRequest(
            "request body exceeds the rule limit",
        ));
    }
    let total_length = header_end
        .checked_add(HEADER_END.len())
        .and_then(|length| length.checked_add(content_length))
        .ok_or(CredentialBrokerError::InvalidRequest(
            "request length overflowed",
        ))?;
    if bytes.len() > total_length {
        return Err(CredentialBrokerError::InvalidRequest(
            "request contains trailing or pipelined bytes",
        ));
    }
    while bytes.len() < total_length {
        let remaining = total_length - bytes.len();
        let mut chunk = [0_u8; READ_CHUNK_BYTES];
        let read_limit = chunk.len().min(remaining);
        let read = reader.read(&mut chunk[..read_limit]).await?;
        if read == 0 {
            return Err(CredentialBrokerError::InvalidRequest(
                "request body ended before Content-Length bytes were received",
            ));
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    parse_complete_request_with_limits(
        &bytes,
        limits.max_request_line_bytes,
        limits.max_header_count,
        max_body_bytes,
    )
}

pub(crate) fn parse_complete_request(
    bytes: &[u8],
    limits: &BrokerLimits,
) -> Result<ParsedRequest, CredentialBrokerError> {
    if bytes.len() > limits.max_header_bytes + sendbox_secrets::MAX_SECRET_VALUE_BYTES {
        return Err(CredentialBrokerError::InvalidRequest(
            "request exceeds the parser fuzzing limit",
        ));
    }
    parse_complete_request_with_limits(
        bytes,
        limits.max_request_line_bytes,
        limits.max_header_count,
        sendbox_secrets::MAX_SECRET_VALUE_BYTES,
    )
}

fn parse_complete_request_with_limits(
    bytes: &[u8],
    max_request_line_bytes: usize,
    max_header_count: usize,
    max_body_bytes: usize,
) -> Result<ParsedRequest, CredentialBrokerError> {
    let header_end = find_header_end(bytes).ok_or(CredentialBrokerError::InvalidRequest(
        "request headers are incomplete",
    ))?;
    let (mut request, content_length) = parse_head(
        &bytes[..header_end],
        max_request_line_bytes,
        max_header_count,
    )?;
    let body_start = header_end + HEADER_END.len();
    let body = bytes
        .get(body_start..)
        .ok_or(CredentialBrokerError::InvalidRequest(
            "request body boundary is invalid",
        ))?;
    if content_length > max_body_bytes || body.len() != content_length {
        return Err(CredentialBrokerError::InvalidRequest(
            "request body length does not match Content-Length",
        ));
    }
    request.body = body.to_vec();
    Ok(request)
}

fn parse_head(
    head: &[u8],
    max_request_line_bytes: usize,
    max_header_count: usize,
) -> Result<(ParsedRequest, usize), CredentialBrokerError> {
    reject_bare_line_feeds(head)?;
    let mut raw_lines = head.split(|byte| *byte == b'\n').peekable();
    let mut lines = std::iter::from_fn(move || {
        raw_lines.next().map(|line| {
            if raw_lines.peek().is_none() {
                Ok(line)
            } else {
                line.strip_suffix(b"\r")
                    .ok_or(CredentialBrokerError::InvalidRequest(
                        "HTTP lines must use CRLF",
                    ))
            }
        })
    });
    let request_line = lines.next().ok_or(CredentialBrokerError::InvalidRequest(
        "request line is missing",
    ))??;
    if request_line.len() > max_request_line_bytes {
        return Err(CredentialBrokerError::InvalidRequest(
            "request line exceeds the configured limit",
        ));
    }
    let request_line = std::str::from_utf8(request_line).map_err(|_| {
        CredentialBrokerError::InvalidRequest("request line is not valid ASCII-compatible UTF-8")
    })?;
    let mut parts = request_line.split(' ');
    let method = parts.next().filter(|value| !value.is_empty()).ok_or(
        CredentialBrokerError::InvalidRequest("request method is missing"),
    )?;
    let target = parts.next().filter(|value| !value.is_empty()).ok_or(
        CredentialBrokerError::InvalidRequest("request target is missing"),
    )?;
    let version = parts.next().ok_or(CredentialBrokerError::InvalidRequest(
        "HTTP version is missing",
    ))?;
    if parts.next().is_some() || version != "HTTP/1.1" {
        return Err(CredentialBrokerError::InvalidRequest(
            "only canonical HTTP/1.1 request lines are supported",
        ));
    }
    let method = Method::from_bytes(method.as_bytes())
        .map_err(|_| CredentialBrokerError::InvalidRequest("request method is invalid"))?;
    if method == Method::CONNECT {
        return Err(CredentialBrokerError::InvalidRequest(
            "CONNECT credential injection is unsupported",
        ));
    }
    validate_origin_form_target(target)?;

    let mut headers = Vec::new();
    let mut host_count = 0_usize;
    let mut content_length = None;
    for line in lines {
        let line = line?;
        if line.is_empty() {
            return Err(CredentialBrokerError::InvalidRequest(
                "unexpected empty header line",
            ));
        }
        if line.first().is_some_and(u8::is_ascii_whitespace) {
            return Err(CredentialBrokerError::InvalidRequest(
                "obsolete folded headers are forbidden",
            ));
        }
        if headers.len() >= max_header_count {
            return Err(CredentialBrokerError::InvalidRequest(
                "request has too many headers",
            ));
        }
        let colon = line.iter().position(|byte| *byte == b':').ok_or(
            CredentialBrokerError::InvalidRequest("header is missing ':'"),
        )?;
        if colon == 0 || line[colon - 1].is_ascii_whitespace() {
            return Err(CredentialBrokerError::InvalidRequest(
                "header name is malformed",
            ));
        }
        let name = HeaderName::from_bytes(&line[..colon])
            .map_err(|_| CredentialBrokerError::InvalidRequest("header name is invalid"))?;
        let value = trim_optional_whitespace(&line[colon + 1..]);
        let value = HeaderValue::from_bytes(value)
            .map_err(|_| CredentialBrokerError::InvalidRequest("header value is invalid"))?;
        if name == http::header::HOST {
            host_count += 1;
        } else if name == http::header::CONTENT_LENGTH {
            if content_length.is_some() {
                return Err(CredentialBrokerError::InvalidRequest(
                    "duplicate Content-Length is forbidden",
                ));
            }
            content_length = Some(parse_content_length(value.as_bytes())?);
        } else if name == http::header::TRANSFER_ENCODING {
            return Err(CredentialBrokerError::InvalidRequest(
                "Transfer-Encoding is unsupported",
            ));
        }
        headers.push((name, value));
    }
    if host_count != 1 {
        return Err(CredentialBrokerError::InvalidRequest(
            "exactly one Host header is required",
        ));
    }
    Ok((
        ParsedRequest {
            method,
            target: target.to_owned(),
            headers,
            body: Vec::new(),
        },
        content_length.unwrap_or(0),
    ))
}

fn validate_origin_form_target(target: &str) -> Result<(), CredentialBrokerError> {
    if !target.starts_with('/')
        || target.starts_with("//")
        || target.contains(['\\', '#'])
        || target.chars().any(char::is_control)
    {
        return Err(CredentialBrokerError::InvalidRequest(
            "request target must use safe origin-form",
        ));
    }
    let uri = Uri::from_str(target)
        .map_err(|_| CredentialBrokerError::InvalidRequest("request target is invalid"))?;
    if uri.scheme().is_some() || uri.authority().is_some() || uri.path().is_empty() {
        return Err(CredentialBrokerError::InvalidRequest(
            "absolute-form and authority-form targets are forbidden",
        ));
    }
    Ok(())
}

fn reject_bare_line_feeds(bytes: &[u8]) -> Result<(), CredentialBrokerError> {
    if bytes.iter().enumerate().any(|(index, byte)| {
        *byte == b'\n' && index.checked_sub(1).is_none_or(|i| bytes[i] != b'\r')
    }) {
        return Err(CredentialBrokerError::InvalidRequest(
            "HTTP lines must use CRLF",
        ));
    }
    Ok(())
}

fn parse_content_length(bytes: &[u8]) -> Result<usize, CredentialBrokerError> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(CredentialBrokerError::InvalidRequest(
            "Content-Length must be an unsigned decimal integer",
        ));
    }
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .ok_or(CredentialBrokerError::InvalidRequest(
            "Content-Length is too large",
        ))
}

fn trim_optional_whitespace(mut bytes: &[u8]) -> &[u8] {
    while bytes
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        bytes = &bytes[1..];
    }
    while bytes
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(HEADER_END.len())
        .position(|window| window == HEADER_END)
}

pub(crate) fn strip_hop_by_hop(
    headers: &[(HeaderName, HeaderValue)],
) -> Vec<(HeaderName, HeaderValue)> {
    let mut connection_named = Vec::new();
    for (name, value) in headers {
        if name == http::header::CONNECTION
            && let Ok(value) = value.to_str()
        {
            connection_named.extend(
                value.split(',').filter_map(|candidate| {
                    HeaderName::from_bytes(candidate.trim().as_bytes()).ok()
                }),
            );
        }
    }
    headers
        .iter()
        .filter(|(name, _)| {
            !is_hop_by_hop(name)
                && !connection_named.iter().any(|candidate| candidate == name)
                && name != http::header::HOST
                && name != http::header::CONTENT_LENGTH
        })
        .cloned()
        .collect()
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn limits() -> BrokerLimits {
        BrokerLimits::default()
    }

    #[test]
    fn parses_canonical_request() {
        let request = parse_complete_request(
            b"POST /credentials/api/v1/messages?q=1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\nContent-Length: 2\r\n\r\n{}",
            &limits(),
        )
        .expect("request");
        assert_eq!(request.method, Method::POST);
        assert_eq!(request.body, b"{}");
    }

    #[test]
    fn rejects_smuggling_and_header_ambiguity() {
        for bytes in [
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n"
                .as_slice(),
            b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: x\r\nHost: y\r\n\r\n",
            b"GET / HTTP/1.1\nHost: x\n\n",
            b"GET / HTTP/1.1\r\nHost : x\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: x\r\n folded\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: x\r\n\r\nGET /two HTTP/1.1\r\nHost: x\r\n\r\n",
        ] {
            assert!(parse_complete_request(bytes, &limits()).is_err());
        }
    }

    #[test]
    fn rejects_connect_and_absolute_form() {
        for bytes in [
            b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com\r\n\r\n".as_slice(),
            b"GET https://api.example.com/ HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
        ] {
            assert!(parse_complete_request(bytes, &limits()).is_err());
        }
    }

    proptest! {
        #[test]
        fn parser_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let _ = parse_complete_request(&bytes, &limits());
        }

        #[test]
        fn duplicate_content_length_is_always_rejected(length in 0_usize..1024) {
            let request = format!(
                "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: {length}\r\nContent-Length: {length}\r\n\r\n"
            );
            prop_assert!(parse_complete_request(request.as_bytes(), &limits()).is_err());
        }
    }
}
