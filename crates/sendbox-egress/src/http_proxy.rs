use std::io;
use std::net::IpAddr;

use http::{Method, Uri, uri::Authority};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::connect_proto::{ConnectStatus, ConnectTarget};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_HEADERS: usize = 64;

pub(crate) struct HttpProxyRequest {
    pub target: ConnectTarget,
    pub port: u16,
    pub prefetched: Vec<u8>,
    pub forwarded_head: Option<Vec<u8>>,
}

pub(crate) async fn read_request<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> io::Result<HttpProxyRequest> {
    let mut bytes = Vec::new();
    let mut chunk = [0; 4096];
    let header_end = loop {
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let end = end + 4;
            if end > MAX_HEADER_BYTES {
                return Err(invalid("HTTP proxy header exceeds its byte limit"));
            }
            break end;
        }
        if bytes.len() >= MAX_HEADER_BYTES {
            return Err(invalid("HTTP proxy header exceeds its byte limit"));
        }
        let count = stream.read(&mut chunk).await?;
        if count == 0 {
            return Err(invalid("HTTP proxy handshake is incomplete"));
        }
        bytes.extend_from_slice(&chunk[..count]);
    };
    let prefetched = bytes.split_off(header_end);
    if bytes.iter().enumerate().any(|(index, byte)| {
        (*byte == b'\n' && (index == 0 || bytes[index - 1] != b'\r'))
            || (*byte == b'\r' && bytes.get(index + 1) != Some(&b'\n'))
    }) {
        return Err(invalid("HTTP proxy headers require CRLF framing"));
    }
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    if request
        .parse(&bytes)
        .map_err(|_| invalid("invalid HTTP proxy header"))?
        != httparse::Status::Complete(header_end)
        || !matches!(request.version, Some(0 | 1))
    {
        return Err(invalid("HTTP proxy requires an HTTP/1.x request"));
    }
    let method = request
        .method
        .ok_or_else(|| invalid("HTTP proxy method is missing"))?
        .parse::<Method>()
        .map_err(|_| invalid("invalid HTTP proxy method"))?;
    let destination = request
        .path
        .ok_or_else(|| invalid("HTTP proxy target is missing"))?;
    let tunnel = method == Method::CONNECT;
    let (target, port, path) = if tunnel {
        let (target, port) = parse_authority(destination, None)?;
        (target, port, None)
    } else {
        let uri = destination
            .parse::<Uri>()
            .map_err(|_| invalid("invalid HTTP forward proxy URL"))?;
        if uri.scheme_str() != Some("http") || destination.contains('#') {
            return Err(invalid(
                "HTTP forward proxy requires an absolute plaintext HTTP URL",
            ));
        }
        let authority = uri
            .authority()
            .ok_or_else(|| invalid("HTTP forward proxy URL has no authority"))?;
        let (target, port) = parse_authority(authority.as_str(), Some(80))?;
        (
            target,
            port,
            Some(
                uri.path_and_query()
                    .map_or("/", |path| path.as_str())
                    .to_owned(),
            ),
        )
    };
    let mut host_seen = false;
    let mut content_length_seen = false;
    let mut transfer_encoding_seen = false;
    let mut connection_fields = Vec::new();
    for header in request.headers.iter() {
        if header.name.eq_ignore_ascii_case("host") {
            if host_seen {
                return Err(invalid("duplicate HTTP proxy Host header"));
            }
            host_seen = true;
            let value = std::str::from_utf8(header.value)
                .map_err(|_| invalid("invalid HTTP proxy Host header"))?;
            if parse_authority(value, Some(if tunnel { port } else { 80 }))?
                != (target.clone(), port)
            {
                return Err(invalid("HTTP proxy Host does not match its target"));
            }
        }
        if header.name.eq_ignore_ascii_case("proxy-authorization") {
            return Err(invalid("HTTP proxy credentials are not supported"));
        }
        if header.name.eq_ignore_ascii_case("content-length") {
            if content_length_seen
                || header.value.is_empty()
                || !header.value.iter().all(u8::is_ascii_digit)
                || (tunnel && header.value != b"0")
            {
                return Err(invalid("invalid or duplicate HTTP proxy Content-Length"));
            }
            content_length_seen = true;
        }
        if header.name.eq_ignore_ascii_case("transfer-encoding") {
            if transfer_encoding_seen || tunnel || !header.value.eq_ignore_ascii_case(b"chunked") {
                return Err(invalid("invalid or duplicate HTTP proxy Transfer-Encoding"));
            }
            transfer_encoding_seen = true;
        }
        if header.name.eq_ignore_ascii_case("upgrade") {
            return Err(invalid("HTTP upgrades require a CONNECT tunnel"));
        }
        if header.name.eq_ignore_ascii_case("connection") {
            let value = std::str::from_utf8(header.value)
                .map_err(|_| invalid("invalid HTTP proxy Connection header"))?;
            for field in value.split(',').map(str::trim) {
                let field = field
                    .parse::<http::HeaderName>()
                    .map_err(|_| invalid("invalid HTTP proxy Connection field"))?;
                if matches!(
                    field.as_str(),
                    "host" | "content-length" | "transfer-encoding"
                ) {
                    return Err(invalid(
                        "HTTP proxy Connection cannot nominate routing or framing headers",
                    ));
                }
                connection_fields.push(field);
            }
        }
    }
    if content_length_seen && transfer_encoding_seen {
        return Err(invalid("HTTP proxy body framing is ambiguous"));
    }
    if !tunnel && !host_seen {
        return Err(invalid(
            "HTTP forward proxy requires one matching Host header",
        ));
    }
    let forwarded_head = path.map(|path| {
        let mut head = format!("{method} {path} HTTP/1.1\r\n").into_bytes();
        for header in request.headers.iter() {
            if [
                "connection",
                "proxy-connection",
                "keep-alive",
                "proxy-authenticate",
                "te",
            ]
            .iter()
            .any(|name| header.name.eq_ignore_ascii_case(name))
                || connection_fields
                    .iter()
                    .any(|name| header.name.eq_ignore_ascii_case(name.as_str()))
            {
                continue;
            }
            head.extend_from_slice(header.name.as_bytes());
            head.extend_from_slice(b": ");
            head.extend_from_slice(header.value);
            head.extend_from_slice(b"\r\n");
        }
        head.extend_from_slice(b"Connection: close\r\n\r\n");
        head
    });
    Ok(HttpProxyRequest {
        target,
        port,
        prefetched,
        forwarded_head,
    })
}

fn parse_authority(value: &str, default_port: Option<u16>) -> io::Result<(ConnectTarget, u16)> {
    if value.bytes().any(|byte| {
        byte.is_ascii_control()
            || byte.is_ascii_whitespace()
            || matches!(byte, b'@' | b'/' | b'\\' | b'?' | b'#' | b'%')
    }) {
        return Err(invalid("invalid HTTP proxy authority"));
    }
    let authority = value
        .parse::<Authority>()
        .map_err(|_| invalid("invalid HTTP proxy authority"))?;
    let explicit_port = if value.starts_with('[') {
        !value.ends_with(']')
    } else {
        value.contains(':')
    };
    if explicit_port && authority.port_u16().is_none() {
        return Err(invalid("HTTP proxy authority contains an invalid port"));
    }
    let port = authority
        .port_u16()
        .or(default_port)
        .filter(|port| *port != 0)
        .ok_or_else(|| invalid("HTTP proxy authority requires a valid port"))?;
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let target = match host.parse::<IpAddr>() {
        Ok(address) => ConnectTarget::Ip(crate::address::canonicalize(address)),
        Err(_) => ConnectTarget::Hostname(
            crate::domain::normalize_domain(host)
                .map_err(|_| invalid("invalid HTTP proxy hostname"))?,
        ),
    };
    Ok((target, port))
}

pub(crate) async fn write_status<S: AsyncWrite + Unpin>(
    stream: &mut S,
    status: ConnectStatus,
) -> io::Result<()> {
    let response = match status {
        ConnectStatus::Ok => "HTTP/1.1 200 Connection Established\r\n\r\n",
        ConnectStatus::PolicyDenied | ConnectStatus::ExpectedIpMismatch => {
            "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        }
        ConnectStatus::LimitExceeded => {
            "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        }
        ConnectStatus::Timeout => {
            "HTTP/1.1 408 Request Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        }
        ConnectStatus::ResolutionFailed | ConnectStatus::ConnectFailed => {
            "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        }
        ConnectStatus::Malformed | ConnectStatus::UnsupportedProtocol => {
            "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        }
    };
    stream.write_all(response.as_bytes()).await
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn rejects_ambiguous_routing_framing_and_proxy_credentials() {
        for source in [
            "CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:65536\r\n\r\n",
            "CONNECT allowed.test:443 HTTP/1.1\r\nHost: forbidden.test:443\r\n\r\n",
            "CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\nHost: allowed.test:443\r\n\r\n",
            "CONNECT allowed.test:443 HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
            "CONNECT allowed.test:443 HTTP/1.1\r\nProxy-Authorization: synthetic-token\r\n\r\n",
            "CONNECT allowed.test:443 HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
            "CONNECT user@allowed.test:443 HTTP/1.1\r\n\r\n",
            "CONNECT allowed.test:0 HTTP/1.1\r\n\r\n",
            "CONNECT allowed.test:443 HTTP/1.1\nHost: allowed.test:443\r\n\r\n",
            "GET /relative HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
            "GET http://allowed.test/ HTTP/1.1\r\n\r\n",
            "POST http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
            "GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\nConnection: host\r\n\r\n",
        ] {
            assert!(
                read_request(&mut Cursor::new(source)).await.is_err(),
                "ambiguous request was accepted: {source}",
            );
        }
        let oversized = vec![b'x'; MAX_HEADER_BYTES + 1];
        assert!(read_request(&mut Cursor::new(oversized)).await.is_err());
    }
}
