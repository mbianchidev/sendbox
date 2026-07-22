use crate::error::FrameError;

const CONTENT_LENGTH_PREFIX: &[u8] = b"content-length:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramingMode {
    Newline,
    ContentLength,
    Auto,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedFrame {
    pub payload: Vec<u8>,
    pub raw: Vec<u8>,
    pub mode: FramingMode,
}

#[derive(Debug)]
pub struct FrameDecoder {
    configured_mode: FramingMode,
    active_mode: Option<FramingMode>,
    max_frame_bytes: usize,
    max_header_bytes: usize,
    newline_buffer: Vec<u8>,
    header_buffer: Vec<u8>,
    body_buffer: Vec<u8>,
    expected_body_bytes: Option<usize>,
    auto_buffer: Vec<u8>,
}

impl FrameDecoder {
    #[must_use]
    pub fn new(mode: FramingMode, max_frame_bytes: usize) -> Self {
        Self::with_header_limit(mode, max_frame_bytes, 8 * 1024)
    }

    #[must_use]
    pub fn with_header_limit(
        mode: FramingMode,
        max_frame_bytes: usize,
        max_header_bytes: usize,
    ) -> Self {
        Self {
            configured_mode: mode,
            active_mode: (mode != FramingMode::Auto).then_some(mode),
            max_frame_bytes: max_frame_bytes.max(1),
            max_header_bytes: max_header_bytes.max(32),
            newline_buffer: Vec::new(),
            header_buffer: Vec::new(),
            body_buffer: Vec::new(),
            expected_body_bytes: None,
            auto_buffer: Vec::new(),
        }
    }

    #[must_use]
    pub fn active_mode(&self) -> Option<FramingMode> {
        self.active_mode
    }

    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<DecodedFrame>, FrameError> {
        if self.active_mode.is_none() {
            let consumed = self.detect_mode(bytes)?;
            if self.active_mode.is_none() {
                return Ok(Vec::new());
            }
            let buffered = std::mem::take(&mut self.auto_buffer);
            let mut frames = self.feed_active(&buffered)?;
            frames.extend(self.feed_active(&bytes[consumed..])?);
            return Ok(frames);
        }
        self.feed_active(bytes)
    }

    pub fn finish(&self) -> Result<(), FrameError> {
        if self.active_mode.is_none() && self.auto_buffer.is_empty() {
            return Ok(());
        }
        if !self.auto_buffer.is_empty()
            || !self.newline_buffer.is_empty()
            || !self.header_buffer.is_empty()
            || !self.body_buffer.is_empty()
            || self.expected_body_bytes.is_some()
        {
            return Err(FrameError::IncompleteFrame);
        }
        Ok(())
    }

    fn detect_mode(&mut self, bytes: &[u8]) -> Result<usize, FrameError> {
        if self.configured_mode != FramingMode::Auto {
            self.active_mode = Some(self.configured_mode);
            return Ok(0);
        }
        let needed = CONTENT_LENGTH_PREFIX.len();
        let remaining = needed.saturating_sub(self.auto_buffer.len());
        let take = remaining.min(bytes.len());
        if self.auto_buffer.len().saturating_add(take) > self.max_header_bytes {
            return Err(FrameError::HeaderTooLarge {
                max: self.max_header_bytes,
            });
        }
        self.auto_buffer.extend_from_slice(&bytes[..take]);
        let lower = self
            .auto_buffer
            .iter()
            .map(u8::to_ascii_lowercase)
            .collect::<Vec<_>>();
        if CONTENT_LENGTH_PREFIX.starts_with(&lower) && lower.len() < needed {
            return Ok(take);
        }
        self.active_mode = if lower.starts_with(CONTENT_LENGTH_PREFIX) {
            Some(FramingMode::ContentLength)
        } else {
            Some(FramingMode::Newline)
        };
        Ok(take)
    }

    fn feed_active(&mut self, bytes: &[u8]) -> Result<Vec<DecodedFrame>, FrameError> {
        match self.active_mode {
            Some(FramingMode::Newline) => self.feed_newline(bytes),
            Some(FramingMode::ContentLength) => self.feed_content_length(bytes),
            Some(FramingMode::Auto) | None => Err(FrameError::UndeterminedMode),
        }
    }

    fn feed_newline(&mut self, mut bytes: &[u8]) -> Result<Vec<DecodedFrame>, FrameError> {
        let mut frames = Vec::new();
        while !bytes.is_empty() {
            if let Some(index) = bytes.iter().position(|byte| *byte == b'\n') {
                let segment = &bytes[..=index];
                self.check_completed_newline_frame(segment)?;
                self.newline_buffer.extend_from_slice(segment);
                let raw = std::mem::take(&mut self.newline_buffer);
                let mut end = raw.len().saturating_sub(1);
                if end > 0 && raw[end - 1] == b'\r' {
                    end -= 1;
                }
                frames.push(DecodedFrame {
                    payload: raw[..end].to_vec(),
                    raw,
                    mode: FramingMode::Newline,
                });
                bytes = &bytes[index + 1..];
            } else {
                if self.newline_buffer.len().saturating_add(bytes.len())
                    > self.max_frame_bytes.saturating_add(1)
                {
                    return Err(FrameError::FrameTooLarge {
                        max: self.max_frame_bytes,
                    });
                }
                self.newline_buffer.extend_from_slice(bytes);
                break;
            }
        }
        Ok(frames)
    }

    fn check_completed_newline_frame(&self, segment: &[u8]) -> Result<(), FrameError> {
        let raw_bytes = self.newline_buffer.len().saturating_add(segment.len());
        let before_newline = if segment.len() >= 2 {
            segment.get(segment.len() - 2).copied()
        } else {
            self.newline_buffer.last().copied()
        };
        let delimiter_bytes = 1 + usize::from(before_newline == Some(b'\r'));
        if raw_bytes.saturating_sub(delimiter_bytes) > self.max_frame_bytes {
            return Err(FrameError::FrameTooLarge {
                max: self.max_frame_bytes,
            });
        }
        Ok(())
    }

    fn feed_content_length(&mut self, mut bytes: &[u8]) -> Result<Vec<DecodedFrame>, FrameError> {
        let mut frames = Vec::new();
        while !bytes.is_empty() {
            if let Some(expected) = self.expected_body_bytes {
                let needed = expected.saturating_sub(self.body_buffer.len());
                let take = needed.min(bytes.len());
                self.body_buffer.extend_from_slice(&bytes[..take]);
                bytes = &bytes[take..];
                if self.body_buffer.len() == expected {
                    let payload = std::mem::take(&mut self.body_buffer);
                    let mut raw = std::mem::take(&mut self.header_buffer);
                    raw.extend_from_slice(&payload);
                    self.expected_body_bytes = None;
                    frames.push(DecodedFrame {
                        payload,
                        raw,
                        mode: FramingMode::ContentLength,
                    });
                }
                continue;
            }

            if self.header_buffer.len() >= self.max_header_bytes {
                return Err(FrameError::HeaderTooLarge {
                    max: self.max_header_bytes,
                });
            }
            self.header_buffer.push(bytes[0]);
            bytes = &bytes[1..];
            if header_complete(&self.header_buffer) {
                let length = parse_content_length(&self.header_buffer)?;
                if length > self.max_frame_bytes {
                    return Err(FrameError::FrameTooLarge {
                        max: self.max_frame_bytes,
                    });
                }
                self.body_buffer = Vec::with_capacity(length);
                self.expected_body_bytes = Some(length);
                if length == 0 {
                    let raw = std::mem::take(&mut self.header_buffer);
                    self.expected_body_bytes = None;
                    frames.push(DecodedFrame {
                        payload: Vec::new(),
                        raw,
                        mode: FramingMode::ContentLength,
                    });
                }
            }
        }
        Ok(frames)
    }
}

#[must_use]
pub fn encode_frame(payload: &[u8], mode: FramingMode) -> Vec<u8> {
    match mode {
        FramingMode::Newline | FramingMode::Auto => {
            let mut frame = Vec::with_capacity(payload.len().saturating_add(1));
            frame.extend_from_slice(payload);
            frame.push(b'\n');
            frame
        }
        FramingMode::ContentLength => {
            let header = format!("Content-Length: {}\r\n\r\n", payload.len());
            let mut frame = Vec::with_capacity(header.len().saturating_add(payload.len()));
            frame.extend_from_slice(header.as_bytes());
            frame.extend_from_slice(payload);
            frame
        }
    }
}

fn header_complete(header: &[u8]) -> bool {
    header.ends_with(b"\r\n\r\n") || header.ends_with(b"\n\n")
}

fn parse_content_length(header: &[u8]) -> Result<usize, FrameError> {
    let text = std::str::from_utf8(header)
        .map_err(|_| FrameError::InvalidHeader("header is not ASCII/UTF-8".into()))?;
    let normalized = text.replace("\r\n", "\n");
    let mut content_length = None;
    for line in normalized.trim_end_matches('\n').split('\n') {
        let Some((name, value)) = line.split_once(':') else {
            return Err(FrameError::InvalidHeader(
                "header line is missing ':'".into(),
            ));
        };
        if !name.eq_ignore_ascii_case("content-length") {
            return Err(FrameError::InvalidHeader(format!(
                "unexpected header '{name}'"
            )));
        }
        if content_length.is_some() {
            return Err(FrameError::InvalidHeader(
                "duplicate Content-Length header".into(),
            ));
        }
        let value = value.trim_matches([' ', '\t']);
        if value.is_empty()
            || (value.len() > 1 && value.starts_with('0'))
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(FrameError::InvalidHeader(
                "Content-Length must be a canonical unsigned decimal".into(),
            ));
        }
        content_length = Some(
            value
                .parse::<usize>()
                .map_err(|_| FrameError::InvalidHeader("Content-Length overflow".into()))?,
        );
    }
    content_length.ok_or_else(|| FrameError::InvalidHeader("missing Content-Length".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newline_frames_preserve_raw_bytes() {
        let mut decoder = FrameDecoder::new(FramingMode::Newline, 64);
        assert!(decoder.feed(br#"{"jsonrpc":"2.0"}"#).unwrap().is_empty());
        let frames = decoder.feed(b"\r\n").unwrap();
        assert_eq!(frames[0].payload, br#"{"jsonrpc":"2.0"}"#);
        assert_eq!(frames[0].raw, b"{\"jsonrpc\":\"2.0\"}\r\n");
    }

    #[test]
    fn content_length_rejects_oversize_before_body_allocation() {
        let mut decoder = FrameDecoder::new(FramingMode::ContentLength, 8);
        assert!(matches!(
            decoder.feed(b"Content-Length: 9\r\n\r\n"),
            Err(FrameError::FrameTooLarge { max: 8 })
        ));
        assert_eq!(decoder.body_buffer.capacity(), 0);
    }

    #[test]
    fn auto_mode_locks_to_content_length() {
        let mut decoder = FrameDecoder::new(FramingMode::Auto, 64);
        let frames = decoder
            .feed(b"Content-Length: 2\r\n\r\n{}")
            .expect("content length");
        assert_eq!(decoder.active_mode(), Some(FramingMode::ContentLength));
        assert_eq!(frames[0].payload, b"{}");
    }

    #[test]
    fn content_length_rejects_ambiguous_headers() {
        let mut decoder = FrameDecoder::new(FramingMode::ContentLength, 64);
        assert!(matches!(
            decoder.feed(b"Content-Length: 1\r\nContent-Length: 1\r\n\r\n{}"),
            Err(FrameError::InvalidHeader(_))
        ));
    }
}
