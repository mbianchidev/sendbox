use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, RwLock};

use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::MAX_SECRET_VALUE_BYTES;

pub const CREDENTIAL_MASK: &[u8] = b"[REDACTED]";
const MAX_REGISTERED_CREDENTIALS: usize = 512;
const TOKEN_PREFIXES: &[&[u8]] = &[
    b"github_pat_",
    b"ghp_",
    b"gho_",
    b"ghu_",
    b"ghs_",
    b"ghr_",
    b"sk-ant-",
    b"sk-proj-",
    b"sk-",
    b"AIza",
    b"glpat-",
    b"xoxb-",
    b"xoxp-",
    b"xoxa-",
    b"xoxr-",
    b"xoxs-",
];
const SENSITIVE_LABELS: &[&[u8]] = &[
    b"authorization",
    b"proxy-authorization",
    b"password",
    b"passwd",
    b"api_key",
    b"api-key",
    b"apikey",
    b"token",
    b"access_token",
    b"refresh_token",
    b"client_secret",
    b"secret",
    b"openai_api_key",
    b"anthropic_api_key",
    b"google_api_key",
    b"gemini_api_key",
    b"copilot_github_token",
    b"github_token",
    b"gh_token",
    b"github_personal_access_token",
    b"aws_secret_access_key",
    b"azure_client_secret",
    b"database_password",
    b"db_password",
];
const URL_PREFIXES: &[&[u8]] = &[
    b"https://",
    b"http://",
    b"postgres://",
    b"postgresql://",
    b"mysql://",
    b"redis://",
    b"rediss://",
    b"mongodb://",
    b"ssh://",
];
const PRIVATE_KEYS: &[(&[u8], &[u8])] = &[
    (b"-----BEGIN PRIVATE KEY-----", b"-----END PRIVATE KEY-----"),
    (
        b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
        b"-----END ENCRYPTED PRIVATE KEY-----",
    ),
    (
        b"-----BEGIN RSA PRIVATE KEY-----",
        b"-----END RSA PRIVATE KEY-----",
    ),
    (
        b"-----BEGIN EC PRIVATE KEY-----",
        b"-----END EC PRIVATE KEY-----",
    ),
    (
        b"-----BEGIN OPENSSH PRIVATE KEY-----",
        b"-----END OPENSSH PRIVATE KEY-----",
    ),
];

#[derive(Default)]
enum MaskingMode {
    #[default]
    Normal,
    AwaitValue {
        whole_line: bool,
    },
    Unquoted {
        whole_line: bool,
    },
    Quoted {
        delimiter: u8,
        escaped: bool,
    },
    PrivateKey {
        end: &'static [u8],
        matched: usize,
    },
    UrlAuthority,
}

enum PrefixDecision {
    None,
    Partial,
    Match { length: usize, kind: PrefixKind },
}

enum PrefixKind {
    Token,
    Label { whole_line: bool },
    PrivateKey(&'static [u8]),
    Url,
}

#[derive(Debug, Error)]
pub enum CredentialMaskingError {
    #[error("credential masking state is unavailable")]
    StateUnavailable,
    #[error("credential masking supports at most 512 registered values")]
    TooManyCredentials,
    #[error("credential masking value exceeds the secret byte limit")]
    ValueTooLarge,
}

#[derive(Default)]
struct CredentialValues {
    values: BTreeMap<u8, Vec<Zeroizing<Vec<u8>>>>,
    count: usize,
}

#[derive(Clone, Default)]
pub struct CredentialMasker {
    values: Arc<RwLock<CredentialValues>>,
}

impl fmt::Debug for CredentialMasker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialMasker([REDACTED])")
    }
}

impl CredentialMasker {
    pub fn register(&self, value: &[u8]) -> Result<(), CredentialMaskingError> {
        let Some(first) = value.first() else {
            return Ok(());
        };
        if value.len() > MAX_SECRET_VALUE_BYTES {
            return Err(CredentialMaskingError::ValueTooLarge);
        }
        let mut state = self
            .values
            .write()
            .map_err(|_| CredentialMaskingError::StateUnavailable)?;
        if state
            .values
            .get(first)
            .is_some_and(|values| values.iter().any(|existing| existing.as_slice() == value))
        {
            return Ok(());
        }
        if state.count >= MAX_REGISTERED_CREDENTIALS {
            return Err(CredentialMaskingError::TooManyCredentials);
        }
        state
            .values
            .entry(*first)
            .or_default()
            .push(Zeroizing::new(value.to_vec()));
        state.count += 1;
        Ok(())
    }

    #[must_use]
    pub fn stream(&self) -> CredentialMaskingStream {
        CredentialMaskingStream {
            masker: self.clone(),
            pending: Zeroizing::new(Vec::new()),
            mode: MaskingMode::Normal,
            previous: None,
        }
    }

    pub fn mask(&self, input: &[u8]) -> Result<Vec<u8>, CredentialMaskingError> {
        let mut stream = self.stream();
        let mut output = stream.push(input)?;
        output.extend(stream.finish()?);
        Ok(output)
    }

    /// Masks complete decoded values without treating normal suffixes as truncated secrets.
    pub fn mask_complete(&self, input: &[u8]) -> Result<Vec<u8>, CredentialMaskingError> {
        let mut stream = self.stream();
        stream.pending.extend_from_slice(input);
        stream.drain(true, false)
    }
}

pub struct CredentialMaskingStream {
    masker: CredentialMasker,
    pending: Zeroizing<Vec<u8>>,
    mode: MaskingMode,
    previous: Option<u8>,
}

impl fmt::Debug for CredentialMaskingStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialMaskingStream([REDACTED])")
    }
}

impl CredentialMaskingStream {
    pub fn push(&mut self, input: &[u8]) -> Result<Vec<u8>, CredentialMaskingError> {
        self.pending.extend_from_slice(input);
        self.drain(false, true)
    }

    pub fn finish(&mut self) -> Result<Vec<u8>, CredentialMaskingError> {
        self.drain(true, true)
    }

    fn drain(
        &mut self,
        final_chunk: bool,
        mask_partial_value: bool,
    ) -> Result<Vec<u8>, CredentialMaskingError> {
        let state = self
            .masker
            .values
            .read()
            .map_err(|_| CredentialMaskingError::StateUnavailable)?;
        let mut output = Vec::with_capacity(self.pending.len());
        let mut offset = 0;
        while offset < self.pending.len() {
            let byte = self.pending[offset];
            if !matches!(
                self.mode,
                MaskingMode::Normal | MaskingMode::AwaitValue { .. }
            ) {
                let remaining = &self.pending[offset..];
                let (matched, partial) = known_match(remaining, &state);
                if partial && !final_chunk {
                    break;
                }
                if let Some(length) = matched {
                    let consumed = &remaining[..length];
                    let complete = match &mut self.mode {
                        MaskingMode::Unquoted { whole_line } => consumed.iter().any(|byte| {
                            if *whole_line {
                                matches!(byte, b'\r' | b'\n' | b'"' | b'\'')
                            } else {
                                token_boundary(*byte)
                            }
                        }),
                        MaskingMode::PrivateKey { end, matched } => {
                            let mut complete = false;
                            for byte in consumed {
                                if *byte == end[*matched] {
                                    *matched += 1;
                                } else {
                                    *matched = usize::from(*byte == end[0]);
                                }
                                if *matched == end.len() {
                                    complete = true;
                                    break;
                                }
                            }
                            complete
                        }
                        _ => false,
                    };
                    if complete {
                        self.mode = MaskingMode::Normal;
                    }
                    self.previous = consumed.last().copied();
                    offset += length;
                    continue;
                }
            }
            match &mut self.mode {
                MaskingMode::AwaitValue { whole_line } => {
                    if matches!(byte, b' ' | b'\t') {
                        output.push(byte);
                    } else if matches!(byte, b'\r' | b'\n') {
                        output.push(byte);
                        self.mode = MaskingMode::Normal;
                    } else {
                        let remaining = &self.pending[offset..];
                        if remaining.starts_with(CREDENTIAL_MASK) {
                            output.extend_from_slice(CREDENTIAL_MASK);
                            self.previous = CREDENTIAL_MASK.last().copied();
                            offset += CREDENTIAL_MASK.len();
                            self.mode = MaskingMode::Normal;
                            continue;
                        }
                        if !final_chunk && CREDENTIAL_MASK.starts_with(remaining) {
                            break;
                        }
                        let (matched, partial) = known_match(remaining, &state);
                        if partial && !final_chunk {
                            break;
                        }
                        if let Some(length) = matched {
                            output.extend_from_slice(CREDENTIAL_MASK);
                            self.previous = Some(remaining[length - 1]);
                            self.mode = MaskingMode::Unquoted {
                                whole_line: *whole_line,
                            };
                            offset += length;
                            continue;
                        }
                        output.extend_from_slice(CREDENTIAL_MASK);
                        if matches!(byte, b'"' | b'\'') {
                            output.insert(output.len() - CREDENTIAL_MASK.len(), byte);
                            self.mode = MaskingMode::Quoted {
                                delimiter: byte,
                                escaped: false,
                            };
                        } else {
                            self.mode = MaskingMode::Unquoted {
                                whole_line: *whole_line,
                            };
                        }
                    }
                    self.previous = Some(byte);
                    offset += 1;
                    continue;
                }
                MaskingMode::Unquoted { whole_line } => {
                    let end = if *whole_line {
                        matches!(byte, b'\r' | b'\n' | b'"' | b'\'')
                    } else {
                        token_boundary(byte)
                    };
                    if end {
                        self.mode = MaskingMode::Normal;
                    } else {
                        self.previous = Some(byte);
                        offset += 1;
                        continue;
                    }
                }
                MaskingMode::Quoted { delimiter, escaped } => {
                    if *escaped {
                        *escaped = false;
                    } else if byte == b'\\' {
                        *escaped = true;
                    } else if byte == *delimiter {
                        output.push(byte);
                        self.mode = MaskingMode::Normal;
                    }
                    self.previous = Some(byte);
                    offset += 1;
                    continue;
                }
                MaskingMode::PrivateKey { end, matched } => {
                    if byte == end[*matched] {
                        *matched += 1;
                    } else {
                        *matched = usize::from(byte == end[0]);
                    }
                    if *matched == end.len() {
                        self.mode = MaskingMode::Normal;
                    }
                    self.previous = Some(byte);
                    offset += 1;
                    continue;
                }
                MaskingMode::UrlAuthority => {
                    if url_boundary(byte) {
                        self.mode = MaskingMode::Normal;
                    } else {
                        self.previous = Some(byte);
                        offset += 1;
                        continue;
                    }
                }
                MaskingMode::Normal => {}
            }
            let remaining = &self.pending[offset..];
            if remaining.starts_with(CREDENTIAL_MASK) {
                output.extend_from_slice(CREDENTIAL_MASK);
                self.previous = CREDENTIAL_MASK.last().copied();
                offset += CREDENTIAL_MASK.len();
                continue;
            }
            if !final_chunk && CREDENTIAL_MASK.starts_with(remaining) {
                break;
            }
            let (matched, partial) = known_match(remaining, &state);
            if partial && !final_chunk {
                break;
            }
            if matched.is_some()
                && !final_chunk
                && matches!(
                    detect_prefix(remaining, self.previous),
                    PrefixDecision::Partial
                )
            {
                break;
            }
            if partial && final_chunk && mask_partial_value {
                output.extend_from_slice(CREDENTIAL_MASK);
                self.previous = remaining.last().copied();
                offset = self.pending.len();
            } else if let Some(mut length) = matched {
                output.extend_from_slice(CREDENTIAL_MASK);
                if let PrefixDecision::Match {
                    length: prefix_length,
                    kind,
                } = detect_prefix(remaining, self.previous)
                {
                    length = length.max(prefix_length);
                    self.mode = match kind {
                        PrefixKind::Token => MaskingMode::Unquoted { whole_line: false },
                        PrefixKind::Label { whole_line } => MaskingMode::AwaitValue { whole_line },
                        PrefixKind::PrivateKey(end)
                            if !remaining[..length]
                                .windows(end.len())
                                .any(|value| value == end) =>
                        {
                            MaskingMode::PrivateKey { end, matched: 0 }
                        }
                        PrefixKind::PrivateKey(_) => MaskingMode::Normal,
                        PrefixKind::Url => MaskingMode::UrlAuthority,
                    };
                }
                self.previous = Some(remaining[length - 1]);
                offset += length;
            } else {
                match detect_prefix(remaining, self.previous) {
                    PrefixDecision::Partial if !final_chunk => break,
                    PrefixDecision::Match {
                        length,
                        kind: PrefixKind::Token,
                    } => {
                        output.extend_from_slice(CREDENTIAL_MASK);
                        self.mode = MaskingMode::Unquoted { whole_line: false };
                        self.previous = Some(remaining[length - 1]);
                        offset += length;
                    }
                    PrefixDecision::Match {
                        length,
                        kind: PrefixKind::Label { whole_line },
                    } => {
                        mask_known_values(&remaining[..length], &state, &mut output);
                        self.mode = MaskingMode::AwaitValue { whole_line };
                        self.previous = Some(remaining[length - 1]);
                        offset += length;
                    }
                    PrefixDecision::Match {
                        length,
                        kind: PrefixKind::PrivateKey(end),
                    } => {
                        output.extend_from_slice(CREDENTIAL_MASK);
                        self.mode = MaskingMode::PrivateKey { end, matched: 0 };
                        self.previous = Some(remaining[length - 1]);
                        offset += length;
                    }
                    PrefixDecision::Match {
                        length,
                        kind: PrefixKind::Url,
                    } => {
                        let authority = &remaining[length..];
                        let end = authority.iter().position(|byte| url_boundary(*byte));
                        if end.is_none()
                            && !final_chunk
                            && authority.len() <= MAX_SECRET_VALUE_BYTES
                        {
                            break;
                        }
                        let end = end.unwrap_or(authority.len());
                        mask_known_values(&remaining[..length], &state, &mut output);
                        if end > MAX_SECRET_VALUE_BYTES {
                            output.extend_from_slice(CREDENTIAL_MASK);
                            if length + end == remaining.len() && !final_chunk {
                                self.mode = MaskingMode::UrlAuthority;
                            }
                        } else if let Some(at) =
                            authority[..end].iter().rposition(|byte| *byte == b'@')
                        {
                            output.extend_from_slice(CREDENTIAL_MASK);
                            mask_known_values(&authority[at..end], &state, &mut output);
                        } else {
                            mask_known_values(&authority[..end], &state, &mut output);
                        }
                        self.previous = remaining[..length + end].last().copied();
                        offset += length + end;
                    }
                    _ => {
                        output.push(remaining[0]);
                        self.previous = Some(remaining[0]);
                        offset += 1;
                    }
                }
            }
        }
        let tail = Zeroizing::new(self.pending[offset..].to_vec());
        self.pending.zeroize();
        self.pending = tail;
        if final_chunk {
            self.mode = MaskingMode::Normal;
        }
        Ok(output)
    }
}

fn mask_known_values(input: &[u8], state: &CredentialValues, output: &mut Vec<u8>) {
    let mut offset = 0;
    while offset < input.len() {
        let remaining = &input[offset..];
        let (matched, _) = known_match(remaining, state);
        if let Some(length) = matched {
            output.extend_from_slice(CREDENTIAL_MASK);
            offset += length;
        } else {
            output.push(remaining[0]);
            offset += 1;
        }
    }
}

fn known_match(input: &[u8], state: &CredentialValues) -> (Option<usize>, bool) {
    let Some(first) = input.first() else {
        return (None, false);
    };
    let Some(values) = state.values.get(first) else {
        return (None, false);
    };
    let matched = values
        .iter()
        .filter(|value| input.starts_with(value))
        .map(|value| value.len())
        .max();
    let partial = values
        .iter()
        .any(|value| value.len() > input.len() && value.starts_with(input));
    (matched, partial)
}

#[must_use]
pub fn is_credential_name(name: &str) -> bool {
    SENSITIVE_LABELS
        .iter()
        .any(|label| name.as_bytes().eq_ignore_ascii_case(label))
}

fn token_boundary(byte: u8) -> bool {
    byte.is_ascii_whitespace()
        || matches!(
            byte,
            b'"' | b'\'' | b',' | b';' | b')' | b']' | b'}' | b'<' | b'>' | b'`'
        )
}

fn url_boundary(byte: u8) -> bool {
    byte.is_ascii_whitespace() || matches!(byte, b'"' | b'<' | b'>' | b'`' | b'/' | b'?' | b'#')
}

fn starts_ascii(input: &[u8], prefix: &[u8]) -> bool {
    input.len() >= prefix.len() && input[..prefix.len()].eq_ignore_ascii_case(prefix)
}

fn partial_ascii(input: &[u8], prefix: &[u8]) -> bool {
    input.len() < prefix.len() && prefix[..input.len()].eq_ignore_ascii_case(input)
}

fn detect_prefix(input: &[u8], previous: Option<u8>) -> PrefixDecision {
    let mut partial = false;
    let word_boundary =
        previous.is_none_or(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'_' | b'-'));
    for (begin, end) in PRIVATE_KEYS {
        if starts_ascii(input, begin) {
            return PrefixDecision::Match {
                length: begin.len(),
                kind: PrefixKind::PrivateKey(end),
            };
        }
        partial |= partial_ascii(input, begin);
    }
    for prefix in TOKEN_PREFIXES {
        if starts_ascii(input, prefix) {
            return PrefixDecision::Match {
                length: prefix.len(),
                kind: PrefixKind::Token,
            };
        }
        partial |= partial_ascii(input, prefix);
    }
    for prefix in [
        b"bearer ".as_slice(),
        b"basic ".as_slice(),
        b"bearer:".as_slice(),
    ]
    .into_iter()
    .filter(|_| word_boundary)
    {
        if starts_ascii(input, prefix) {
            return PrefixDecision::Match {
                length: prefix.len(),
                kind: PrefixKind::Label { whole_line: false },
            };
        }
        partial |= partial_ascii(input, prefix);
    }
    for prefix in URL_PREFIXES.iter().filter(|_| word_boundary) {
        if starts_ascii(input, prefix) {
            return PrefixDecision::Match {
                length: prefix.len(),
                kind: PrefixKind::Url,
            };
        }
        partial |= partial_ascii(input, prefix);
    }
    if word_boundary {
        for label in SENSITIVE_LABELS {
            if partial_ascii(input, label) {
                partial = true;
                continue;
            }
            if !starts_ascii(input, label) {
                continue;
            }
            let mut offset = label.len();
            if input
                .get(offset)
                .is_some_and(|byte| matches!(byte, b'"' | b'\''))
            {
                offset += 1;
            }
            while offset < input.len()
                && offset - label.len() <= 64
                && matches!(input[offset], b' ' | b'\t')
            {
                offset += 1;
            }
            if offset == input.len() && offset - label.len() <= 64 {
                partial = true;
            } else if input
                .get(offset)
                .is_some_and(|byte| matches!(byte, b':' | b'='))
            {
                return PrefixDecision::Match {
                    length: offset + 1,
                    kind: PrefixKind::Label {
                        whole_line: label.ends_with(b"authorization"),
                    },
                };
            }
        }
    }
    if partial {
        PrefixDecision::Partial
    } else {
        PrefixDecision::None
    }
}
