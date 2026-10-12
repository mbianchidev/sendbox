use proptest::prelude::*;
use sendbox_secrets::{CredentialMasker, CredentialMaskingError};

fn assert_chunk_safe(masker: &CredentialMasker, input: &[u8], expected: &[u8]) {
    for split in 0..=input.len() {
        let mut stream = masker.stream();
        let mut output = stream.push(&input[..split]).unwrap();
        output.extend(stream.push(&input[split..]).unwrap());
        output.extend(stream.finish().unwrap());
        assert_eq!(output, expected, "split {split}");
    }
    let mut stream = masker.stream();
    let mut output = Vec::new();
    for byte in input {
        output.extend(stream.push(std::slice::from_ref(byte)).unwrap());
    }
    output.extend(stream.finish().unwrap());
    assert_eq!(output, expected, "single-byte chunks");
}

#[test]
fn known_credentials_are_masked_at_every_stream_chunk_boundary() {
    let masker = CredentialMasker::default();
    masker.register(b"synthetic-session-credential").unwrap();
    let input = b"before synthetic-session-credential after\n";
    for split in 0..=input.len() {
        let mut stream = masker.stream();
        let mut output = stream.push(&input[..split]).unwrap();
        output.extend(stream.push(&input[split..]).unwrap());
        output.extend(stream.finish().unwrap());
        assert_eq!(output, b"before [REDACTED] after\n", "split {split}");
    }
    assert!(!format!("{masker:?}").contains("synthetic-session-credential"));
}

#[test]
fn ordinary_terminal_output_is_not_buffered_or_changed() {
    let masker = CredentialMasker::default();
    masker.register(b"synthetic-session-credential").unwrap();
    let mut stream = masker.stream();
    assert_eq!(
        stream.push(b"\x1b[32mReady> \x1b[0m").unwrap(),
        b"\x1b[32mReady> \x1b[0m"
    );
    assert!(stream.finish().unwrap().is_empty());
}

#[test]
fn complete_structured_values_do_not_treat_normal_suffixes_as_truncated_credentials() {
    let masker = CredentialMasker::default();
    masker.register(b"synthetic-value").unwrap();
    assert_eq!(masker.mask_complete(b"params").unwrap(), b"params");
    assert_eq!(
        masker.mask_complete(b"synthetic-value").unwrap(),
        b"[REDACTED]"
    );
    assert_eq!(masker.mask(b"synthetic-val").unwrap(), b"[REDACTED]");
}

#[test]
fn recognizable_credentials_are_masked_even_without_vault_registration() {
    for (input, expected) in [
        (
            "Authorization: Bearer synthetic-oauth-value\n",
            "Authorization: [REDACTED]\n",
        ),
        (
            "key=ghp_syntheticgithubcredential, ok\n",
            "key=[REDACTED], ok\n",
        ),
        (
            "api=sk-proj-syntheticprovidercredential done\n",
            "api=[REDACTED] done\n",
        ),
        ("PASSWORD=synthetic-password\n", "PASSWORD=[REDACTED]\n"),
        (
            r#"{"access_token" : "synthetic-token","ok":true}"#,
            r#"{"access_token" : "[REDACTED]","ok":true}"#,
        ),
        (
            "before -----BEGIN OPENSSH PRIVATE KEY-----\nsynthetic-key-material\n-----END OPENSSH PRIVATE KEY----- after\n",
            "before [REDACTED] after\n",
        ),
        (
            "https://synthetic-user:synthetic-password@example.test/path\n",
            "https://[REDACTED]@example.test/path\n",
        ),
    ] {
        for split in 0..=input.len() {
            let masker = CredentialMasker::default();
            let mut stream = masker.stream();
            let mut output = stream.push(&input.as_bytes()[..split]).unwrap();
            output.extend(stream.push(&input.as_bytes()[split..]).unwrap());
            output.extend(stream.finish().unwrap());
            assert_eq!(output, expected.as_bytes(), "split {split}: {input}");
        }
    }
}

#[test]
fn overlapping_values_and_incomplete_values_at_eof_fail_closed() {
    let masker = CredentialMasker::default();
    masker.register(b"synthetic-value").unwrap();
    masker.register(b"synthetic-value-longer").unwrap();
    assert_chunk_safe(
        &masker,
        b"synthetic-value-longer synthetic-value synthetic-val",
        b"[REDACTED] [REDACTED] [REDACTED]",
    );
}

#[test]
fn binary_and_unicode_bytes_outside_credentials_are_unchanged() {
    let masker = CredentialMasker::default();
    masker.register(b"\xff\x00synthetic\xfe").unwrap();
    assert_chunk_safe(
        &masker,
        b"\xf0\x9f\x94\x92 \xff\x00synthetic\xfe \x00 \xc3\xa9",
        b"\xf0\x9f\x94\x92 [REDACTED] \x00 \xc3\xa9",
    );
}

#[test]
fn quoted_and_unterminated_credentials_remain_masked() {
    let masker = CredentialMasker::default();
    assert_chunk_safe(
        &masker,
        br#"{"client_secret":"synthetic\"quoted\\value","ok":true}"#,
        br#"{"client_secret":"[REDACTED]","ok":true}"#,
    );
    assert_chunk_safe(
        &masker,
        b"-----BEGIN PRIVATE KEY-----\nsynthetic-incomplete-key",
        b"[REDACTED]",
    );
}

#[test]
fn sensitive_field_recognition_does_not_expose_parts_of_registered_multiword_values() {
    let masker = CredentialMasker::default();
    masker.register(b"synthetic spaced credential").unwrap();
    assert_chunk_safe(
        &masker,
        b"password=synthetic spaced credential after\n",
        b"password=[REDACTED] after\n",
    );
    assert_chunk_safe(
        &masker,
        b"Bearer prefixsynthetic spaced credential after\n",
        b"Bearer [REDACTED] after\n",
    );
}

#[test]
fn registered_private_keys_with_trailing_newlines_do_not_hide_later_prompts() {
    let masker = CredentialMasker::default();
    let key = b"-----BEGIN PRIVATE KEY-----\nsynthetic-private-key\n-----END PRIVATE KEY-----\n";
    masker.register(key).unwrap();
    let mut input = key.to_vec();
    input.extend_from_slice(b"Ready> ");
    assert_chunk_safe(&masker, &input, b"[REDACTED]Ready> ");
}

#[test]
fn redaction_is_idempotent_in_sensitive_fields_and_headers() {
    let masker = CredentialMasker::default();
    for input in [
        b"Authorization: Bearer synthetic-value\n".as_slice(),
        br#"{"password":"synthetic-value","access_token":"synthetic-other"}"#,
        b"token=synthetic-value done\n",
        b"https://synthetic-user:synthetic-value@example.test/path",
    ] {
        let once = masker.mask(input).unwrap();
        assert_eq!(masker.mask(&once).unwrap(), once);
        assert_chunk_safe(&masker, &once, &once);
    }
}

#[test]
fn registered_credentials_in_url_authorities_are_not_bypassed() {
    let masker = CredentialMasker::default();
    masker.register(b"synthetic-authority").unwrap();
    assert_chunk_safe(
        &masker,
        b"https://synthetic-authority.example.test/path",
        b"https://[REDACTED].example.test/path",
    );
}

#[test]
fn registered_prefixes_do_not_disable_recognizable_credential_detection() {
    let masker = CredentialMasker::default();
    masker.register(b"gh").unwrap();
    masker.register(b"authorization").unwrap();
    masker.register(b"https").unwrap();
    assert_chunk_safe(
        &masker,
        b"ghp_synthetic-unregistered next\n",
        b"[REDACTED] next\n",
    );
    for input in [
        b"authorization: Bearer synthetic-unregistered\n".as_slice(),
        b"https://synthetic-user:synthetic-unregistered@example.test/path\n",
    ] {
        let masked = masker.mask(input).unwrap();
        assert!(!String::from_utf8_lossy(&masked).contains("synthetic-unregistered"));
        assert_chunk_safe(&masker, input, &masked);
    }
}

#[test]
fn url_userinfo_accepts_legal_authority_punctuation_without_bypassing_masking() {
    let masker = CredentialMasker::default();
    assert_chunk_safe(
        &masker,
        b"https://synthetic-user:synthetic;pass,word)]'@example.test/path\n",
        b"https://[REDACTED]@example.test/path\n",
    );
}

#[test]
fn redaction_markers_are_stable_even_when_credentials_overlap_them() {
    let masker = CredentialMasker::default();
    masker.register(b"R").unwrap();
    assert_chunk_safe(&masker, b"[REDACTED]", b"[REDACTED]");
    let once = masker.mask(b"R").unwrap();
    assert_eq!(masker.mask(&once).unwrap(), once);
}

#[test]
fn long_url_authorities_do_not_expose_later_chunks() {
    let masker = CredentialMasker::default();
    let mut stream = masker.stream();
    let mut first = b"https://".to_vec();
    first.extend(std::iter::repeat_n(b'x', 65_537));
    let mut output = stream.push(&first).unwrap();
    output.extend(
        stream
            .push(b"synthetic-continuation@example.test/path\n")
            .unwrap(),
    );
    output.extend(stream.finish().unwrap());
    assert_eq!(output, b"https://[REDACTED]/path\n");
}

#[test]
fn registration_limits_are_explicit_and_debug_never_exposes_values() {
    let masker = CredentialMasker::default();
    assert!(matches!(
        masker.register(&vec![b'x'; 65_537]),
        Err(CredentialMaskingError::ValueTooLarge)
    ));
    for index in 0..512 {
        masker
            .register(format!("synthetic-credential-{index}").as_bytes())
            .unwrap();
    }
    masker.register(b"synthetic-credential-0").unwrap();
    masker.register(b"").unwrap();
    assert!(matches!(
        masker.register(b"synthetic-additional-credential"),
        Err(CredentialMaskingError::TooManyCredentials)
    ));
    assert!(!format!("{:?}", masker.stream()).contains("synthetic"));
}

proptest! {
    #[test]
    fn arbitrary_bytes_have_identical_redaction_regardless_of_chunking(
        bytes in proptest::collection::vec(any::<u8>(), 0..4096),
        chunk_size in 1usize..128,
    ) {
        let masker = CredentialMasker::default();
        masker.register(b"synthetic-opaque-credential").unwrap();
        let expected = masker.mask(&bytes).unwrap();
        let mut stream = masker.stream();
        let mut output = Vec::new();
        for chunk in bytes.chunks(chunk_size) {
            output.extend(stream.push(chunk).unwrap());
        }
        output.extend(stream.finish().unwrap());
        prop_assert_eq!(output, expected);
    }
}
