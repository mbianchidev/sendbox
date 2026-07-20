use proptest::prelude::*;

proptest! {
    #[test]
    fn audit_decoders_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        sendbox_security::fuzzing::decode_audit(&bytes);
    }

    #[test]
    fn provenance_decoders_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        sendbox_security::fuzzing::decode_provenance(&bytes);
    }

    #[test]
    fn snapshot_decoders_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        sendbox_security::fuzzing::decode_snapshot(&bytes);
    }
}
