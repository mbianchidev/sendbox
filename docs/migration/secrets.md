# Secret Store Migration

## Compatibility

The Rust store preserves the Swift Keychain service identifier
`com.sendbox.secrets` and the Linux hex-encoded directory and filename layout.
Legacy values remain readable before migration.

## Linux

1. Open the existing store. Any symlink, non-owner entry, non-directory
   component, non-`0700` directory, or non-`0600` file stops migration.
2. Retrieve the legacy value through the typed store.
3. Call `SecretStore::migrate` for that name.
4. SendBox writes a versioned temporary record, syncs it, atomically replaces
   the legacy file, and syncs the directory.
5. Re-running migration is safe and returns the existing versioned metadata.

There is no bulk plaintext export. Rollback readers must continue to understand
the versioned record before a user migrates production data.

## macOS

Keeping the service identifier unchanged avoids unnecessary item duplication,
but a changed code-signing identity can still cause Keychain ACL prompts.
Generate a `KeychainMigrationPlan` using the old and new signing identities.
When reauthorization is required, obtain explicit user confirmation and run the
migration using the final signed binary.

Never delete an old-service item until the replacement has been stored and
verified. Never silently relax an ACL, create an empty replacement, or fall
back to a different service. Cross-service movement requires an explicit
`MigrationAuthorization` and performs direct Keychain-to-Keychain transfer
without producing a plaintext archive.
