use core_foundation::data::CFData;
use security_framework::item::{ItemAddOptions, ItemAddValue, ItemClass, ItemSearchOptions, Limit};
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};
use security_framework_sys::base::{errSecAuthFailed, errSecDuplicateItem, errSecItemNotFound};

use crate::record::{decode_for_name, encode_record};
use crate::types::unix_time_ms;
use crate::{
    RecordVersion, Secret, SecretMetadata, SecretName, SecretStore, SecretStoreError, SecretValue,
};

pub const DEFAULT_KEYCHAIN_SERVICE: &str = "com.sendbox.secrets";
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningIdentityChange {
    Unchanged,
    Changed,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeychainMigrationPlan {
    pub source_service: String,
    pub target_service: String,
    pub preserves_service_identifier: bool,
    pub signing_identity_change: SigningIdentityChange,
    pub requires_user_authorization: bool,
    pub requires_acl_reauthorization: bool,
}

#[derive(Debug, Clone)]
pub struct MigrationAuthorization {
    source_service: String,
    target_service: String,
}

impl MigrationAuthorization {
    pub fn user_confirmed(plan: &KeychainMigrationPlan) -> Self {
        Self {
            source_service: plan.source_service.clone(),
            target_service: plan.target_service.clone(),
        }
    }
}

pub struct KeychainStore {
    service: String,
}

impl KeychainStore {
    pub fn new(service: impl Into<String>) -> Result<Self, SecretStoreError> {
        let service = service.into();
        if service.is_empty() || service.len() > 128 || service.chars().any(char::is_control) {
            return Err(SecretStoreError::InvalidName(
                "keychain service name is invalid".to_owned(),
            ));
        }
        Ok(Self { service })
    }

    pub fn default_service() -> Self {
        Self {
            service: DEFAULT_KEYCHAIN_SERVICE.to_owned(),
        }
    }

    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    #[must_use]
    pub fn migration_plan(
        source_service: impl Into<String>,
        target_service: impl Into<String>,
        signing_identity_change: SigningIdentityChange,
    ) -> KeychainMigrationPlan {
        let source_service = source_service.into();
        let target_service = target_service.into();
        let preserves_service_identifier = source_service == target_service;
        KeychainMigrationPlan {
            source_service,
            target_service,
            preserves_service_identifier,
            signing_identity_change,
            requires_user_authorization: !preserves_service_identifier
                || signing_identity_change != SigningIdentityChange::Unchanged,
            requires_acl_reauthorization: signing_identity_change
                != SigningIdentityChange::Unchanged,
        }
    }

    pub fn migrate_from(
        &self,
        source: &KeychainStore,
        authorization: &MigrationAuthorization,
    ) -> Result<Vec<SecretMetadata>, SecretStoreError> {
        if authorization.source_service != source.service
            || authorization.target_service != self.service
        {
            return Err(SecretStoreError::MigrationNotAuthorized);
        }
        if source.service == self.service {
            return source
                .list()?
                .into_iter()
                .map(|metadata| source.migrate(&metadata.name))
                .collect();
        }

        let mut migrated = Vec::new();
        for metadata in source.list()? {
            let secret = source.retrieve(&metadata.name)?;
            migrated.push(self.store(&metadata.name, secret.value)?);
        }
        Ok(migrated)
    }

    fn read(&self, name: &SecretName) -> Result<Secret, SecretStoreError> {
        let bytes = get_generic_password(&self.service, name.as_str())
            .map_err(|error| map_keychain_error_for_name(error, name))?;
        let now = unix_time_ms();
        decode_for_name(name, &bytes, now, now)
    }
}

impl Default for KeychainStore {
    fn default() -> Self {
        Self::default_service()
    }
}

impl SecretStore for KeychainStore {
    fn store(
        &self,
        name: &SecretName,
        value: SecretValue,
    ) -> Result<SecretMetadata, SecretStoreError> {
        let now = unix_time_ms();
        let secret = Secret {
            metadata: SecretMetadata {
                name: name.clone(),
                created_at_unix_ms: now,
                updated_at_unix_ms: now,
                version: RecordVersion::V1,
            },
            value,
        };
        let encoded = encode_record(&secret)?;
        let mut options = ItemAddOptions::new(ItemAddValue::Data {
            class: ItemClass::generic_password(),
            data: CFData::from_buffer(&encoded),
        });
        options
            .set_service(&self.service)
            .set_account_name(name.as_str())
            .set_description("sendbox-secret-v1")
            .set_comment(format!("updated={now}"));
        options.add().map_err(|error| {
            if error.code() == errSecDuplicateItem {
                SecretStoreError::AlreadyExists(name.clone())
            } else {
                map_keychain_error(error)
            }
        })?;
        Ok(secret.metadata)
    }

    fn update(
        &self,
        name: &SecretName,
        value: SecretValue,
    ) -> Result<SecretMetadata, SecretStoreError> {
        let previous = self.read(name)?;
        let secret = Secret {
            metadata: SecretMetadata {
                name: name.clone(),
                created_at_unix_ms: previous.metadata.created_at_unix_ms,
                updated_at_unix_ms: unix_time_ms(),
                version: RecordVersion::V1,
            },
            value,
        };
        let encoded = encode_record(&secret)?;
        set_generic_password(&self.service, name.as_str(), &encoded).map_err(map_keychain_error)?;
        Ok(secret.metadata)
    }

    fn retrieve(&self, name: &SecretName) -> Result<Secret, SecretStoreError> {
        self.read(name)
    }

    fn delete(&self, name: &SecretName) -> Result<(), SecretStoreError> {
        delete_generic_password(&self.service, name.as_str())
            .map_err(|error| map_keychain_error_for_name(error, name))
    }

    fn list(&self) -> Result<Vec<SecretMetadata>, SecretStoreError> {
        let results = ItemSearchOptions::new()
            .class(ItemClass::generic_password())
            .service(&self.service)
            .load_attributes(true)
            .limit(Limit::All)
            .search();
        let results = match results {
            Ok(results) => results,
            Err(error) if error.code() == errSecItemNotFound => return Ok(Vec::new()),
            Err(error) => return Err(map_keychain_error(error)),
        };
        let mut metadata = results
            .into_iter()
            .map(|result| {
                let attributes = result.simplify_dict().ok_or_else(|| {
                    SecretStoreError::Corrupt(
                        "keychain search returned non-attribute result".to_owned(),
                    )
                })?;
                let account = attributes.get("acct").ok_or_else(|| {
                    SecretStoreError::Corrupt(
                        "keychain item is missing its account attribute".to_owned(),
                    )
                })?;
                let name = SecretName::new(account.clone())?;
                self.read(&name).map(|secret| secret.metadata)
            })
            .collect::<Result<Vec<_>, _>>()?;
        metadata.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(metadata)
    }

    fn exists(&self, name: &SecretName) -> Result<bool, SecretStoreError> {
        match get_generic_password(&self.service, name.as_str()) {
            Ok(_) => Ok(true),
            Err(error) if error.code() == errSecItemNotFound => Ok(false),
            Err(error) => Err(map_keychain_error(error)),
        }
    }

    fn migrate(&self, name: &SecretName) -> Result<SecretMetadata, SecretStoreError> {
        let mut secret = self.read(name)?;
        if secret.metadata.version == RecordVersion::V1 {
            return Ok(secret.metadata);
        }
        secret.metadata.version = RecordVersion::V1;
        let encoded = encode_record(&secret)?;
        set_generic_password(&self.service, name.as_str(), &encoded).map_err(map_keychain_error)?;
        Ok(secret.metadata)
    }
}

fn map_keychain_error(error: security_framework::base::Error) -> SecretStoreError {
    match error.code() {
        status if status == errSecItemNotFound => SecretStoreError::NotFound(
            SecretName::new("<unknown>").expect("static valid secret name"),
        ),
        status if status == errSecAuthFailed || status == ERR_SEC_INTERACTION_NOT_ALLOWED => {
            SecretStoreError::AccessDenied
        }
        status => SecretStoreError::Keychain(status),
    }
}

fn map_keychain_error_for_name(
    error: security_framework::base::Error,
    name: &SecretName,
) -> SecretStoreError {
    if error.code() == errSecItemNotFound {
        SecretStoreError::NotFound(name.clone())
    } else {
        map_keychain_error(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_service() -> String {
        format!(
            "com.sendbox.tests.{}.{}",
            std::process::id(),
            unix_time_ms()
        )
    }

    #[test]
    fn keychain_round_trip_uses_unique_service_and_cleans_up() {
        let store = KeychainStore::new(unique_service()).expect("store");
        let name = SecretName::new("TOKEN").expect("name");
        assert!(!store.exists(&name).expect("exists"));
        store
            .store(&name, SecretValue::try_from("first").expect("value"))
            .expect("store");
        assert_eq!(
            store
                .retrieve(&name)
                .expect("retrieve")
                .value
                .expose_secret(),
            b"first"
        );
        store
            .update(&name, SecretValue::try_from("second").expect("value"))
            .expect("update");
        assert_eq!(store.list().expect("list").len(), 1);
        store.delete(&name).expect("delete");
        assert!(!store.exists(&name).expect("exists"));
    }

    #[test]
    fn migration_plan_preserves_service_and_models_signing_acl_change() {
        #[derive(serde::Deserialize)]
        struct Fixture {
            service: String,
        }
        let fixture: Fixture = serde_json::from_str(include_str!(
            "../../../test-fixtures/secrets/swift-linux-v0.json"
        ))
        .expect("fixture");
        assert_eq!(fixture.service, DEFAULT_KEYCHAIN_SERVICE);
        let compatible = KeychainStore::migration_plan(
            DEFAULT_KEYCHAIN_SERVICE,
            DEFAULT_KEYCHAIN_SERVICE,
            SigningIdentityChange::Unchanged,
        );
        assert!(compatible.preserves_service_identifier);
        assert!(!compatible.requires_user_authorization);

        let signing_change = KeychainStore::migration_plan(
            DEFAULT_KEYCHAIN_SERVICE,
            DEFAULT_KEYCHAIN_SERVICE,
            SigningIdentityChange::Changed,
        );
        assert!(signing_change.requires_user_authorization);
        assert!(signing_change.requires_acl_reauthorization);
    }

    #[test]
    #[ignore = "requires a qualified signed binary and interactive Keychain ACL environment"]
    fn signing_acl_qualification_is_opt_in() {
        let plan = KeychainStore::migration_plan(
            DEFAULT_KEYCHAIN_SERVICE,
            DEFAULT_KEYCHAIN_SERVICE,
            SigningIdentityChange::Changed,
        );
        assert!(plan.requires_acl_reauthorization);
    }
}
