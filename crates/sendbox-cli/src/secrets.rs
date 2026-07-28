use std::io::{self, IsTerminal as _, Read as _};
use std::process::ExitCode;

use clap::{Args, Subcommand};
use sendbox_secrets::{
    MAX_SECRET_VALUE_BYTES, RecordVersion, SecretMetadata, SecretName, SecretStore,
    SecretStoreError, SecretValue,
};
use serde::Serialize;

const DEFAULT_SECRET_SERVICE: &str = "com.sendbox.secrets";

#[derive(Debug, Args)]
pub(crate) struct SecretsArgs {
    #[command(subcommand)]
    command: SecretsCommand,
}

#[derive(Debug, Subcommand)]
enum SecretsCommand {
    /// Store a new secret or replace its existing value.
    Add(AddArgs),
    /// List stored secret names and metadata without revealing values.
    List(ListArgs),
    /// Remove a secret. Missing secrets are treated as already removed.
    Remove(RemoveArgs),
}

#[derive(Debug, Args)]
struct AddArgs {
    #[arg(value_name = "NAME")]
    name: String,
    #[arg(long, help = "Read the secret value from standard input")]
    stdin: bool,
    #[arg(long, help = "Emit a deterministic JSON result")]
    json: bool,
}

#[derive(Debug, Args)]
struct ListArgs {
    #[arg(long, help = "Emit deterministic JSON metadata")]
    json: bool,
}

#[derive(Debug, Args)]
struct RemoveArgs {
    #[arg(value_name = "NAME")]
    name: String,
    #[arg(long, help = "Emit a deterministic JSON result")]
    json: bool,
}

#[derive(Debug, Serialize)]
struct SecretOutput {
    name: String,
    created_at_unix_ms: u64,
    updated_at_unix_ms: u64,
    version: &'static str,
}

impl From<SecretMetadata> for SecretOutput {
    fn from(metadata: SecretMetadata) -> Self {
        Self {
            name: metadata.name.to_string(),
            created_at_unix_ms: metadata.created_at_unix_ms,
            updated_at_unix_ms: metadata.updated_at_unix_ms,
            version: match metadata.version {
                RecordVersion::SwiftLegacy => "swift_legacy",
                RecordVersion::V1 => "v1",
            },
        }
    }
}

pub(crate) fn execute(arguments: SecretsArgs) -> ExitCode {
    match arguments.command {
        SecretsCommand::Add(arguments) => add(arguments),
        SecretsCommand::List(arguments) => list(arguments),
        SecretsCommand::Remove(arguments) => remove(arguments),
    }
}

fn add(arguments: AddArgs) -> ExitCode {
    let result = (|| {
        let name = SecretName::new(arguments.name).map_err(|error| error.to_string())?;
        let value = read_secret_value(arguments.stdin)?;
        let store = open_store()?;
        let updating = store.exists(&name).map_err(|error| error.to_string())?;
        let metadata = if updating {
            store.update(&name, value)
        } else {
            store.store(&name, value)
        }
        .map_err(|error| error.to_string())?;
        Ok::<_, String>((updating, SecretOutput::from(metadata)))
    })();

    match result {
        Ok((updating, secret)) => {
            if arguments.json {
                super::print_json(&serde_json::json!({
                    "schema_version": 1,
                    "ok": true,
                    "action": if updating { "updated" } else { "added" },
                    "secret": secret,
                }));
            } else {
                println!(
                    "{} secret: {}",
                    if updating { "updated" } else { "added" },
                    secret.name
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => emit_error(arguments.json, "add", &error),
    }
}

fn list(arguments: ListArgs) -> ExitCode {
    let result = open_store().and_then(|store| {
        store
            .list()
            .map_err(|error| error.to_string())
            .map(|metadata| {
                let mut secrets = metadata
                    .into_iter()
                    .map(SecretOutput::from)
                    .collect::<Vec<_>>();
                secrets.sort_by(|left, right| left.name.cmp(&right.name));
                secrets
            })
    });

    match result {
        Ok(secrets) => {
            if arguments.json {
                super::print_json(&serde_json::json!({
                    "schema_version": 1,
                    "secrets": secrets,
                }));
            } else if secrets.is_empty() {
                println!("no secrets stored");
            } else {
                for secret in secrets {
                    println!("{}", secret.name);
                }
            }
            ExitCode::SUCCESS
        }
        Err(error) => emit_error(arguments.json, "list", &error),
    }
}

fn remove(arguments: RemoveArgs) -> ExitCode {
    let name = match SecretName::new(arguments.name) {
        Ok(name) => name,
        Err(error) => return emit_error(arguments.json, "remove", &error.to_string()),
    };
    let result = open_store().and_then(|store| match store.delete(&name) {
        Ok(()) => Ok(true),
        Err(SecretStoreError::NotFound(_)) => Ok(false),
        Err(error) => Err(error.to_string()),
    });

    match result {
        Ok(removed) => {
            if arguments.json {
                super::print_json(&serde_json::json!({
                    "schema_version": 1,
                    "ok": true,
                    "name": name.to_string(),
                    "removed": removed,
                }));
            } else if removed {
                println!("removed secret: {name}");
            } else {
                println!("secret already absent: {name}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => emit_error(arguments.json, "remove", &error),
    }
}

fn read_secret_value(from_stdin: bool) -> Result<SecretValue, String> {
    let value = if from_stdin {
        let maximum = u64::try_from(MAX_SECRET_VALUE_BYTES)
            .expect("secret value limit fits in u64")
            .saturating_add(2);
        let mut value = String::new();
        io::stdin()
            .take(maximum)
            .read_to_string(&mut value)
            .map_err(|error| format!("could not read secret value from stdin: {error}"))?;
        if value.len() > MAX_SECRET_VALUE_BYTES + 1 {
            return Err(format!(
                "secret value exceeds {MAX_SECRET_VALUE_BYTES} UTF-8 bytes"
            ));
        }
        value.truncate(value.trim_end_matches(['\r', '\n']).len());
        value
    } else {
        if !io::stdin().is_terminal() {
            return Err(
                "interactive secret input requires a terminal; use --stdin for automation"
                    .to_owned(),
            );
        }
        rpassword::prompt_password("Secret value: ")
            .map_err(|error| format!("could not read secret value: {error}"))?
    };
    if value.is_empty() {
        return Err("no secret value provided".to_owned());
    }
    SecretValue::new(value.into_bytes()).map_err(|error| error.to_string())
}

fn open_store() -> Result<Box<dyn SecretStore>, String> {
    let service = std::env::var("SENDBOX_SECRET_SERVICE")
        .unwrap_or_else(|_| DEFAULT_SECRET_SERVICE.to_owned());

    #[cfg(target_os = "linux")]
    {
        sendbox_secrets::LinuxFileStore::open_default(&service)
            .map(|store| Box::new(store) as Box<dyn SecretStore>)
            .map_err(|error| error.to_string())
    }

    #[cfg(target_os = "macos")]
    {
        sendbox_secrets::KeychainStore::new(service)
            .map(|store| Box::new(store) as Box<dyn SecretStore>)
            .map_err(|error| error.to_string())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = service;
        Err("the native secret store is supported only on Linux and macOS".to_owned())
    }
}

fn emit_error(json: bool, action: &str, error: &str) -> ExitCode {
    if json {
        super::print_json(&serde_json::json!({
            "schema_version": 1,
            "ok": false,
            "action": action,
            "error": error,
        }));
    } else {
        eprintln!("sendbox secrets {action}: {error}");
    }
    ExitCode::from(super::OUTPUT_EXIT)
}
