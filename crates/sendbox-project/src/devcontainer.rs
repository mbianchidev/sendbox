use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tempfile::NamedTempFile;

use crate::jsonc::parse_jsonc_at;
use crate::{ProjectAnalysis, ProjectError, Result};

const DEFAULT_CONFIG_PATH: &str = ".devcontainer/devcontainer.json";
const MAX_EXISTING_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DevContainerOverrides {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(default)]
    pub features: BTreeMap<String, Value>,
    #[serde(default)]
    pub extensions: Vec<String>,
    #[serde(default)]
    pub settings: BTreeMap<String, Value>,
    #[serde(default)]
    pub forward_ports: Vec<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_create_command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_user: Option<String>,
    #[serde(default)]
    pub container_env: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedDevContainer {
    pub path: PathBuf,
    pub merged_existing: bool,
    pub comments_preserved: bool,
    pub spec: Value,
}

pub fn generate_devcontainer(
    analysis: &ProjectAnalysis,
    existing: Option<Value>,
    overrides: &DevContainerOverrides,
) -> Result<Value> {
    let mut generated = generated_spec(analysis);
    if let Some(existing) = existing {
        deep_merge(&mut generated, existing);
    }
    apply_overrides(&mut generated, overrides)?;
    normalize_spec(&mut generated)?;
    Ok(generated)
}

pub fn write_devcontainer(
    project_root: impl AsRef<Path>,
    output: Option<&Path>,
    analysis: &ProjectAnalysis,
    overrides: &DevContainerOverrides,
) -> Result<GeneratedDevContainer> {
    let project_root = fs::canonicalize(project_root.as_ref())
        .map_err(|source| ProjectError::io(project_root.as_ref(), source))?;
    let output = resolve_output(&project_root, output)?;
    let existing = if output.exists() {
        Some(read_jsonc_file(&output)?)
    } else {
        let default = project_root.join(DEFAULT_CONFIG_PATH);
        if output != default && default.exists() {
            Some(read_jsonc_file(&default)?)
        } else {
            None
        }
    };
    let merged_existing = existing.is_some();
    let spec = generate_devcontainer(analysis, existing, overrides)?;
    atomic_write_json(&project_root, &output, &spec)?;
    Ok(GeneratedDevContainer {
        path: output,
        merged_existing,
        comments_preserved: false,
        spec,
    })
}

fn generated_spec(analysis: &ProjectAnalysis) -> Value {
    let mut features = Map::new();
    for feature in &analysis.suggested_features {
        features.insert(feature.clone(), json!({}));
    }
    let extensions = stable_union(
        analysis.suggested_extensions.clone(),
        [
            "EditorConfig.EditorConfig",
            "GitHub.copilot",
            "GitHub.copilot-chat",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    let mut settings = Map::from_iter([
        ("editor.formatOnSave".to_owned(), Value::Bool(true)),
        (
            "editor.defaultFormatter".to_owned(),
            Value::String("esbenp.prettier-vscode".to_owned()),
        ),
    ]);
    match analysis.language.as_str() {
        "python" => {
            settings.insert(
                "python.defaultInterpreterPath".to_owned(),
                Value::String("/usr/local/bin/python".to_owned()),
            );
            settings.insert(
                "[python]".to_owned(),
                json!({"editor.defaultFormatter": "ms-python.black-formatter"}),
            );
        }
        "rust" => {
            settings.insert(
                "[rust]".to_owned(),
                json!({"editor.defaultFormatter": "rust-lang.rust-analyzer"}),
            );
        }
        "go" => {
            settings.insert(
                "[go]".to_owned(),
                json!({"editor.defaultFormatter": "golang.go"}),
            );
            settings.insert("go.useLanguageServer".to_owned(), Value::Bool(true));
        }
        _ => {}
    }
    json!({
        "name": container_name(analysis),
        "image": analysis.suggested_image,
        "features": features,
        "customizations": {
            "vscode": {
                "extensions": extensions,
                "settings": settings,
            },
        },
        "forwardPorts": detected_ports(analysis),
        "postCreateCommand": post_create_command(analysis.package_manager.as_deref()),
        "remoteUser": "vscode",
        "containerEnv": {},
    })
}

fn apply_overrides(spec: &mut Value, overrides: &DevContainerOverrides) -> Result<()> {
    let object = spec
        .as_object_mut()
        .ok_or(ProjectError::InvalidDevContainerRoot)?;
    if let Some(name) = &overrides.name {
        object.insert("name".to_owned(), Value::String(name.clone()));
    }
    if let Some(image) = &overrides.image {
        object.insert("image".to_owned(), Value::String(image.clone()));
    }
    merge_object_field(object, "features", &overrides.features);
    merge_nested_object_field(
        object,
        &["customizations", "vscode", "settings"],
        &overrides.settings,
    );
    merge_string_array_field(
        object,
        &["customizations", "vscode", "extensions"],
        &overrides.extensions,
    );
    merge_port_array_field(object, "forwardPorts", &overrides.forward_ports);
    if let Some(command) = &overrides.post_create_command {
        object.insert(
            "postCreateCommand".to_owned(),
            Value::String(command.clone()),
        );
    }
    if let Some(user) = &overrides.remote_user {
        object.insert("remoteUser".to_owned(), Value::String(user.clone()));
    }
    if !overrides.container_env.is_empty() {
        let values = overrides
            .container_env
            .iter()
            .map(|(key, value)| (key.clone(), Value::String(value.clone())))
            .collect();
        merge_object_field(object, "containerEnv", &values);
    }
    Ok(())
}

fn deep_merge(base: &mut Value, overlay: Value) {
    match (base, overlay) {
        (Value::Object(base), Value::Object(overlay)) => {
            for (key, value) in overlay {
                if let Some(existing) = base.get_mut(&key) {
                    if key == "extensions" {
                        merge_string_values(existing, value);
                    } else if key == "forwardPorts" {
                        merge_number_values(existing, value);
                    } else {
                        deep_merge(existing, value);
                    }
                } else {
                    base.insert(key, value);
                }
            }
        }
        (base, overlay) => *base = overlay,
    }
}

fn merge_string_values(base: &mut Value, overlay: Value) {
    let Some(base_values) = base.as_array() else {
        *base = overlay;
        return;
    };
    let Some(overlay_values) = overlay.as_array() else {
        *base = overlay;
        return;
    };
    let merged = stable_union(
        base_values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned),
        overlay_values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned),
    );
    *base = Value::Array(merged.into_iter().map(Value::String).collect());
}

fn merge_number_values(base: &mut Value, overlay: Value) {
    let Some(base_values) = base.as_array() else {
        *base = overlay;
        return;
    };
    let Some(overlay_values) = overlay.as_array() else {
        *base = overlay;
        return;
    };
    let values = base_values
        .iter()
        .chain(overlay_values)
        .filter_map(Value::as_u64)
        .collect::<BTreeSet<_>>();
    *base = Value::Array(values.into_iter().map(|value| json!(value)).collect());
}

fn normalize_spec(spec: &mut Value) -> Result<()> {
    let object = spec
        .as_object_mut()
        .ok_or(ProjectError::InvalidDevContainerRoot)?;
    normalize_string_array(object, &["customizations", "vscode", "extensions"]);
    normalize_number_array(object, "forwardPorts");
    sort_json(spec);
    Ok(())
}

fn sort_json(value: &mut Value) {
    match value {
        Value::Array(values) => {
            for value in values {
                sort_json(value);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                sort_json(value);
            }
        }
        _ => {}
    }
}

fn normalize_string_array(root: &mut Map<String, Value>, path: &[&str]) {
    if let Some(Value::Array(values)) = nested_value_mut(root, path) {
        let mut strings = values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        strings.sort();
        strings.dedup();
        *values = strings.into_iter().map(Value::String).collect();
    }
}

fn normalize_number_array(root: &mut Map<String, Value>, key: &str) {
    if let Some(Value::Array(values)) = root.get_mut(key) {
        let ports = values
            .iter()
            .filter_map(Value::as_u64)
            .collect::<BTreeSet<_>>();
        *values = ports.into_iter().map(|value| json!(value)).collect();
    }
}

fn merge_object_field(
    root: &mut Map<String, Value>,
    key: &str,
    additions: &BTreeMap<String, Value>,
) {
    if additions.is_empty() {
        return;
    }
    let value = root.entry(key.to_owned()).or_insert_with(|| json!({}));
    if !value.is_object() {
        *value = json!({});
    }
    let object = value
        .as_object_mut()
        .expect("value was replaced with object");
    object.extend(
        additions
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
    );
}

fn merge_nested_object_field(
    root: &mut Map<String, Value>,
    path: &[&str],
    additions: &BTreeMap<String, Value>,
) {
    if additions.is_empty() {
        return;
    }
    let value = ensure_nested_value(root, path, || json!({}));
    if !value.is_object() {
        *value = json!({});
    }
    let object = value
        .as_object_mut()
        .expect("value was replaced with object");
    object.extend(
        additions
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
    );
}

fn merge_string_array_field(root: &mut Map<String, Value>, path: &[&str], additions: &[String]) {
    if additions.is_empty() {
        return;
    }
    let value = ensure_nested_value(root, path, || json!([]));
    if !value.is_array() {
        *value = json!([]);
    }
    let values = value.as_array_mut().expect("value was replaced with array");
    let merged = stable_union(
        values.iter().filter_map(Value::as_str).map(str::to_owned),
        additions.iter().cloned(),
    );
    *values = merged.into_iter().map(Value::String).collect();
}

fn merge_port_array_field(root: &mut Map<String, Value>, key: &str, additions: &[u16]) {
    if additions.is_empty() {
        return;
    }
    let value = root.entry(key.to_owned()).or_insert_with(|| json!([]));
    if !value.is_array() {
        *value = json!([]);
    }
    let values = value.as_array_mut().expect("value was replaced with array");
    values.extend(additions.iter().map(|port| json!(port)));
}

fn ensure_nested_value<'a>(
    root: &'a mut Map<String, Value>,
    path: &[&str],
    default: impl FnOnce() -> Value,
) -> &'a mut Value {
    let mut current = root.entry(path[0].to_owned()).or_insert_with(|| json!({}));
    for segment in &path[1..path.len() - 1] {
        if !current.is_object() {
            *current = json!({});
        }
        current = current
            .as_object_mut()
            .expect("value was replaced with object")
            .entry((*segment).to_owned())
            .or_insert_with(|| json!({}));
    }
    if !current.is_object() {
        *current = json!({});
    }
    current
        .as_object_mut()
        .expect("value was replaced with object")
        .entry(path[path.len() - 1].to_owned())
        .or_insert_with(default)
}

fn nested_value_mut<'a>(root: &'a mut Map<String, Value>, path: &[&str]) -> Option<&'a mut Value> {
    let mut current = root.get_mut(path[0])?;
    for segment in &path[1..] {
        current = current.as_object_mut()?.get_mut(*segment)?;
    }
    Some(current)
}

fn stable_union(
    first: impl IntoIterator<Item = String>,
    second: impl IntoIterator<Item = String>,
) -> Vec<String> {
    let mut values = first.into_iter().chain(second).collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

fn container_name(analysis: &ProjectAnalysis) -> String {
    let mut parts = vec!["sendbox".to_owned()];
    if analysis.language != "unknown" {
        parts.push(analysis.language.clone());
    }
    if let Some(framework) = &analysis.framework {
        parts.push(
            framework
                .to_lowercase()
                .chars()
                .map(|character| {
                    if character == '.' || character.is_whitespace() {
                        '-'
                    } else {
                        character
                    }
                })
                .collect(),
        );
    }
    parts.join("-")
}

fn detected_ports(analysis: &ProjectAnalysis) -> Vec<u16> {
    let framework_ports = [
        ("Next.js", 3000),
        ("Nuxt", 3000),
        ("React", 3000),
        ("Angular", 4200),
        ("Vue", 5173),
        ("Svelte", 5173),
        ("Express", 3000),
        ("Fastify", 3000),
        ("Hono", 3000),
        ("NestJS", 3000),
        ("Django", 8000),
        ("Flask", 5000),
        ("FastAPI", 8000),
        ("Rails", 3000),
        ("Sinatra", 4567),
    ];
    if let Some(framework) = analysis.framework.as_deref()
        && let Some((_, port)) = framework_ports
            .iter()
            .find(|(candidate, _)| *candidate == framework)
    {
        return vec![*port];
    }
    match analysis.language.as_str() {
        "node" | "typescript" | "ruby" => vec![3000],
        "python" | "php" => vec![8000],
        "go" | "java" | "kotlin" => vec![8080],
        _ => Vec::new(),
    }
}

fn post_create_command(package_manager: Option<&str>) -> &'static str {
    match package_manager {
        Some("npm") => "npm install",
        Some("yarn") => "yarn install",
        Some("pnpm") => "pnpm install",
        Some("pip") => "pip install -r requirements.txt",
        Some("pipenv") => "pipenv install --dev",
        Some("poetry") => "poetry install",
        Some("cargo") => "cargo build",
        Some("go") => "go mod download",
        Some("bundle") => "bundle install",
        Some("maven") => "mvn install -DskipTests",
        Some("gradle") => "gradle build -x test",
        Some("composer") => "composer install",
        Some("mix") => "mix deps.get",
        Some("swift") => "swift build",
        Some("dotnet") => "dotnet restore",
        _ => "echo 'No post-create command configured'",
    }
}

fn read_jsonc_file(path: &Path) -> Result<Value> {
    let metadata = fs::symlink_metadata(path).map_err(|source| ProjectError::io(path, source))?;
    if metadata.file_type().is_symlink() {
        return Err(ProjectError::SymlinkOutput(path.to_path_buf()));
    }
    if metadata.len() > MAX_EXISTING_CONFIG_BYTES {
        return Err(ProjectError::InvalidJsonc {
            path: path.to_path_buf(),
            message: format!(
                "file is {} bytes; maximum is {MAX_EXISTING_CONFIG_BYTES}",
                metadata.len()
            ),
        });
    }
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|source| ProjectError::io(path, source))?;
    let mut source = String::new();
    Read::by_ref(&mut file)
        .take(MAX_EXISTING_CONFIG_BYTES + 1)
        .read_to_string(&mut source)
        .map_err(|source| ProjectError::io(path, source))?;
    parse_jsonc_at(&source, path)
}

fn resolve_output(project_root: &Path, output: Option<&Path>) -> Result<PathBuf> {
    let relative = output.unwrap_or_else(|| Path::new(DEFAULT_CONFIG_PATH));
    if relative
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(ProjectError::OutputOutsideProject(relative.to_path_buf()));
    }
    let output = if relative.is_absolute() {
        relative.to_path_buf()
    } else {
        project_root.join(relative)
    };
    if !output.starts_with(project_root) {
        return Err(ProjectError::OutputOutsideProject(output));
    }
    Ok(output)
}

fn atomic_write_json(project_root: &Path, output: &Path, spec: &Value) -> Result<()> {
    if let Ok(metadata) = fs::symlink_metadata(output)
        && metadata.file_type().is_symlink()
    {
        return Err(ProjectError::SymlinkOutput(output.to_path_buf()));
    }
    let parent = output
        .parent()
        .ok_or_else(|| ProjectError::OutputOutsideProject(output.to_path_buf()))?;
    create_secure_directory(parent)?;
    let canonical_parent =
        fs::canonicalize(parent).map_err(|source| ProjectError::io(parent, source))?;
    if !canonical_parent.starts_with(project_root) {
        return Err(ProjectError::OutputOutsideProject(output.to_path_buf()));
    }

    let mut temporary = NamedTempFile::new_in(&canonical_parent)
        .map_err(|source| ProjectError::io(parent, source))?;
    set_private_permissions(temporary.as_file())?;
    let mut content = serde_json::to_vec_pretty(spec).expect("JSON values are serializable");
    content.push(b'\n');
    temporary
        .write_all(&content)
        .map_err(|source| ProjectError::io(temporary.path(), source))?;
    temporary
        .as_file_mut()
        .sync_all()
        .map_err(|source| ProjectError::io(temporary.path(), source))?;
    temporary
        .persist(output)
        .map_err(|error| ProjectError::io(output, error.error))?;
    Ok(())
}

fn create_secure_directory(path: &Path) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder
            .create(path)
            .map_err(|source| ProjectError::io(path, source))
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path).map_err(|source| ProjectError::io(path, source))
    }
}

fn set_private_permissions(file: &fs::File) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|source| ProjectError::io("<temporary devcontainer>", source))
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Ok(())
    }
}
