use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use roxmltree::Document;
use serde::{Deserialize, Serialize};
use toml::Value as TomlValue;

use crate::Result;
use crate::refinement::{RefinementProvider, RefinementReport, apply_refinement};
use crate::scan::{ProjectSnapshot, ScanIssue, ScanIssueKind, ScanLimits, scan};

const DETECTED_FILE_KEYS: &[&str] = &[
    "package.json",
    "tsconfig.json",
    "requirements.txt",
    "Pipfile",
    "pyproject.toml",
    "setup.py",
    "Cargo.toml",
    "go.mod",
    "Makefile",
    "Gemfile",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "CMakeLists.txt",
    "Dockerfile",
    ".devcontainer/devcontainer.json",
    "composer.json",
    "mix.exs",
    "Package.swift",
    "*.csproj",
    "*.fsproj",
];

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectAnalysis {
    pub language: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package_manager: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_system: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_version: Option<String>,
    pub dependencies: Vec<String>,
    pub dev_dependencies: Vec<String>,
    pub has_dockerfile: bool,
    pub has_dev_container: bool,
    pub detected_files: BTreeMap<String, bool>,
    pub suggested_image: String,
    pub suggested_features: Vec<String>,
    pub suggested_extensions: Vec<String>,
    pub languages: Vec<String>,
    pub scan: crate::ScanReport,
    pub refinement: RefinementReport,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Analyzer {
    limits: ScanLimits,
}

impl Analyzer {
    pub fn new(limits: ScanLimits) -> Self {
        Self { limits }
    }

    pub fn analyze(&self, root: impl AsRef<Path>) -> Result<ProjectAnalysis> {
        let snapshot = scan(root.as_ref(), self.limits)?;
        Ok(analyze_snapshot(snapshot))
    }

    pub fn analyze_with_refinement(
        &self,
        root: impl AsRef<Path>,
        provider: &dyn RefinementProvider,
    ) -> Result<ProjectAnalysis> {
        let mut analysis = self.analyze(root)?;
        apply_refinement(&mut analysis, provider)?;
        Ok(analysis)
    }
}

fn analyze_snapshot(mut snapshot: ProjectSnapshot) -> ProjectAnalysis {
    let detected_files = detected_files(&snapshot);
    let language = detect_primary_language(&detected_files);
    let languages = detect_languages(&detected_files);
    let package_manager = detect_package_manager(&snapshot, &detected_files);
    let framework = detect_framework(&mut snapshot);
    let build_system = detect_build_system(&detected_files);
    let mut manifest = ManifestEvidence::default();
    extract_manifest_evidence(&mut snapshot, &language, &mut manifest);

    let has_dockerfile = detected_files["Dockerfile"];
    let has_dev_container = detected_files[".devcontainer/devcontainer.json"];
    let suggested_image = suggested_image(&language).to_owned();
    let suggested_features = suggested_features(&language, &snapshot, has_dockerfile);
    let suggested_extensions = suggested_extensions(&language);

    manifest.dependencies.remove("");
    manifest.dev_dependencies.remove("");
    ProjectAnalysis {
        language,
        framework,
        package_manager,
        build_system,
        runtime_version: manifest.runtime_version,
        dependencies: manifest.dependencies.into_iter().collect(),
        dev_dependencies: manifest.dev_dependencies.into_iter().collect(),
        has_dockerfile,
        has_dev_container,
        detected_files,
        suggested_image,
        suggested_features,
        suggested_extensions,
        languages,
        scan: snapshot.report,
        refinement: RefinementReport::default(),
    }
}

fn detected_files(snapshot: &ProjectSnapshot) -> BTreeMap<String, bool> {
    DETECTED_FILE_KEYS
        .iter()
        .map(|key| ((*key).to_owned(), has_detected_file(snapshot, key)))
        .collect()
}

fn has_detected_file(snapshot: &ProjectSnapshot, key: &str) -> bool {
    match key {
        "*.csproj" => snapshot.files.iter().any(|path| path.ends_with(".csproj")),
        "*.fsproj" => snapshot.files.iter().any(|path| path.ends_with(".fsproj")),
        _ => snapshot
            .files
            .iter()
            .any(|path| path == key || path.ends_with(&format!("/{key}"))),
    }
}

fn detect_primary_language(detected: &BTreeMap<String, bool>) -> String {
    const PRIORITY: &[(&str, &str)] = &[
        ("tsconfig.json", "typescript"),
        ("Cargo.toml", "rust"),
        ("go.mod", "go"),
        ("pom.xml", "java"),
        ("build.gradle", "java"),
        ("build.gradle.kts", "kotlin"),
        ("*.csproj", "csharp"),
        ("*.fsproj", "fsharp"),
        ("Package.swift", "swift"),
        ("Gemfile", "ruby"),
        ("mix.exs", "elixir"),
        ("composer.json", "php"),
        ("requirements.txt", "python"),
        ("Pipfile", "python"),
        ("pyproject.toml", "python"),
        ("setup.py", "python"),
        ("CMakeLists.txt", "cpp"),
        ("package.json", "node"),
    ];
    PRIORITY
        .iter()
        .find_map(|(file, language)| detected[*file].then(|| (*language).to_owned()))
        .unwrap_or_else(|| "unknown".to_owned())
}

fn detect_languages(detected: &BTreeMap<String, bool>) -> Vec<String> {
    const MAPPINGS: &[(&str, &str)] = &[
        ("tsconfig.json", "typescript"),
        ("package.json", "node"),
        ("requirements.txt", "python"),
        ("Pipfile", "python"),
        ("pyproject.toml", "python"),
        ("setup.py", "python"),
        ("Cargo.toml", "rust"),
        ("go.mod", "go"),
        ("Gemfile", "ruby"),
        ("pom.xml", "java"),
        ("build.gradle", "java"),
        ("build.gradle.kts", "kotlin"),
        ("CMakeLists.txt", "cpp"),
        ("composer.json", "php"),
        ("mix.exs", "elixir"),
        ("Package.swift", "swift"),
        ("*.csproj", "csharp"),
        ("*.fsproj", "fsharp"),
    ];
    MAPPINGS
        .iter()
        .filter_map(|(file, language)| detected[*file].then_some((*language).to_owned()))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn detect_package_manager(
    snapshot: &ProjectSnapshot,
    detected: &BTreeMap<String, bool>,
) -> Option<String> {
    let has = |name: &str| has_detected_file(snapshot, name);
    if has("pnpm-lock.yaml") || has("pnpm-workspace.yaml") {
        Some("pnpm")
    } else if has("yarn.lock") {
        Some("yarn")
    } else if has("package-lock.json") || detected["package.json"] {
        Some("npm")
    } else if has("poetry.lock") {
        Some("poetry")
    } else if detected["Pipfile"] {
        Some("pipenv")
    } else if detected["requirements.txt"] || detected["setup.py"] || detected["pyproject.toml"] {
        Some("pip")
    } else if detected["Cargo.toml"] {
        Some("cargo")
    } else if detected["go.mod"] {
        Some("go")
    } else if detected["Gemfile"] {
        Some("bundle")
    } else if detected["pom.xml"] {
        Some("maven")
    } else if detected["build.gradle"] || detected["build.gradle.kts"] {
        Some("gradle")
    } else if detected["composer.json"] {
        Some("composer")
    } else if detected["mix.exs"] {
        Some("mix")
    } else if detected["Package.swift"] {
        Some("swift")
    } else if detected["*.csproj"] || detected["*.fsproj"] {
        Some("dotnet")
    } else {
        None
    }
    .map(str::to_owned)
}

fn detect_build_system(detected: &BTreeMap<String, bool>) -> Option<String> {
    [
        ("CMakeLists.txt", "cmake"),
        ("Makefile", "make"),
        ("build.gradle.kts", "gradle-kotlin"),
        ("build.gradle", "gradle"),
        ("pom.xml", "maven"),
        ("Cargo.toml", "cargo"),
        ("tsconfig.json", "tsc"),
    ]
    .iter()
    .find_map(|(file, system)| detected[*file].then(|| (*system).to_owned()))
}

fn detect_framework(snapshot: &mut ProjectSnapshot) -> Option<String> {
    if let Some((path, package)) = manifest_owned(snapshot, "package.json") {
        match serde_json::from_str::<serde_json::Value>(&package) {
            Ok(value) => {
                let mut dependencies = BTreeSet::new();
                add_json_object_keys(value.get("dependencies"), &mut dependencies);
                add_json_object_keys(value.get("devDependencies"), &mut dependencies);
                for (dependency, framework) in [
                    ("next", "Next.js"),
                    ("nuxt", "Nuxt"),
                    ("@angular/core", "Angular"),
                    ("react", "React"),
                    ("vue", "Vue"),
                    ("svelte", "Svelte"),
                    ("express", "Express"),
                    ("fastify", "Fastify"),
                    ("hono", "Hono"),
                    ("@nestjs/core", "NestJS"),
                ] {
                    if dependencies.contains(dependency) {
                        return Some(framework.to_owned());
                    }
                }
            }
            Err(error) => manifest_error(snapshot, &path, error),
        }
    }

    let python = ["requirements.txt", "Pipfile", "pyproject.toml"]
        .iter()
        .filter_map(|name| manifest(snapshot, name).map(|(_, content)| content))
        .collect::<Vec<_>>()
        .join("\n")
        .to_lowercase();
    for (dependency, framework) in [
        ("django", "Django"),
        ("flask", "Flask"),
        ("fastapi", "FastAPI"),
    ] {
        if python.contains(dependency) {
            return Some(framework.to_owned());
        }
    }

    if let Some((_, gemfile)) = manifest(snapshot, "Gemfile") {
        let gemfile = gemfile.to_lowercase();
        if gemfile.contains("rails") {
            return Some("Rails".to_owned());
        }
        if gemfile.contains("sinatra") {
            return Some("Sinatra".to_owned());
        }
    }
    None
}

#[derive(Default)]
struct ManifestEvidence {
    dependencies: BTreeSet<String>,
    dev_dependencies: BTreeSet<String>,
    runtime_version: Option<String>,
}

fn extract_manifest_evidence(
    snapshot: &mut ProjectSnapshot,
    language: &str,
    evidence: &mut ManifestEvidence,
) {
    match language {
        "node" | "typescript" => parse_package_json(snapshot, evidence),
        "python" => parse_python(snapshot, evidence),
        "rust" => parse_cargo(snapshot, evidence),
        "go" => parse_go_mod(snapshot, evidence),
        "java" | "kotlin" => parse_java(snapshot, evidence),
        "ruby" => parse_gemfile(snapshot, evidence),
        "php" => parse_composer(snapshot, evidence),
        "elixir" => parse_mix(snapshot, evidence),
        "csharp" | "fsharp" => parse_dotnet(snapshot, evidence),
        _ => {}
    }
}

fn parse_package_json(snapshot: &mut ProjectSnapshot, evidence: &mut ManifestEvidence) {
    let Some((path, content)) = manifest_owned(snapshot, "package.json") else {
        return;
    };
    match serde_json::from_str::<serde_json::Value>(&content) {
        Ok(value) => {
            add_json_object_keys(value.get("dependencies"), &mut evidence.dependencies);
            add_json_object_keys(value.get("devDependencies"), &mut evidence.dev_dependencies);
            evidence.runtime_version = value
                .pointer("/engines/node")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned);
        }
        Err(error) => manifest_error(snapshot, &path, error),
    }
}

fn parse_python(snapshot: &mut ProjectSnapshot, evidence: &mut ManifestEvidence) {
    if let Some((_, requirements)) = manifest(snapshot, "requirements.txt") {
        for line in requirements.lines() {
            if let Some(name) = python_requirement_name(line) {
                evidence.dependencies.insert(name);
            }
        }
    }
    if let Some((path, content)) = manifest_owned(snapshot, "pyproject.toml") {
        match toml::from_str::<TomlValue>(&content) {
            Ok(value) => {
                if let Some(dependencies) = value
                    .get("project")
                    .and_then(|project| project.get("dependencies"))
                    .and_then(TomlValue::as_array)
                {
                    for dependency in dependencies.iter().filter_map(TomlValue::as_str) {
                        if let Some(name) = python_requirement_name(dependency) {
                            evidence.dependencies.insert(name);
                        }
                    }
                }
                if let Some(dependencies) = value
                    .get("tool")
                    .and_then(|tool| tool.get("poetry"))
                    .and_then(|poetry| poetry.get("dependencies"))
                    .and_then(TomlValue::as_table)
                {
                    evidence.dependencies.extend(
                        dependencies
                            .keys()
                            .filter(|name| name.as_str() != "python")
                            .cloned(),
                    );
                }
                if let Some(groups) = value
                    .get("tool")
                    .and_then(|tool| tool.get("poetry"))
                    .and_then(|poetry| poetry.get("group"))
                    .and_then(TomlValue::as_table)
                {
                    for dependencies in groups
                        .values()
                        .filter_map(|group| group.get("dependencies").and_then(TomlValue::as_table))
                    {
                        evidence
                            .dev_dependencies
                            .extend(dependencies.keys().cloned());
                    }
                }
                evidence.runtime_version = value
                    .get("project")
                    .and_then(|project| project.get("requires-python"))
                    .and_then(TomlValue::as_str)
                    .map(str::to_owned);
            }
            Err(error) => manifest_error(snapshot, &path, error),
        }
    }
    if evidence.runtime_version.is_none() {
        evidence.runtime_version = manifest(snapshot, ".python-version")
            .map(|(_, value)| value.trim().to_owned())
            .filter(|value| !value.is_empty());
    }
}

fn parse_cargo(snapshot: &mut ProjectSnapshot, evidence: &mut ManifestEvidence) {
    let Some((path, content)) = manifest_owned(snapshot, "Cargo.toml") else {
        return;
    };
    match toml::from_str::<TomlValue>(&content) {
        Ok(value) => {
            add_toml_table_keys(value.get("dependencies"), &mut evidence.dependencies);
            add_toml_table_keys(
                value.get("dev-dependencies"),
                &mut evidence.dev_dependencies,
            );
            evidence.runtime_version = value
                .get("package")
                .and_then(|package| package.get("rust-version"))
                .and_then(TomlValue::as_str)
                .map(str::to_owned);
        }
        Err(error) => manifest_error(snapshot, &path, error),
    }
}

fn parse_go_mod(snapshot: &mut ProjectSnapshot, evidence: &mut ManifestEvidence) {
    let Some((_, content)) = manifest(snapshot, "go.mod") else {
        return;
    };
    let mut in_require = false;
    for line in content.lines().map(str::trim) {
        if let Some(version) = line.strip_prefix("go ") {
            evidence.runtime_version = Some(version.trim().to_owned());
        } else if line == "require (" {
            in_require = true;
        } else if in_require && line == ")" {
            in_require = false;
        } else if in_require {
            if let Some(name) = line.split_whitespace().next()
                && !name.starts_with("//")
            {
                evidence.dependencies.insert(name.to_owned());
            }
        } else if let Some(requirement) = line.strip_prefix("require ")
            && let Some(name) = requirement.split_whitespace().next()
        {
            evidence.dependencies.insert(name.to_owned());
        }
    }
}

fn parse_java(snapshot: &mut ProjectSnapshot, evidence: &mut ManifestEvidence) {
    if let Some((path, content)) = manifest_owned(snapshot, "pom.xml") {
        match Document::parse(&content) {
            Ok(document) => {
                for dependency in document
                    .descendants()
                    .filter(|node| node.has_tag_name("dependency"))
                {
                    let group = child_text(dependency, "groupId");
                    let artifact = child_text(dependency, "artifactId");
                    if let Some(artifact) = artifact {
                        let name = group
                            .map(|group| format!("{group}:{artifact}"))
                            .unwrap_or(artifact);
                        let is_test = child_text(dependency, "scope").as_deref() == Some("test");
                        if is_test {
                            evidence.dev_dependencies.insert(name);
                        } else {
                            evidence.dependencies.insert(name);
                        }
                    }
                }
                evidence.runtime_version = document
                    .descendants()
                    .find(|node| {
                        node.has_tag_name("maven.compiler.release")
                            || node.has_tag_name("java.version")
                    })
                    .and_then(|node| node.text())
                    .map(str::to_owned);
            }
            Err(error) => manifest_error(snapshot, &path, error),
        }
    }
    for name in ["build.gradle", "build.gradle.kts"] {
        if let Some((_, content)) = manifest(snapshot, name) {
            for line in content.lines().map(str::trim) {
                let is_dev = line.starts_with("testImplementation");
                if (line.starts_with("implementation") || is_dev)
                    && let Some(value) = first_quoted(line)
                {
                    if is_dev {
                        evidence.dev_dependencies.insert(value.to_owned());
                    } else {
                        evidence.dependencies.insert(value.to_owned());
                    }
                }
            }
        }
    }
}

fn parse_gemfile(snapshot: &mut ProjectSnapshot, evidence: &mut ManifestEvidence) {
    let Some((_, content)) = manifest(snapshot, "Gemfile") else {
        return;
    };
    for line in content.lines().map(str::trim) {
        if line.starts_with("gem ")
            && let Some(name) = first_quoted(line)
        {
            evidence.dependencies.insert(name.to_owned());
        }
    }
}

fn parse_composer(snapshot: &mut ProjectSnapshot, evidence: &mut ManifestEvidence) {
    let Some((path, content)) = manifest_owned(snapshot, "composer.json") else {
        return;
    };
    match serde_json::from_str::<serde_json::Value>(&content) {
        Ok(value) => {
            add_json_object_keys(value.get("require"), &mut evidence.dependencies);
            add_json_object_keys(value.get("require-dev"), &mut evidence.dev_dependencies);
            evidence.dependencies.remove("php");
        }
        Err(error) => manifest_error(snapshot, &path, error),
    }
}

fn parse_mix(snapshot: &mut ProjectSnapshot, evidence: &mut ManifestEvidence) {
    let Some((_, content)) = manifest(snapshot, "mix.exs") else {
        return;
    };
    for line in content.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("{:")
            && let Some(end) = rest.find(',')
        {
            evidence.dependencies.insert(rest[..end].trim().to_owned());
        }
    }
}

fn parse_dotnet(snapshot: &mut ProjectSnapshot, evidence: &mut ManifestEvidence) {
    let manifests = snapshot
        .contents
        .iter()
        .filter(|(path, _)| path.ends_with(".csproj") || path.ends_with(".fsproj"))
        .map(|(path, content)| (path.clone(), content.clone()))
        .collect::<Vec<_>>();
    for (path, content) in manifests {
        match Document::parse(&content) {
            Ok(document) => {
                for reference in document
                    .descendants()
                    .filter(|node| node.has_tag_name("PackageReference"))
                {
                    if let Some(name) = reference.attribute("Include") {
                        evidence.dependencies.insert(name.to_owned());
                    }
                }
                if evidence.runtime_version.is_none() {
                    evidence.runtime_version = document
                        .descendants()
                        .find(|node| node.has_tag_name("TargetFramework"))
                        .and_then(|node| node.text())
                        .map(str::to_owned);
                }
            }
            Err(error) => manifest_error(snapshot, &path, error),
        }
    }
}

fn manifest<'a>(snapshot: &'a ProjectSnapshot, name: &str) -> Option<(&'a str, &'a str)> {
    snapshot
        .contents
        .iter()
        .filter(|(path, _)| path.as_str() == name || path.ends_with(&format!("/{name}")))
        .min_by_key(|(path, _)| (path.matches('/').count(), path.as_str()))
        .map(|(path, content)| (path.as_str(), content.as_str()))
}

fn manifest_owned(snapshot: &ProjectSnapshot, name: &str) -> Option<(String, String)> {
    manifest(snapshot, name).map(|(path, content)| (path.to_owned(), content.to_owned()))
}

fn manifest_error(snapshot: &mut ProjectSnapshot, path: &str, error: impl std::fmt::Display) {
    snapshot.report.errors.push(ScanIssue {
        path: path.to_owned(),
        kind: ScanIssueKind::ManifestParse,
        message: error.to_string(),
    });
    snapshot
        .report
        .errors
        .sort_by(|left, right| left.path.cmp(&right.path));
}

fn add_json_object_keys(value: Option<&serde_json::Value>, output: &mut BTreeSet<String>) {
    if let Some(object) = value.and_then(serde_json::Value::as_object) {
        output.extend(object.keys().cloned());
    }
}

fn add_toml_table_keys(value: Option<&TomlValue>, output: &mut BTreeSet<String>) {
    if let Some(table) = value.and_then(TomlValue::as_table) {
        output.extend(table.keys().cloned());
    }
}

fn python_requirement_name(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with('-') || line.starts_with("git+")
    {
        return None;
    }
    let end = line
        .find(['>', '<', '=', '!', '~', ';', '@', ' ', '['])
        .unwrap_or(line.len());
    let name = line[..end].trim();
    (!name.is_empty()).then(|| name.to_owned())
}

fn child_text(node: roxmltree::Node<'_, '_>, name: &str) -> Option<String> {
    node.children()
        .find(|child| child.has_tag_name(name))
        .and_then(|child| child.text())
        .map(str::to_owned)
}

fn first_quoted(line: &str) -> Option<&str> {
    let (index, quote) = line
        .char_indices()
        .find(|(_, character)| *character == '\'' || *character == '"')?;
    let rest = &line[index + quote.len_utf8()..];
    let end = rest.find(quote)?;
    Some(&rest[..end])
}

fn suggested_image(language: &str) -> &'static str {
    match language {
        "typescript" => "mcr.microsoft.com/devcontainers/typescript-node:1-22-bookworm",
        "node" => "mcr.microsoft.com/devcontainers/javascript-node:1-22-bookworm",
        "python" => "mcr.microsoft.com/devcontainers/python:1-3.12-bookworm",
        "rust" => "mcr.microsoft.com/devcontainers/rust:1-bookworm",
        "go" => "mcr.microsoft.com/devcontainers/go:1-1.22-bookworm",
        "ruby" => "mcr.microsoft.com/devcontainers/ruby:1-3.3-bookworm",
        "java" | "kotlin" => "mcr.microsoft.com/devcontainers/java:1-21-bookworm",
        "cpp" => "mcr.microsoft.com/devcontainers/cpp:1-bookworm",
        "csharp" | "fsharp" => "mcr.microsoft.com/devcontainers/dotnet:1-8.0-bookworm",
        "php" => "mcr.microsoft.com/devcontainers/php:1-8.3-bookworm",
        "swift" => "swift:5.10",
        _ => "mcr.microsoft.com/devcontainers/base:bookworm",
    }
}

fn suggested_features(
    language: &str,
    snapshot: &ProjectSnapshot,
    has_dockerfile: bool,
) -> Vec<String> {
    let mut features = Vec::new();
    if has_dockerfile || has_detected_file(snapshot, ".dockerignore") {
        features.push("ghcr.io/devcontainers/features/docker-in-docker:2".to_owned());
    }
    if let Some(feature) = match language {
        "python" => Some("ghcr.io/devcontainers/features/python:1"),
        "node" | "typescript" => Some("ghcr.io/devcontainers/features/node:1"),
        "go" => Some("ghcr.io/devcontainers/features/go:1"),
        "rust" => Some("ghcr.io/devcontainers/features/rust:1"),
        _ => None,
    } {
        features.push(feature.to_owned());
    }
    features.push("ghcr.io/devcontainers/features/git:1".to_owned());
    features
}

fn suggested_extensions(language: &str) -> Vec<String> {
    match language {
        "typescript" => vec![
            "dbaeumer.vscode-eslint",
            "esbenp.prettier-vscode",
            "ms-vscode.vscode-typescript-next",
        ],
        "node" => vec!["dbaeumer.vscode-eslint", "esbenp.prettier-vscode"],
        "python" => vec![
            "ms-python.python",
            "ms-python.vscode-pylance",
            "ms-python.black-formatter",
        ],
        "rust" => vec![
            "rust-lang.rust-analyzer",
            "tamasfe.even-better-toml",
            "vadimcn.vscode-lldb",
        ],
        "go" => vec!["golang.go"],
        "ruby" => vec!["shopify.ruby-lsp"],
        "java" => vec!["vscjava.vscode-java-pack", "vscjava.vscode-gradle"],
        "kotlin" => vec!["vscjava.vscode-java-pack", "mathiasfrohlich.Kotlin"],
        "cpp" => vec!["ms-vscode.cpptools-extension-pack", "ms-vscode.cmake-tools"],
        "csharp" | "fsharp" => vec!["ms-dotnettools.csdevkit"],
        "php" => vec!["bmewburn.vscode-intelephense-client"],
        "swift" => vec!["sswg.swift-lang"],
        "elixir" => vec!["JakeBecker.elixir-ls"],
        _ => Vec::new(),
    }
    .into_iter()
    .map(str::to_owned)
    .collect()
}
