import { CopilotClient, defineTool } from "@github/copilot-sdk";
import * as fs from "fs";
import * as path from "path";

// ── Types ───────────────────────────────────────────────────────────────────

export interface ProjectAnalysis {
  language: string;
  framework?: string;
  packageManager?: string;
  buildSystem?: string;
  runtimeVersion?: string;
  dependencies: string[];
  devDependencies: string[];
  hasDockerfile: boolean;
  hasDevContainer: boolean;
  detectedFiles: Record<string, boolean>;
  suggestedImage: string;
  suggestedFeatures: string[];
  suggestedExtensions: string[];
}

export interface DevContainerConfig {
  name: string;
  image: string;
  features: Record<string, unknown>;
  customizations: {
    vscode: {
      extensions: string[];
      settings: Record<string, unknown>;
    };
  };
  forwardPorts: number[];
  postCreateCommand: string;
  remoteUser: string;
}

// ── Constants ───────────────────────────────────────────────────────────────

const CONFIG_FILES: Record<string, string> = {
  "package.json": "node",
  "tsconfig.json": "typescript",
  "requirements.txt": "python",
  "Pipfile": "python",
  "pyproject.toml": "python",
  "setup.py": "python",
  "Cargo.toml": "rust",
  "go.mod": "go",
  "Makefile": "make",
  "Gemfile": "ruby",
  "pom.xml": "java",
  "build.gradle": "java",
  "build.gradle.kts": "kotlin",
  "CMakeLists.txt": "cpp",
  "Dockerfile": "docker",
  ".devcontainer/devcontainer.json": "devcontainer",
  "composer.json": "php",
  "mix.exs": "elixir",
  "Package.swift": "swift",
  "*.csproj": "csharp",
  "*.fsproj": "fsharp",
};

const IMAGE_MAP: Record<string, string> = {
  typescript: "mcr.microsoft.com/devcontainers/typescript-node:1-22-bookworm",
  node: "mcr.microsoft.com/devcontainers/javascript-node:1-22-bookworm",
  python: "mcr.microsoft.com/devcontainers/python:1-3.12-bookworm",
  rust: "mcr.microsoft.com/devcontainers/rust:1-bookworm",
  go: "mcr.microsoft.com/devcontainers/go:1-1.22-bookworm",
  ruby: "mcr.microsoft.com/devcontainers/ruby:1-3.3-bookworm",
  java: "mcr.microsoft.com/devcontainers/java:1-21-bookworm",
  kotlin: "mcr.microsoft.com/devcontainers/java:1-21-bookworm",
  cpp: "mcr.microsoft.com/devcontainers/cpp:1-bookworm",
  csharp: "mcr.microsoft.com/devcontainers/dotnet:1-8.0-bookworm",
  php: "mcr.microsoft.com/devcontainers/php:1-8.3-bookworm",
  swift: "swift:5.10",
  elixir: "mcr.microsoft.com/devcontainers/base:bookworm",
  default: "mcr.microsoft.com/devcontainers/base:bookworm",
};

const EXTENSION_MAP: Record<string, string[]> = {
  typescript: [
    "dbaeumer.vscode-eslint",
    "esbenp.prettier-vscode",
    "ms-vscode.vscode-typescript-next",
  ],
  node: [
    "dbaeumer.vscode-eslint",
    "esbenp.prettier-vscode",
  ],
  python: [
    "ms-python.python",
    "ms-python.vscode-pylance",
    "ms-python.black-formatter",
  ],
  rust: [
    "rust-lang.rust-analyzer",
    "tamasfe.even-better-toml",
    "vadimcn.vscode-lldb",
  ],
  go: [
    "golang.go",
  ],
  ruby: [
    "shopify.ruby-lsp",
  ],
  java: [
    "vscjava.vscode-java-pack",
    "vscjava.vscode-gradle",
  ],
  kotlin: [
    "vscjava.vscode-java-pack",
    "mathiasfrohlich.Kotlin",
  ],
  cpp: [
    "ms-vscode.cpptools-extension-pack",
    "ms-vscode.cmake-tools",
  ],
  csharp: [
    "ms-dotnettools.csdevkit",
  ],
  php: [
    "bmewburn.vscode-intelephense-client",
  ],
  swift: [
    "sswg.swift-lang",
  ],
  elixir: [
    "JakeBecker.elixir-ls",
  ],
};

const INSTALL_COMMANDS: Record<string, string> = {
  npm: "npm install",
  yarn: "yarn install",
  pnpm: "pnpm install",
  pip: "pip install -r requirements.txt",
  pipenv: "pipenv install --dev",
  poetry: "poetry install",
  cargo: "cargo build",
  go: "go mod download",
  bundle: "bundle install",
  maven: "mvn install -DskipTests",
  gradle: "gradle build -x test",
  composer: "composer install",
  mix: "mix deps.get",
  swift: "swift build",
  dotnet: "dotnet restore",
};

// ── Logging ─────────────────────────────────────────────────────────────────

function log(message: string): void {
  process.stderr.write(`[sendbox] ${message}\n`);
}

// ── ProjectAnalyzer ─────────────────────────────────────────────────────────

export class ProjectAnalyzer {
  private projectPath: string;

  constructor(projectPath: string) {
    this.projectPath = path.resolve(projectPath);
  }

  async analyze(): Promise<ProjectAnalysis> {
    log(`Analyzing project at ${this.projectPath}`);

    const detectedFiles = this.scanConfigFiles();
    const language = this.detectPrimaryLanguage(detectedFiles);
    const packageManager = this.detectPackageManager(detectedFiles);
    const framework = this.detectFramework(detectedFiles);
    const { dependencies, devDependencies, runtimeVersion } =
      this.extractDependencyInfo(detectedFiles, language);

    const analysis: ProjectAnalysis = {
      language,
      framework,
      packageManager,
      buildSystem: this.detectBuildSystem(detectedFiles),
      runtimeVersion,
      dependencies,
      devDependencies,
      hasDockerfile: detectedFiles["Dockerfile"] ?? false,
      hasDevContainer:
        detectedFiles[".devcontainer/devcontainer.json"] ?? false,
      detectedFiles,
      suggestedImage: IMAGE_MAP[language] ?? IMAGE_MAP.default,
      suggestedFeatures: this.suggestFeatures(language, detectedFiles),
      suggestedExtensions: EXTENSION_MAP[language] ?? [],
    };

    // Attempt Copilot-assisted refinement
    try {
      return await this.refineWithCopilot(analysis, detectedFiles);
    } catch (error) {
      log(
        `Copilot refinement unavailable, using local analysis: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
      return analysis;
    }
  }

  // ── File scanning ───────────────────────────────────────────────────────

  private scanConfigFiles(): Record<string, boolean> {
    const detected: Record<string, boolean> = {};

    for (const filename of Object.keys(CONFIG_FILES)) {
      if (filename.startsWith("*.")) {
        // Glob-style match for extension-based patterns
        const ext = filename.slice(1);
        detected[filename] = this.hasFileWithExtension(this.projectPath, ext);
      } else {
        detected[filename] = fs.existsSync(
          path.join(this.projectPath, filename),
        );
      }
    }

    return detected;
  }

  private hasFileWithExtension(dir: string, ext: string): boolean {
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      return entries.some(
        (entry) => entry.isFile() && entry.name.endsWith(ext),
      );
    } catch {
      return false;
    }
  }

  private readFile(filePath: string): string | null {
    const resolved = path.resolve(this.projectPath, filePath);
    // Prevent path traversal outside the project
    if (!resolved.startsWith(this.projectPath)) {
      log(`Blocked read outside project: ${filePath}`);
      return null;
    }
    try {
      return fs.readFileSync(resolved, "utf-8");
    } catch {
      return null;
    }
  }

  // ── Detection logic ─────────────────────────────────────────────────────

  private detectPrimaryLanguage(
    detectedFiles: Record<string, boolean>,
  ): string {
    // Priority-ordered language detection
    const priority: [string, string][] = [
      ["tsconfig.json", "typescript"],
      ["Cargo.toml", "rust"],
      ["go.mod", "go"],
      ["pom.xml", "java"],
      ["build.gradle", "java"],
      ["build.gradle.kts", "kotlin"],
      ["*.csproj", "csharp"],
      ["*.fsproj", "fsharp"],
      ["Package.swift", "swift"],
      ["Gemfile", "ruby"],
      ["mix.exs", "elixir"],
      ["composer.json", "php"],
      ["requirements.txt", "python"],
      ["Pipfile", "python"],
      ["pyproject.toml", "python"],
      ["setup.py", "python"],
      ["CMakeLists.txt", "cpp"],
      ["package.json", "node"],
    ];

    for (const [file, lang] of priority) {
      if (detectedFiles[file]) return lang;
    }

    return "unknown";
  }

  private detectPackageManager(
    detectedFiles: Record<string, boolean>,
  ): string | undefined {
    if (
      fs.existsSync(path.join(this.projectPath, "pnpm-lock.yaml")) ||
      fs.existsSync(path.join(this.projectPath, "pnpm-workspace.yaml"))
    )
      return "pnpm";
    if (fs.existsSync(path.join(this.projectPath, "yarn.lock"))) return "yarn";
    if (fs.existsSync(path.join(this.projectPath, "package-lock.json")))
      return "npm";
    if (detectedFiles["package.json"]) return "npm";

    if (fs.existsSync(path.join(this.projectPath, "poetry.lock")))
      return "poetry";
    if (detectedFiles["Pipfile"]) return "pipenv";
    if (
      detectedFiles["requirements.txt"] ||
      detectedFiles["setup.py"] ||
      detectedFiles["pyproject.toml"]
    )
      return "pip";

    if (detectedFiles["Cargo.toml"]) return "cargo";
    if (detectedFiles["go.mod"]) return "go";
    if (detectedFiles["Gemfile"]) return "bundle";
    if (detectedFiles["pom.xml"]) return "maven";
    if (detectedFiles["build.gradle"] || detectedFiles["build.gradle.kts"])
      return "gradle";
    if (detectedFiles["composer.json"]) return "composer";
    if (detectedFiles["mix.exs"]) return "mix";
    if (detectedFiles["Package.swift"]) return "swift";
    if (detectedFiles["*.csproj"] || detectedFiles["*.fsproj"])
      return "dotnet";

    return undefined;
  }

  private detectFramework(
    detectedFiles: Record<string, boolean>,
  ): string | undefined {
    const pkgContent = this.readFile("package.json");
    if (pkgContent) {
      try {
        const pkg = JSON.parse(pkgContent);
        const allDeps = {
          ...pkg.dependencies,
          ...pkg.devDependencies,
        };

        if (allDeps["next"]) return "Next.js";
        if (allDeps["nuxt"]) return "Nuxt";
        if (allDeps["@angular/core"]) return "Angular";
        if (allDeps["react"]) return "React";
        if (allDeps["vue"]) return "Vue";
        if (allDeps["svelte"]) return "Svelte";
        if (allDeps["express"]) return "Express";
        if (allDeps["fastify"]) return "Fastify";
        if (allDeps["hono"]) return "Hono";
        if (allDeps["@nestjs/core"]) return "NestJS";
      } catch {
        // malformed package.json
      }
    }

    const reqContent = this.readFile("requirements.txt");
    const pipfileContent = this.readFile("Pipfile");
    const pyprojectContent = this.readFile("pyproject.toml");
    const pyDeps = [reqContent, pipfileContent, pyprojectContent]
      .filter(Boolean)
      .join("\n")
      .toLowerCase();

    if (pyDeps.includes("django")) return "Django";
    if (pyDeps.includes("flask")) return "Flask";
    if (pyDeps.includes("fastapi")) return "FastAPI";

    if (detectedFiles["Gemfile"]) {
      const gemContent = this.readFile("Gemfile");
      if (gemContent?.includes("rails")) return "Rails";
      if (gemContent?.includes("sinatra")) return "Sinatra";
    }

    return undefined;
  }

  private detectBuildSystem(
    detectedFiles: Record<string, boolean>,
  ): string | undefined {
    if (detectedFiles["CMakeLists.txt"]) return "cmake";
    if (detectedFiles["Makefile"]) return "make";
    if (detectedFiles["build.gradle.kts"]) return "gradle-kotlin";
    if (detectedFiles["build.gradle"]) return "gradle";
    if (detectedFiles["pom.xml"]) return "maven";
    if (detectedFiles["Cargo.toml"]) return "cargo";
    if (detectedFiles["tsconfig.json"]) return "tsc";
    return undefined;
  }

  private extractDependencyInfo(
    detectedFiles: Record<string, boolean>,
    language: string,
  ): {
    dependencies: string[];
    devDependencies: string[];
    runtimeVersion: string | undefined;
  } {
    const dependencies: string[] = [];
    const devDependencies: string[] = [];
    let runtimeVersion: string | undefined;

    if (language === "node" || language === "typescript") {
      const content = this.readFile("package.json");
      if (content) {
        try {
          const pkg = JSON.parse(content);
          if (pkg.dependencies) dependencies.push(...Object.keys(pkg.dependencies));
          if (pkg.devDependencies) devDependencies.push(...Object.keys(pkg.devDependencies));
          runtimeVersion = pkg.engines?.node;
        } catch {
          // ignore
        }
      }
    }

    if (language === "python") {
      const content = this.readFile("requirements.txt");
      if (content) {
        const lines = content
          .split("\n")
          .map((l) => l.trim())
          .filter((l) => l && !l.startsWith("#"));
        for (const line of lines) {
          const name = line.split(/[><=!~;@\s]/)[0];
          if (name) dependencies.push(name);
        }
      }
      // Attempt to read .python-version
      const pyVer = this.readFile(".python-version");
      if (pyVer) runtimeVersion = pyVer.trim();
    }

    if (language === "rust") {
      const content = this.readFile("Cargo.toml");
      if (content) {
        const depSection = content.match(
          /\[dependencies\]([\s\S]*?)(?:\[|$)/,
        );
        if (depSection) {
          const lines = depSection[1]
            .split("\n")
            .filter((l) => l.includes("="));
          for (const line of lines) {
            const name = line.split("=")[0].trim();
            if (name) dependencies.push(name);
          }
        }
      }
    }

    if (language === "go") {
      const content = this.readFile("go.mod");
      if (content) {
        const goVer = content.match(/^go\s+([\d.]+)/m);
        if (goVer) runtimeVersion = goVer[1];
        const reqBlock = content.match(/require\s*\(([\s\S]*?)\)/);
        if (reqBlock) {
          const lines = reqBlock[1].split("\n").filter((l) => l.trim());
          for (const line of lines) {
            const name = line.trim().split(/\s+/)[0];
            if (name) dependencies.push(name);
          }
        }
      }
    }

    return { dependencies, devDependencies, runtimeVersion };
  }

  private suggestFeatures(
    language: string,
    detectedFiles: Record<string, boolean>,
  ): string[] {
    const features: string[] = [];

    if (detectedFiles["Dockerfile"] || detectedFiles[".dockerignore"]) {
      features.push("ghcr.io/devcontainers/features/docker-in-docker:2");
    }

    if (language === "python") {
      features.push("ghcr.io/devcontainers/features/python:1");
    }
    if (language === "node" || language === "typescript") {
      features.push("ghcr.io/devcontainers/features/node:1");
    }
    if (language === "go") {
      features.push("ghcr.io/devcontainers/features/go:1");
    }
    if (language === "rust") {
      features.push("ghcr.io/devcontainers/features/rust:1");
    }

    // Common dev tools
    features.push("ghcr.io/devcontainers/features/git:1");

    return features;
  }

  // ── Copilot refinement ──────────────────────────────────────────────────

  private async refineWithCopilot(
    analysis: ProjectAnalysis,
    detectedFiles: Record<string, boolean>,
  ): Promise<ProjectAnalysis> {
    const client = new CopilotClient();

    const readProjectFile = defineTool<{ filePath: string }>("readProjectFile", {
      description:
        "Read a file from the project being analyzed. " +
        "Use this to inspect configuration files, source code, or any file " +
        "in the project directory.",
      parameters: {
        type: "object" as const,
        properties: {
          filePath: {
            type: "string" as const,
            description: "Relative path to the file within the project directory",
          },
        },
        required: ["filePath"],
      },
      handler: async (params: { filePath: string }): Promise<string> => {
        const content = this.readFile(params.filePath);
        if (content === null) {
          return `Error: file not found or unreadable: ${params.filePath}`;
        }
        // Truncate large files to avoid token limits
        const maxLen = 8000;
        if (content.length > maxLen) {
          return content.slice(0, maxLen) + "\n... [truncated]";
        }
        return content;
      },
    });

    const fileList = Object.entries(detectedFiles)
      .filter(([, found]) => found)
      .map(([name]) => name)
      .join(", ");

    const prompt = [
      "Analyze this project and suggest improvements to the devcontainer configuration.",
      "",
      `Detected language: ${analysis.language}`,
      analysis.framework ? `Framework: ${analysis.framework}` : null,
      analysis.packageManager
        ? `Package manager: ${analysis.packageManager}`
        : null,
      `Detected files: ${fileList}`,
      `Dependencies: ${analysis.dependencies.slice(0, 30).join(", ")}`,
      "",
      "Current suggested image: " + analysis.suggestedImage,
      "Current suggested extensions: " + analysis.suggestedExtensions.join(", "),
      "",
      "Please use the readProjectFile tool to inspect relevant config files, " +
        "then respond with a JSON object containing any suggested changes to:",
      "  - suggestedImage (string)",
      "  - suggestedFeatures (string[])",
      "  - suggestedExtensions (string[])",
      "  - framework (string, if detected)",
      "  - runtimeVersion (string, if detected)",
      "",
      "Only include fields you want to change. Respond with valid JSON only.",
    ]
      .filter(Boolean)
      .join("\n");

    log("Requesting Copilot analysis...");

    const session = await client.createSession({
      tools: [readProjectFile],
    });
    let text = "";
    try {
      const response = await session.sendAndWait({ prompt });
      text = response?.data.content ?? "";
    } finally {
      await session.disconnect();
      await client.stop();
    }

    // Parse Copilot's refinement suggestions
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      try {
        const suggestions = JSON.parse(jsonMatch[0]) as Partial<ProjectAnalysis>;
        return {
          ...analysis,
          ...(suggestions.suggestedImage && {
            suggestedImage: suggestions.suggestedImage,
          }),
          ...(suggestions.suggestedFeatures && {
            suggestedFeatures: suggestions.suggestedFeatures,
          }),
          ...(suggestions.suggestedExtensions && {
            suggestedExtensions: suggestions.suggestedExtensions,
          }),
          ...(suggestions.framework && { framework: suggestions.framework }),
          ...(suggestions.runtimeVersion && {
            runtimeVersion: suggestions.runtimeVersion,
          }),
        };
      } catch {
        log("Could not parse Copilot suggestions, using local analysis");
      }
    }

    return analysis;
  }
}

// ── DevContainerGenerator ───────────────────────────────────────────────────

export class DevContainerGenerator {
  private analysis: ProjectAnalysis;

  constructor(analysis: ProjectAnalysis) {
    this.analysis = analysis;
  }

  generate(): DevContainerConfig {
    const config: DevContainerConfig = {
      name: this.buildContainerName(),
      image: this.analysis.suggestedImage,
      features: this.buildFeatures(),
      customizations: {
        vscode: {
          extensions: this.buildExtensions(),
          settings: this.buildSettings(),
        },
      },
      forwardPorts: this.detectPorts(),
      postCreateCommand: this.buildPostCreateCommand(),
      remoteUser: "vscode",
    };

    return config;
  }

  async generateWithCopilot(): Promise<DevContainerConfig> {
    const base = this.generate();

    try {
      const client = new CopilotClient();

      const prompt = [
        "Review this devcontainer.json configuration and suggest improvements.",
        "Respond with the complete, improved JSON configuration only.",
        "",
        "```json",
        JSON.stringify(base, null, 2),
        "```",
        "",
        `Project uses: ${this.analysis.language}`,
        this.analysis.framework ? `Framework: ${this.analysis.framework}` : "",
        `Package manager: ${this.analysis.packageManager ?? "unknown"}`,
      ].join("\n");

      const session = await client.createSession({});
      let text = "";
      try {
        const response = await session.sendAndWait({ prompt });
        text = response?.data.content ?? "";
      } finally {
        await session.disconnect();
        await client.stop();
      }

      const jsonMatch = text.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const refined = JSON.parse(jsonMatch[0]) as DevContainerConfig;
        // Validate required fields exist before accepting
        if (refined.name && refined.image) {
          return refined;
        }
      }
    } catch (error) {
      log(
        `Copilot refinement unavailable: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }

    return base;
  }

  writeToProject(projectPath: string): string {
    const config = this.generate();
    const devcontainerDir = path.join(projectPath, ".devcontainer");

    if (!fs.existsSync(devcontainerDir)) {
      fs.mkdirSync(devcontainerDir, { recursive: true });
    }

    const outputPath = path.join(devcontainerDir, "devcontainer.json");
    const content =
      "// For format details, see https://aka.ms/devcontainer.json\n" +
      JSON.stringify(config, null, 2) +
      "\n";

    fs.writeFileSync(outputPath, content, "utf-8");
    return outputPath;
  }

  // ── Private helpers ─────────────────────────────────────────────────────

  private buildContainerName(): string {
    const parts = ["sendbox"];
    if (this.analysis.language !== "unknown") {
      parts.push(this.analysis.language);
    }
    if (this.analysis.framework) {
      parts.push(this.analysis.framework.toLowerCase().replace(/[.\s]/g, "-"));
    }
    return parts.join("-");
  }

  private buildFeatures(): Record<string, unknown> {
    const features: Record<string, unknown> = {};
    for (const feature of this.analysis.suggestedFeatures) {
      features[feature] = {};
    }
    return features;
  }

  private buildExtensions(): string[] {
    const extensions = new Set(this.analysis.suggestedExtensions);

    // Always useful extensions
    extensions.add("EditorConfig.EditorConfig");
    extensions.add("GitHub.copilot");
    extensions.add("GitHub.copilot-chat");

    return [...extensions];
  }

  private buildSettings(): Record<string, unknown> {
    const settings: Record<string, unknown> = {
      "editor.formatOnSave": true,
      "editor.defaultFormatter": "esbenp.prettier-vscode",
    };

    switch (this.analysis.language) {
      case "python":
        settings["python.defaultInterpreterPath"] = "/usr/local/bin/python";
        settings["[python]"] = {
          "editor.defaultFormatter": "ms-python.black-formatter",
        };
        break;
      case "rust":
        settings["[rust]"] = {
          "editor.defaultFormatter": "rust-lang.rust-analyzer",
        };
        break;
      case "go":
        settings["[go]"] = {
          "editor.defaultFormatter": "golang.go",
        };
        settings["go.useLanguageServer"] = true;
        break;
    }

    return settings;
  }

  private detectPorts(): number[] {
    const ports: number[] = [];
    const { framework, language } = this.analysis;

    const frameworkPorts: Record<string, number[]> = {
      "Next.js": [3000],
      Nuxt: [3000],
      React: [3000],
      Angular: [4200],
      Vue: [5173],
      Svelte: [5173],
      Express: [3000],
      Fastify: [3000],
      Hono: [3000],
      NestJS: [3000],
      Django: [8000],
      Flask: [5000],
      FastAPI: [8000],
      Rails: [3000],
      Sinatra: [4567],
    };

    if (framework && frameworkPorts[framework]) {
      ports.push(...frameworkPorts[framework]);
    } else if (language === "node" || language === "typescript") {
      ports.push(3000);
    } else if (language === "python") {
      ports.push(8000);
    } else if (language === "go") {
      ports.push(8080);
    } else if (language === "ruby") {
      ports.push(3000);
    } else if (language === "java" || language === "kotlin") {
      ports.push(8080);
    } else if (language === "php") {
      ports.push(8000);
    }

    return ports;
  }

  private buildPostCreateCommand(): string {
    const pm = this.analysis.packageManager;
    if (pm && INSTALL_COMMANDS[pm]) {
      return INSTALL_COMMANDS[pm];
    }
    return "echo 'No post-create command configured'";
  }
}
