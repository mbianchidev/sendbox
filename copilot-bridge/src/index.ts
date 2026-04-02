#!/usr/bin/env node

import * as path from "path";
import { ProjectAnalyzer, DevContainerGenerator } from "./analyzer.js";

// ── Logging (to stderr, keeping stdout clean for JSON) ──────────────────────

function log(message: string): void {
  process.stderr.write(`[sendbox] ${message}\n`);
}

function fatal(message: string, exitCode = 1): never {
  process.stderr.write(`[sendbox] ERROR: ${message}\n`);
  process.exit(exitCode);
}

// ── CLI ─────────────────────────────────────────────────────────────────────

type Action = "analyze" | "generate";

interface CliArgs {
  action: Action;
  projectPath: string;
}

function parseArgs(): CliArgs {
  const args = process.argv.slice(2);

  if (args.includes("--help") || args.includes("-h") || args.length === 0) {
    process.stderr.write(
      [
        "Usage: sendbox-bridge <action> [project-path]",
        "",
        "Actions:",
        "  analyze   Analyze a project and output JSON to stdout",
        "  generate  Analyze a project and generate .devcontainer/devcontainer.json",
        "",
        "Options:",
        "  --help, -h  Show this help message",
        "",
        "If project-path is omitted, the current directory is used.",
        "",
      ].join("\n"),
    );
    process.exit(args.includes("--help") || args.includes("-h") ? 0 : 1);
  }

  const action = args[0] as string;
  if (action !== "analyze" && action !== "generate") {
    fatal(`Unknown action: "${action}". Use "analyze" or "generate".`);
  }

  const projectPath = args[1] ?? process.cwd();

  return { action, projectPath: path.resolve(projectPath) };
}

// ── Main ────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const { action, projectPath } = parseArgs();

  log(`Action: ${action}`);
  log(`Project: ${projectPath}`);

  const analyzer = new ProjectAnalyzer(projectPath);

  switch (action) {
    case "analyze": {
      const analysis = await analyzer.analyze();
      process.stdout.write(JSON.stringify(analysis, null, 2) + "\n");
      log("Analysis complete.");
      break;
    }

    case "generate": {
      const analysis = await analyzer.analyze();
      const generator = new DevContainerGenerator(analysis);
      const outputPath = generator.writeToProject(projectPath);
      // Output the path as JSON for programmatic consumption
      process.stdout.write(JSON.stringify({ path: outputPath }) + "\n");
      log(`Generated devcontainer config at ${outputPath}`);
      break;
    }
  }
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  fatal(`Unhandled error: ${message}`);
});
