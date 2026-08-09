#!/usr/bin/env node

import { preflight } from "./preflight.mjs";

const args = process.argv.slice(2);
const json = args.includes("--json");
const requireAuth = args.includes("--require-auth");
const endpoint = args.find((arg) => !arg.startsWith("--"));

if (!endpoint || args.includes("--help")) {
  process.stdout.write("Usage: node src/cli.mjs <https://remote.example/mcp> [--json] [--require-auth]\n");
  process.exit(endpoint ? 0 : 1);
}

try {
  const report = await preflight(endpoint, { requireAuth });
  if (json) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    process.stdout.write(`# MCP authorization preflight\n\n`);
    process.stdout.write(`- Endpoint: ${report.endpoint}\n`);
    process.stdout.write(`- Protocol target: ${report.protocol_version}\n`);
    process.stdout.write(`- Result: ${report.summary.status.toUpperCase()}\n`);
    process.stdout.write(`- Findings: ${report.summary.counts.fail} fail, ${report.summary.counts.warn} warning, ${report.summary.counts.pass} pass, ${report.summary.counts.info} info\n\n`);
    for (const finding of report.findings) {
      process.stdout.write(`- [${finding.level.toUpperCase()}] ${finding.code}: ${finding.message}\n`);
    }
  }
  if (report.summary.status === "fail") process.exitCode = 2;
} catch (error) {
  process.stderr.write(`mcp-auth-preflight: ${error.message}\n`);
  process.exitCode = 1;
}
