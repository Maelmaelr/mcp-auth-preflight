import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

const reportPath = new URL("../sample/plain-public-report.json", import.meta.url);
const manifestPath = new URL("../sample/plain-public-manifest.json", import.meta.url);
const narrativePath = new URL("../sample/plain-public-report.md", import.meta.url);
const readmePath = new URL("../README.md", import.meta.url);
const implementationFormPath = new URL("../.github/ISSUE_TEMPLATE/implementation.yml", import.meta.url);

test("the public sample is version-bound, internally consistent evidence", async () => {
  const [reportBytes, manifestText, narrative] = await Promise.all([
    readFile(reportPath),
    readFile(manifestPath, "utf8"),
    readFile(narrativePath, "utf8"),
  ]);
  const report = JSON.parse(reportBytes);
  const manifest = JSON.parse(manifestText);
  const digest = createHash("sha256").update(reportBytes).digest("hex");

  assert.equal(manifest.schema_version, "mcp-auth-preflight-evidence/v1");
  assert.equal(manifest.observation_kind, "historical_public_metadata");
  assert.equal(manifest.report.path, "sample/plain-public-report.json");
  assert.equal(manifest.report.sha256, digest);
  assert.match(manifest.engine_commit, /^[0-9a-f]{40}$/);
  assert.match(manifest.node_version, /^v\d+\.\d+\.\d+$/);
  assert.equal(
    manifest.command,
    "node src/cli.mjs https://mcp.plain.com/mcp --json --require-auth",
  );
  assert.equal(report.endpoint, manifest.endpoint);
  assert.equal(report.checked_at, manifest.checked_at);
  assert.equal(report.require_auth, true);

  const counts = { fail: 0, warn: 0, pass: 0, info: 0 };
  for (const finding of report.findings) counts[finding.level] += 1;
  assert.deepEqual(report.summary.counts, counts);
  assert.deepEqual(manifest.summary, report.summary);

  assert.match(narrative, new RegExp(manifest.checked_at.replaceAll(".", "\\.")));
  assert.match(narrative, new RegExp(manifest.engine_commit));
  assert.match(narrative, new RegExp(manifest.report.sha256));
  assert.match(narrative, /dated observation/i);
});

test("the available commercial route is a non-binding public-data fit check", async () => {
  const [readme, implementationForm] = await Promise.all([
    readFile(readmePath, "utf8"),
    readFile(implementationFormPath, "utf8"),
  ]);

  assert.doesNotMatch(readme, /upwork\.com\/services\/product/);
  assert.match(readme, /Request a USD 399 implementation estimate/);
  assert.match(readme, /not a proposal, contract, funded order, or support channel/);
  assert.match(implementationForm, /safe to post publicly/i);
  assert.match(implementationForm, /Do not include credentials, tokens, private endpoints/i);
  assert.match(implementationForm, /USD 399 scope is acceptable if the fit is confirmed/);
});
