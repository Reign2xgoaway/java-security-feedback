import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

import { SecurityFinding } from "../models/securityFinding";

export function readSarifFile(
  sarifPath: string,
  sourceRoot: string
): SecurityFinding[] {
  const resolvedSarifPath = path.resolve(sarifPath);

  if (!fs.existsSync(resolvedSarifPath)) {
    throw new Error(
      `SARIF file not found: ${resolvedSarifPath}`
    );
  }

  const content = fs.readFileSync(
    resolvedSarifPath,
    "utf8"
  );

  const sarif = JSON.parse(content);

  const findings: SecurityFinding[] = [];

  for (const run of sarif.runs ?? []) {
    for (const result of run.results ?? []) {
      const message =
        result.message?.text?.trim() ||
        result.message?.markdown?.trim();

      if (!message) {
        continue;
      }

      const physicalLocation =
        result.locations?.[0]?.physicalLocation;

      const uri =
        physicalLocation?.artifactLocation?.uri;

      const region = physicalLocation?.region;

      if (!uri || !region?.startLine) {
        continue;
      }

      let filePath: string;

      if (/^file:/i.test(uri)) {
        filePath = fileURLToPath(uri);
      } else {
        let decodedUri = uri;

        try {
          decodedUri = decodeURIComponent(uri);
        } catch {
          // Retain the original URI if decoding fails.
        }

        filePath = path.isAbsolute(decodedUri)
          ? path.normalize(decodedUri)
          : path.resolve(
              sourceRoot,
              decodedUri.replace(/[\\/]/g, path.sep)
            );
      }

      const apiMatch = message.match(
        /Affected API:\s*(.+)$/i
      );

      const finding: SecurityFinding = {
        ruleId: result.ruleId ?? "unknown",
        title:
          "Hard-coded password passed to Java security APIs",
        message,
        filePath,
        startLine: region.startLine,
        startColumn: region.startColumn,
        endLine: region.endLine,
        endColumn: region.endColumn,
        affectedApi:
          apiMatch?.[1]?.trim() ??
          "Java security API (not specified by CodeQL)"
      };

      findings.push(finding);
    }
  }

  return findings;
}
