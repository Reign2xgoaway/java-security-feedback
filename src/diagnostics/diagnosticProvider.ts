import * as vscode from "vscode";
import { SecurityFinding } from "../models/securityFinding";

export class SecurityDiagnosticProvider {
  private readonly diagnosticCollection: vscode.DiagnosticCollection;

  constructor() {
    this.diagnosticCollection =
      vscode.languages.createDiagnosticCollection(
        "java-security-feedback"
      );
  }

  update(findings: SecurityFinding[]): void {
    this.diagnosticCollection.clear();

    const diagnosticsByFile = new Map<
      string,
      vscode.Diagnostic[]
    >();

    for (const finding of findings) {
      const fileUri = vscode.Uri.file(finding.filePath);

      const startColumn = Math.max(
        0,
        (finding.startColumn ?? 1) - 1
      );

      const endLine =
        (finding.endLine ?? finding.startLine) - 1;

      const endColumn =
        finding.endColumn !== undefined
          ? Math.max(0, finding.endColumn - 1)
          : startColumn + 1;

      const range = new vscode.Range(
        finding.startLine - 1,
        startColumn,
        endLine,
        endColumn
      );

      const diagnostic = new vscode.Diagnostic(
        range,
        "⚠️ Potential hard-coded password passed to Java security API",
        vscode.DiagnosticSeverity.Warning
      );

      const existing =
        diagnosticsByFile.get(fileUri.fsPath) ?? [];

      existing.push(diagnostic);

      diagnosticsByFile.set(fileUri.fsPath, existing);
    }

    for (const [filePath, diagnostics] of diagnosticsByFile) {
      this.diagnosticCollection.set(
        vscode.Uri.file(filePath),
        diagnostics
      );
    }
  }

  clear(): void {
    this.diagnosticCollection.clear();
  }

  dispose(): void {
    this.diagnosticCollection.dispose();
  }
}
