import * as vscode from "vscode";
import * as path from "path";

import { SecurityFinding } from "../models/securityFinding";
import { generateExplanation } from "../feedback/geminiClient";
import { getFallbackExplanation } from "../feedback/fallbackExplanationService";

import {
  getApiExampleFix,
  getApiDocumentation
} from "../remediation/apiRemediation";

export function createSecurityHoverProvider(
  getFindings: () => SecurityFinding[],
  getApiKey: () => Promise<string | undefined>
): vscode.HoverProvider {
  return {
    async provideHover(
      document: vscode.TextDocument,
      position: vscode.Position
    ): Promise<vscode.Hover | undefined> {
      const documentPath = path.resolve(document.uri.fsPath);

      const finding = getFindings().find((item) => {
        const findingPath = path.resolve(item.filePath);

        if (findingPath !== documentPath) {
          return false;
        }

        const lineMatches =
          position.line + 1 >= item.startLine &&
          position.line + 1 <= (item.endLine ?? item.startLine);

        if (!lineMatches) {
          return false;
        }

        if (item.startColumn !== undefined) {
          const startColumn = item.startColumn - 1;

          const endColumn =
            item.endColumn !== undefined
              ? item.endColumn - 1
              : startColumn + 1;

          return (
            position.character >= startColumn &&
            position.character <= endColumn
          );
        }

        return true;
      });

      if (!finding) {
        return undefined;
      }

      let explanation;

      try {
        const apiKey = await getApiKey();

        explanation = await generateExplanation(finding, apiKey);
      } catch {
        explanation = undefined;
      }

      if (!explanation) {
        explanation = getFallbackExplanation(finding);
      }

      const markdown = new vscode.MarkdownString();

      markdown.isTrusted = false;
      markdown.supportHtml = false;
      markdown.supportThemeIcons = true;

      // Affected API
      markdown.appendMarkdown("**🔑 Affected API**\n\n");
      markdown.appendCodeblock(finding.affectedApi, "java");

      // Why this matters
      markdown.appendMarkdown("**💡 Why this matters**\n\n");
      markdown.appendMarkdown(
        `${explanation.whyItMatters}\n\n`
      );

      // Suggested actions
      markdown.appendMarkdown("**🔧 What you should do**\n\n");

      for (const action of explanation.suggestedAction) {
        markdown.appendMarkdown(`- ${action}\n`);
      }

      // Example fix: displayed only when an example exists.
      const exampleFix = getApiExampleFix(finding.affectedApi);

      if (exampleFix) {
        markdown.appendMarkdown("\n---\n\n");

        markdown.appendMarkdown("**🛠️ Example fix**\n\n");

        markdown.appendCodeblock(
          exampleFix.exampleCode,
          "java"
        );
      }

      // Documentation: displayed independently of example availability.
      const documentation = getApiDocumentation(
        finding.affectedApi
      );

      if (documentation) {
        markdown.appendMarkdown("\n---\n\n");

        markdown.appendMarkdown("**📚 Learn more**\n\n");

        markdown.appendMarkdown(
          `[$(link-external) ${documentation.documentationLabel}](${documentation.documentationUrl})\n`
        );
      }

      return new vscode.Hover(markdown);
    }
  };
}
