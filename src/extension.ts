import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import { createHash } from "crypto";
import { spawn, ChildProcess } from "child_process";

import { SecurityFinding } from "./models/securityFinding";
import { readSarifFile } from "./detection/sarifReader";
import { SecurityDiagnosticProvider } from "./diagnostics/diagnosticProvider";
import { createSecurityHoverProvider } from "./presentation/hoverProvider";

let activeCodeQLProcess: ChildProcess | undefined;

interface AnalysisCache {
  schemaVersion: number;
  workspaceIdentity: string;
  sourceFingerprint: string;
  codeqlPath: string;
  codeqlVersion: string;
  queryFingerprint: string;
}

export function activate(context: vscode.ExtensionContext) {
  const diagnosticProvider = new SecurityDiagnosticProvider();

  const outputChannel =
    vscode.window.createOutputChannel("Java Security Feedback");

  let findings: SecurityFinding[] = [];
  let analysisRunning = false;

  const hoverProvider = createSecurityHoverProvider(
    () => findings,
    async () => await context.secrets.get("geminiApiKey")
  );

  const hoverRegistration =
    vscode.languages.registerHoverProvider(
      { language: "java" },
      hoverProvider
    );

  context.subscriptions.push(
    diagnosticProvider,
    hoverRegistration,
    outputChannel
  );

  // Execute CodeQL and stream output to the Output panel.
  function executeCodeQL(
    codeqlPath: string,
    args: string[],
    workingDirectory: string
  ): Promise<string> {
    return new Promise((resolve, reject) => {
      outputChannel.appendLine(
        `> ${codeqlPath} ${args.join(" ")}`
      );

      let child: ChildProcess;

      try {
        child = spawn(
          codeqlPath,
          args,
          {
            cwd: workingDirectory,
            windowsHide: true,
            shell: false
          }
        );
      } catch (error) {
        reject(error);
        return;
      }

      activeCodeQLProcess = child;

      let stdoutOutput = "";
      let stderrOutput = "";
      let settled = false;

      const finish = (callback: () => void) => {
        if (settled) {
          return;
        }

        settled = true;

        if (activeCodeQLProcess === child) {
          activeCodeQLProcess = undefined;
        }

        callback();
      };

      child.stdout?.on("data", (data: Buffer) => {
        const message = data.toString();

        stdoutOutput = (
          stdoutOutput + message
        ).slice(-20000);

        outputChannel.append(message);
      });

      child.stderr?.on("data", (data: Buffer) => {
        const message = data.toString();

        stderrOutput = (
          stderrOutput + message
        ).slice(-20000);

        outputChannel.append(message);
      });

      child.on("error", (error) => {
        finish(() => reject(error));
      });

      child.on("close", (code, signal) => {
        if (code === 0) {
          finish(() => resolve(stdoutOutput));
          return;
        }

        const errorMessage = [
          `CodeQL exited with code ${code}.`,
          signal ? `Signal: ${signal}` : "",
          stderrOutput.trim()
        ]
          .filter(Boolean)
          .join("\n");

        finish(() => reject(new Error(errorMessage)));
      });
    });
  }

  // Generate a fingerprint from all Java source files.
  async function calculateSourceFingerprint(
    javaFiles: vscode.Uri[],
    workspaceRoot: string
  ): Promise<string> {
    const hash = createHash("sha256");

    const sortedFiles = [...javaFiles].sort(
      (a, b) => a.fsPath.localeCompare(b.fsPath)
    );

    for (const file of sortedFiles) {
      const relativePath = path.relative(
        workspaceRoot,
        file.fsPath
      ).replace(/\\/g, "/");

      const content = await fs.promises.readFile(
        file.fsPath
      );

      hash.update(relativePath);
      hash.update("\0");
      hash.update(content);
      hash.update("\0");
    }

    return hash.digest("hex");
  }

  // Generate a fingerprint from the CodeQL query.
  async function calculateQueryFingerprint(
    queryPath: string
  ): Promise<string> {
    const content = await fs.promises.readFile(queryPath);

    return createHash("sha256")
      .update(content)
      .digest("hex");
  }

  // Read the previous analysis cache.
  async function readAnalysisCache(
    cachePath: string
  ): Promise<AnalysisCache | undefined> {
    try {
      const content = await fs.promises.readFile(
        cachePath,
        "utf8"
      );

      const cache = JSON.parse(content) as Partial<AnalysisCache>;

      if (
        cache.schemaVersion !== 1 ||
        typeof cache.workspaceIdentity !== "string" ||
        typeof cache.sourceFingerprint !== "string" ||
        typeof cache.codeqlPath !== "string" ||
        typeof cache.codeqlVersion !== "string" ||
        typeof cache.queryFingerprint !== "string"
      ) {
        return undefined;
      }

      return cache as AnalysisCache;
    } catch {
      return undefined;
    }
  }

  // Save the analysis cache.
  async function saveAnalysisCache(
    cachePath: string,
    cache: AnalysisCache
  ): Promise<void> {
    await fs.promises.writeFile(
      cachePath,
      JSON.stringify(cache, null, 2),
      "utf8"
    );
  }

  // Run security analysis manually against the opened folder.
  async function runSecurityAnalysis(): Promise<void> {
    if (analysisRunning) {
      vscode.window.showWarningMessage(
        "Security analysis is already running."
      );
      return;
    }

    const workspaceFolder =
      vscode.workspace.workspaceFolders?.[0];

    if (!workspaceFolder) {
      vscode.window.showErrorMessage(
        "Open a folder containing Java files before running security analysis."
      );
      return;
    }

    analysisRunning = true;

    try {
      const workspaceRoot = path.resolve(
        workspaceFolder.uri.fsPath
      );

      const workspaceIdentity =
        process.platform === "win32"
          ? workspaceRoot.toLowerCase()
          : workspaceRoot;

      const javaFiles = await vscode.workspace.findFiles(
        new vscode.RelativePattern(
          workspaceFolder,
          "**/*.java"
        ),
        "**/{.git,node_modules,target,build,.gradle,out}/**"
      );

      if (javaFiles.length === 0) {
        findings = [];
        diagnosticProvider.update([]);

        throw new Error(
          "No Java source files were found in the opened folder."
        );
      }

      const queryPath = context.asAbsolutePath(
        path.join("codeql", "HardcodedPassword.ql")
      );

      if (!fs.existsSync(queryPath)) {
        throw new Error(
          `CodeQL query file not found: ${queryPath}`
        );
      }

      const configuration =
        vscode.workspace.getConfiguration(
          "java-security-feedback"
        );

      const codeqlPath =
        configuration.get<string>("codeqlPath", "codeql");

      const storageRoot =
        context.storageUri?.fsPath ??
        context.globalStorageUri.fsPath;

      // Keep a separate database and cache for each project.
      const workspaceKey = createHash("sha256")
        .update(workspaceIdentity)
        .digest("hex");

      const workspaceStorage = path.join(
        storageRoot,
        "workspaces",
        workspaceKey
      );

      const databasePath = path.join(
        workspaceStorage,
        "codeql-database"
      );

      const sarifPath = path.join(
        workspaceStorage,
        "results.sarif"
      );

      const cachePath = path.join(
        workspaceStorage,
        "analysis-cache.json"
      );

      await fs.promises.mkdir(workspaceStorage, {
        recursive: true
      });

      outputChannel.clear();
      outputChannel.show(true);

      outputChannel.appendLine(
        "Java Security Feedback"
      );

      outputChannel.appendLine(
        `Workspace: ${workspaceRoot}`
      );

      outputChannel.appendLine(
        `Java files found: ${javaFiles.length}`
      );

      outputChannel.appendLine(
        `Query: ${queryPath}`
      );

      // Calculate fingerprints.
      outputChannel.appendLine(
        "\nChecking whether source files or query have changed..."
      );

      const sourceFingerprint =
        await calculateSourceFingerprint(
          javaFiles,
          workspaceRoot
        );

      const queryFingerprint =
        await calculateQueryFingerprint(queryPath);

      // Get the CodeQL version for cache compatibility.
      const codeqlVersion = (
        await executeCodeQL(
          codeqlPath,
          ["version"],
          workspaceRoot
        )
      ).trim();

      const previousCache =
        await readAnalysisCache(cachePath);

      // Determine whether the existing database can be reused.
      const canReuseDatabase =
        previousCache !== undefined &&
        previousCache.schemaVersion === 1 &&
        previousCache.workspaceIdentity === workspaceIdentity &&
        previousCache.sourceFingerprint === sourceFingerprint &&
        previousCache.codeqlPath === codeqlPath &&
        previousCache.codeqlVersion === codeqlVersion &&
        fs.existsSync(databasePath);

      let currentCache: AnalysisCache;

      if (canReuseDatabase) {
        outputChannel.appendLine(
          "\nJava source files have not changed."
        );

        outputChannel.appendLine(
          "Reusing existing CodeQL database."
        );

        currentCache = previousCache;
      } else {
        // Create a new database only when source files or
        // the CodeQL installation have changed.
        outputChannel.appendLine(
          "\nJava source files have changed or no reusable database exists."
        );

        outputChannel.appendLine(
          "Creating a new CodeQL database..."
        );

        await executeCodeQL(
          codeqlPath,
          [
            "database",
            "create",
            "--language=java",
            "--build-mode=none",
            `--source-root=${workspaceRoot}`,
            "--overwrite",
            databasePath
          ],
          workspaceRoot
        );

        outputChannel.appendLine(
          "\nCodeQL database creation completed."
        );

        currentCache = {
          schemaVersion: 1,
          workspaceIdentity,
          sourceFingerprint,
          codeqlPath,
          codeqlVersion,
          queryFingerprint: ""
        };

        // Save database information immediately.
        await saveAnalysisCache(
          cachePath,
          currentCache
        );
      }

      // Determine whether previous query results can be reused.
      const canReuseResults =
        canReuseDatabase &&
        currentCache.queryFingerprint === queryFingerprint &&
        fs.existsSync(sarifPath);

      if (canReuseResults) {
        outputChannel.appendLine(
          "\nCodeQL query has not changed."
        );

        outputChannel.appendLine(
          "Reusing previous SARIF results. Skipping query execution."
        );
      } else {
        // The database is reusable, but the query has changed
        // or previous results are unavailable.
        outputChannel.appendLine(
          "\nRunning security query..."
        );

        await executeCodeQL(
          codeqlPath,
          [
            "database",
            "analyze",
            databasePath,
            queryPath,
            "--format=sarif-latest",
            `--output=${sarifPath}`
          ],
          workspaceRoot
        );

        outputChannel.appendLine(
          "\nSecurity query completed."
        );

        currentCache.queryFingerprint = queryFingerprint;

        await saveAnalysisCache(
          cachePath,
          currentCache
        );
      }

      // Load the previous or newly generated SARIF results.
      outputChannel.appendLine(
        "\nLoading security findings..."
      );

      findings = readSarifFile(
        sarifPath,
        workspaceRoot
      );

      diagnosticProvider.update(findings);

      outputChannel.appendLine(
        `\nAnalysis completed: ${findings.length} finding(s).`
      );

      vscode.window.showInformationMessage(
        `Security analysis completed. Found ${findings.length} finding(s).`
      );
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : String(error);

      outputChannel.appendLine(
        `\nAnalysis failed: ${message}`
      );

      vscode.window.showErrorMessage(
        `Security analysis failed: ${message}`
      );
    } finally {
      analysisRunning = false;
    }
  }

  // Manual security analysis command.
  const runAnalysisCommand =
    vscode.commands.registerCommand(
      "java-security-feedback.runAnalysis",
      async () => {
        await runSecurityAnalysis();
      }
    );

  // Save the developer's Gemini API key securely.
  const setGeminiApiKeyCommand =
    vscode.commands.registerCommand(
      "java-security-feedback.setGeminiApiKey",
      async () => {
        const apiKey = await vscode.window.showInputBox({
          prompt: "Enter your Gemini API key",
          password: true,
          ignoreFocusOut: true,
          placeHolder: "Gemini API key"
        });

        if (apiKey === undefined) {
          return;
        }

        if (!apiKey.trim()) {
          vscode.window.showErrorMessage(
            "Gemini API key cannot be empty."
          );
          return;
        }

        await context.secrets.store(
          "geminiApiKey",
          apiKey.trim()
        );

        vscode.window.showInformationMessage(
          "Gemini API key saved securely."
        );
      }
    );

  // Remove the developer's Gemini API key.
  const removeGeminiApiKeyCommand =
    vscode.commands.registerCommand(
      "java-security-feedback.removeGeminiApiKey",
      async () => {
        await context.secrets.delete("geminiApiKey");

        vscode.window.showInformationMessage(
          "Gemini API key removed."
        );
      }
    );

  context.subscriptions.push(
    runAnalysisCommand,
    setGeminiApiKeyCommand,
    removeGeminiApiKeyCommand
  );
}

export function deactivate() {
  if (activeCodeQLProcess) {
    activeCodeQLProcess.kill();
    activeCodeQLProcess = undefined;
  }
}
