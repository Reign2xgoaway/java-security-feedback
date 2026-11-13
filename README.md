# Java Security Feedback

**Java Security Feedback** is a Visual Studio Code extension that helps Java developers investigate hard-coded passwords passed to selected Java security APIs. It runs a bundled CodeQL query against the currently opened workspace, shows findings as editor warnings, and provides contextual remediation guidance when you hover over a finding.

The extension currently checks password arguments to `javax.crypto.spec.PBEKeySpec` and `java.security.KeyStore.load()`. It is a focused aid for reviewing code, not a general Java security scanner or proof that a reported value is a live credential or exploitable vulnerability.

## Features

- **CodeQL analysis on demand:** scan Java source files in the first opened workspace folder.
- **Editor diagnostics:** reported findings appear as warning squiggles and entries in VS Code's Problems panel.
- **Contextual hover feedback:** see the affected API, an explanation, practical suggestions, and (for the supported APIs) an illustrative Java example and Oracle documentation link.
- **Optional Gemini explanations:** configure a Gemini API key to request a concise, finding-specific explanation. If the key is missing or the request fails, the extension displays its built-in explanation instead.
- **Per-workspace CodeQL reuse:** source, query, and CodeQL version fingerprints determine whether the database and SARIF results can be reused on a later analysis.
- **CodeQL output:** command output and errors are available in the **Java Security Feedback** Output channel.

## Requirements

- Visual Studio Code **1.143.0 or later**.
- The [CodeQL CLI](https://github.com/github/codeql-cli-binaries/releases) installed and available on `PATH`, or the path to its executable configured in the extension settings.
- A workspace folder containing Java source files (`.java`).
- A Gemini API key is optional. Without one, hover feedback uses the built-in explanation.

CodeQL must be able to create a Java database from the opened project. The extension invokes database creation with `--build-mode=none`; it does not run your build system.

## Install and run

1. Install the extension in VS Code.
2. Open the Java project folder you want to analyze.
3. Confirm that the CodeQL CLI is installed. If it is not on `PATH`, set `java-security-feedback.codeqlPath` to its executable path.
4. Open the Command Palette (`Ctrl+Shift+P` on Windows/Linux or `Cmd+Shift+P` on macOS).
5. Run **Java Security Feedback: Run Security Analysis**.
6. Review the warnings in the editor or Problems panel. Hover over a highlighted finding for its explanation and remediation guidance.

The extension scans Java files in the first workspace folder, excluding `.git`, `node_modules`, `target`, `build`, `.gradle`, and `out` directories. Analysis runs only when you invoke the command; opening a Java file activates the extension but does not start a scan.

## Gemini API key (optional)

To enable Gemini-generated hover explanations:

1. Obtain a Gemini API key from [Google AI Studio](https://aistudio.google.com/app/apikey).
2. Run **Java Security Feedback: Set Gemini API Key** from the Command Palette.
3. Enter the key in the password-masked input box.

The key is stored using VS Code's SecretStorage. To remove it, run **Java Security Feedback: Remove Gemini API Key**. The extension sends the finding's rule ID, title, affected API, and CodeQL message to Google's Gemini API to generate an explanation. It does not send the source file contents as part of that request. Hover explanations are cached in memory for the current extension session. If there is no key, the network request fails, or the response is unusable, a built-in explanation is shown.

## Extension settings

| Setting | Default | Description |
| --- | --- | --- |
| `java-security-feedback.codeqlPath` | `codeql` | Path or command name used to launch the CodeQL CLI. Use `codeql` when it is available on `PATH`. |

For example, add this to your VS Code `settings.json` if CodeQL is installed outside `PATH`:

```json
{
  "java-security-feedback.codeqlPath": "C:/tools/codeql/codeql.exe"
}
```

## How analysis works

When you run the analysis command, the extension:

1. Finds Java source files in the first workspace folder, applying the exclusions listed above.
2. Creates or reuses a CodeQL Java database in the extension's workspace storage.
3. Runs the bundled `codeql/HardcodedPassword.ql` query and writes SARIF results to that storage.
4. Converts SARIF results into VS Code warning diagnostics and hover information.

The query looks for non-empty string literals that flow to the password argument of either:

- `PBEKeySpec(char[] password, ...)`
- `KeyStore.load(InputStream, char[] password)`

### CodeQL Java test fixture

`codeql/codeql-test/Test.java` contains 12 small cases covering both APIs. The cases exercise direct literals, literals assigned to variables, helper methods, calls across classes, character-array initialization, and values read from environment variables.

| Case | API | Scenario | Expected by the current query |
| --- | --- | --- | --- |
| 1 | `PBEKeySpec` | Hard-coded string assigned to a variable, then converted to `char[]` | Finding |
| 2 | `PBEKeySpec` | Direct hard-coded string literal, then converted to `char[]` | Finding |
| 3 | `PBEKeySpec` | Password initialized directly as a `char[]` | No finding |
| 4 | `PBEKeySpec` | Hard-coded string passed through a helper method | Finding |
| 5 | `PBEKeySpec` | Hard-coded string passed through a helper class | Finding |
| 6 | `PBEKeySpec` | Password read from an environment variable | No finding |
| 7 | `KeyStore.load()` | Hard-coded string assigned to a variable, then converted to `char[]` | Finding |
| 8 | `KeyStore.load()` | Direct hard-coded string literal, then converted to `char[]` | Finding |
| 9 | `KeyStore.load()` | Password initialized directly as a `char[]` | No finding |
| 10 | `KeyStore.load()` | Hard-coded string passed through a helper method | Finding |
| 11 | `KeyStore.load()` | Hard-coded string passed through a helper class | Finding |
| 12 | `KeyStore.load()` | Password read from an environment variable | No finding |

The expected outcomes reflect the query's current source definition: it treats non-empty string literals as sources and tracks their flow to the selected password arguments. Character-array initializers and environment-variable reads are included as comparison cases, but are not string-literal sources in this query.

The database is rebuilt when the Java source fingerprint, configured CodeQL command, or CodeQL version changes. Query results are rerun when the query fingerprint changes or no previous SARIF result is available. Workspace-specific analysis data is stored under VS Code's extension storage; it is not written into the Java project folder.

## Development

Clone the repository, install dependencies, and open it in VS Code:

```sh
npm install
npm run compile
```

Press `F5` to launch an Extension Development Host. In that window, open a Java project and run **Java Security Feedback: Run Security Analysis**.

Useful scripts:

| Script | Purpose |
| --- | --- |
| `npm run compile` | Check TypeScript types, lint `src`, and build the extension into `dist/`. |
| `npm run watch` | Rebuild and type-check while developing. |
| `npm run check-types` | Run the TypeScript type check. |
| `npm run lint` | Lint the source files. |
| `npm test` | Compile the tests and extension, then run the VS Code extension test suite. |
| `npm run package` | Type-check, lint, and create a production build. |

The CodeQL query is in `codeql/HardcodedPassword.ql`. Extension implementation is under `src/`, grouped into detection, diagnostics, feedback, presentation, remediation, and model modules.

## Limitations

- The bundled query covers only hard-coded string flows to the two password arguments listed above; it does not cover all credential storage or security issues.
- Findings are warnings for developer review. Check the surrounding code and the value's origin and use before deciding how to respond.
- The extension analyzes only the first workspace folder and does not automatically rerun after edits.
- Gemini explanations require a network connection and a valid API key. The built-in explanation remains available without Gemini.
- Example code is illustrative guidance. Adapt it to your application and secret-management setup; the extension does not rewrite code automatically.

## License

No license file is currently included in this repository. Check with the project maintainers for reuse and distribution terms.
