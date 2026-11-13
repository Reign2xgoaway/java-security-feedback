import { SecurityExplanation } from "../models/securityExplanation";
import { SecurityFinding } from "../models/securityFinding";

const MODEL_NAME = "gemini-3.5-flash-lite";

const API_URL =
  `https://generativelanguage.googleapis.com/v1beta/models/${MODEL_NAME}:generateContent`;

interface GeminiResponse {
  candidates?: Array<{
    content?: {
      parts?: Array<{
        text?: string;
      }>;
    };
  }>;
}

const explanationCache = new Map<string, SecurityExplanation>();

function isValidExplanation(
  value: unknown
): value is SecurityExplanation {
  if (!value || typeof value !== "object") {
    return false;
  }

  const explanation = value as Record<string, unknown>;

  return (
    typeof explanation.whyItMatters === "string" &&
    explanation.whyItMatters.trim().length > 0 &&
    Array.isArray(explanation.suggestedAction) &&
    explanation.suggestedAction.length > 0 &&
    explanation.suggestedAction.every(
      (item) =>
        typeof item === "string" && item.trim().length > 0
    ) &&
    typeof explanation.confidenceNote === "string" &&
    explanation.confidenceNote.trim().length > 0
  );
}

export async function generateExplanation(
  finding: SecurityFinding,
  apiKey: string | undefined
): Promise<SecurityExplanation | undefined> {
  if (!apiKey) {
    return undefined;
  }

  const cacheKey = [
    finding.ruleId,
    finding.filePath,
    finding.startLine,
    finding.message
  ].join(":");

  const cached = explanationCache.get(cacheKey);

  if (cached) {
    return cached;
  }

  const systemPrompt = `
You are a security assistant helping Java developers understand
security findings involving hard-coded passwords in Java security APIs.

Return only valid JSON with exactly these properties:

{
  "whyItMatters": "Explain the potential security risk.",
  "suggestedAction": [
    "First practical recommendation",
    "Second practical recommendation"
  ],
  "confidenceNote": "Explain what the finding establishes and its limitations."
}

Requirements:
- Use clear and concise language.
- Do not automatically claim that the application is vulnerable.
- Do not assume the hard-coded value is a real credential.
- Explain the potential consequences of exposing passwords.
- Give practical recommendations relevant to Java development.
- Acknowledge that the surrounding code must be reviewed.
- Do not suggest that CodeQL has proven an exploit exists.
`;

  const findingInformation = {
    ruleId: finding.ruleId,
    title: finding.title,
    affectedApi: finding.affectedApi,
    message: finding.message
  };

  const controller = new AbortController();

  const timeout = setTimeout(
    () => controller.abort(),
    30000
  );

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-goog-api-key": apiKey
      },
      body: JSON.stringify({
        systemInstruction: {
          parts: [{ text: systemPrompt }]
        },
        contents: [
          {
            role: "user",
            parts: [
              {
                text: JSON.stringify(findingInformation)
              }
            ]
          }
        ],
        generationConfig: {
          temperature: 0.2,
          maxOutputTokens: 400,
          responseMimeType: "application/json"
        }
      }),
      signal: controller.signal
    });

    if (!response.ok) {
      console.error(
        `Gemini API request failed: ${response.status}`
      );
      return undefined;
    }

    const data = await response.json() as GeminiResponse;

    const generatedText =
      data.candidates?.[0]?.content?.parts
        ?.map((part) => part.text ?? "")
        .join("");

    if (!generatedText) {
      return undefined;
    }

    const parsed: unknown = JSON.parse(generatedText);

    if (!isValidExplanation(parsed)) {
      console.error("Gemini returned an invalid explanation.");
      return undefined;
    }

    explanationCache.set(cacheKey, parsed);

    return parsed;
  } catch (error) {
    console.error("Gemini explanation request failed:", error);
    return undefined;
  } finally {
    clearTimeout(timeout);
  }
}
