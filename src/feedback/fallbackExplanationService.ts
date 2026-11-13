import { SecurityExplanation } from "../models/securityExplanation";
import { SecurityFinding } from "../models/securityFinding";

export function getFallbackExplanation(
  finding: SecurityFinding
): SecurityExplanation {
  return {
    whyItMatters:
      "A hard-coded password can be exposed to anyone who can access the source code, repository, or compiled application. This may allow unauthorised access to protected data or cryptographic operations.",

    suggestedAction: [
      "Avoid storing passwords or other sensitive credentials directly in source code.",
      "Retrieve passwords from a secure configuration source or secrets manager.",
      "Use secure credential management and restrict access to stored secrets."
    ]
  };
}
