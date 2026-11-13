export interface ApiExampleFix {
  exampleCode: string;
}

export interface ApiDocumentation {
  documentationUrl: string;
  documentationLabel: string;
}

// Curated Java remediation examples.
// These are illustrative patterns, not automatic replacements
// for the developer's existing code.
const apiExamples: Record<string, ApiExampleFix> = {
  "javax.crypto.spec.PBEKeySpec": {
    exampleCode: `import java.util.Arrays;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

// Retrieve the password from a secure secrets manager.
char[] password =
    secretStore.getPassword("application-password");

// Use a unique, securely generated salt.
byte[] salt = loadOrGenerateSalt();

PBEKeySpec spec = new PBEKeySpec(
    password,
    salt,
    iterationCount,
    keyLength
);

try {
    SecretKeyFactory factory =
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

    byte[] derivedKey =
        factory.generateSecret(spec).getEncoded();

    // Use the derived key in your cryptographic operation.
} finally {
    spec.clearPassword();
    Arrays.fill(password, '\\0');
}`
  },

  "java.security.KeyStore.load()": {
    exampleCode: `import java.io.InputStream;
import java.security.KeyStore;
import java.util.Arrays;

// Retrieve the keystore password securely.
char[] password =
    secretStore.getPassword("keystore-password");

KeyStore keyStore = KeyStore.getInstance("PKCS12");

try (InputStream inputStream = openKeyStoreFile()) {
    keyStore.load(inputStream, password);

    // Use the loaded keystore.
} finally {
    Arrays.fill(password, '\\0');
}`
  }
};

// Official Oracle Java documentation.
// Documentation is independent of example availability.
const apiDocumentation: Record<string, ApiDocumentation> = {
  "javax.crypto.spec.PBEKeySpec": {
    documentationUrl:
      "https://docs.oracle.com/en/java/javase/26/docs/api/java.base/javax/crypto/spec/PBEKeySpec.html",
    documentationLabel: "Oracle Java PBEKeySpec Documentation"
  },

  "java.security.KeyStore.load()": {
    documentationUrl:
      "https://docs.oracle.com/en/java/javase/26/docs/api/java.base/java/security/KeyStore.html",
    documentationLabel: "Oracle Java KeyStore Documentation"
  }
};

export function getApiExampleFix(
  affectedApi: string
): ApiExampleFix | undefined {
  return apiExamples[affectedApi.trim()];
}

export function getApiDocumentation(
  affectedApi: string
): ApiDocumentation | undefined {
  return apiDocumentation[affectedApi.trim()];
}
