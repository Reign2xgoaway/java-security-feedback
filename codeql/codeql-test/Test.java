import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import javax.crypto.spec.PBEKeySpec;

public class Test {
    // ============================================================
    // GROUP A: PBEKeySpec
    // ============================================================

    // TEST 1: Hard-coded password variable.
    public void pbePasswordVariable() {
        String password = "pbe-password-variable";

        PBEKeySpec spec = new PBEKeySpec(password.toCharArray());
    }

    // TEST 2: Direct hard-coded password literal.
    public void pbeDirectPassword() {
        PBEKeySpec spec = new PBEKeySpec("pbe-direct-password".toCharArray());
    }

    // TEST 3: Password initialized as a char array.
    public void pbeCharArrayInitialisation() {
        char[] password = {'p', 'b', 'e', '-', 'p', 'a', 's', 's'};

        PBEKeySpec spec = new PBEKeySpec(password);
    }

    // TEST 4: Hard-coded password passed through a helper method.
    public void pbePasswordHelperMethod() {
        String password = "pbe-password-helper-method";

        createPbeKeySpec(password);
    }

    private PBEKeySpec createPbeKeySpec(String password) {
        return new PBEKeySpec(password.toCharArray());
    }

    // TEST 5: Hard-coded password passed through another class.
    public void pbePasswordClass() {
        String password = "pbe-password-through-class";

        PbePasswordHelper.create(password);
    }

    static class PbePasswordHelper {
        public static PBEKeySpec create(String password) {
            return new PBEKeySpec(password.toCharArray());
        }
    }

    // TEST 6: Password loaded from an environment variable.
    public void pbeEnvironmentPassword() {
        String password = System.getenv("PBE_PASSWORD");

        PBEKeySpec spec = new PBEKeySpec(password.toCharArray());
    }

    // ============================================================
    // GROUP B: KeyStore.load()
    // ============================================================

    // TEST 7: Hard-coded password variable.
    public void keyStoreLoadPasswordVariable() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        String password = "keystore-load-password-variable";

        keyStore.load(
            new ByteArrayInputStream(new byte[0]),
            password.toCharArray()
        );
    }

    // TEST 8: Direct hard-coded password literal.
    public void keyStoreLoadDirectPassword() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");

        keyStore.load(
            new ByteArrayInputStream(new byte[0]),
            "keystore-load-direct-password".toCharArray()
        );
    }

    // TEST 9: Password initialized as a char array.
    public void keyStoreLoadCharArrayInitialisation() throws Exception {
        char[] password = {'k', 'e', 'y', '-', 's', 't', 'o', 'r', 'e'};
        KeyStore keyStore = KeyStore.getInstance("JKS");

        keyStore.load(
            new ByteArrayInputStream(new byte[0]),
            password
        );
    }

    // TEST 10: Hard-coded password passed through a helper method.
    public void keyStoreLoadHelperMethod() throws Exception {
        String password = "keystore-load-password-helper-method";

        loadKeyStore(password);
    }

    private void loadKeyStore(String password) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");

        keyStore.load(
            new ByteArrayInputStream(new byte[0]),
            password.toCharArray()
        );
    }

    // TEST 11: Hard-coded password passed through another class.
    public void keyStoreLoadThroughAnotherClass() throws Exception {
        String password = "keystore-load-password-through-class";

        KeyStorePasswordHelper.load(password);
    }

    static class KeyStorePasswordHelper {
        public static void load(String password) throws Exception {
            KeyStore keyStore = KeyStore.getInstance("JKS");

            keyStore.load(
                new ByteArrayInputStream(new byte[0]),
                password.toCharArray()
            );
        }
    }

    // TEST 12: Password loaded from an environment variable.
    public void keyStoreLoadEnvironmentPassword() throws Exception {
        String password = System.getenv("KEYSTORE_PASSWORD");
        KeyStore keyStore = KeyStore.getInstance("JKS");

        keyStore.load(
            new ByteArrayInputStream(new byte[0]),
            password.toCharArray()
        );
    }
}
