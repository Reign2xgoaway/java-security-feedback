/**
 * @name Hard-coded password passed to Java security APIs
 * @description Detects hard-coded strings flowing into password
 *              arguments of PBEKeySpec and KeyStore.load().
 * @kind problem
 * @id java/hardcoded-password-security-api
 * @problem.severity warning
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

module HardcodedPasswordConfig implements DataFlow::ConfigSig {

    /**
     * Identifies non-empty hard-coded string literals.
     */
    predicate isSource(DataFlow::Node source) {
        exists(StringLiteral literal |
            source.asExpr() = literal and
            literal.getValue().length() > 0
        )
    }

    /**
     * Identifies password arguments in the two selected APIs.
     */
    predicate isSink(DataFlow::Node sink) {

        // PBEKeySpec(char[] password, ...)
        exists(ClassInstanceExpr constructor |
            constructor.getConstructor().getDeclaringType()
                .hasQualifiedName("javax.crypto.spec", "PBEKeySpec") and
            sink.asExpr() = constructor.getArgument(0)
        )
        or

        // KeyStore.load(InputStream, char[] password)
        exists(MethodCall call |
            call.getMethod().hasQualifiedName(
                "java.security", "KeyStore", "load"
            ) and
            sink.asExpr() = call.getArgument(1)
        )
    }
}

module HardcodedPasswordFlow =
    TaintTracking::Global<HardcodedPasswordConfig>;

/**
 * Returns the Java security API associated with the finding.
 */
string getAffectedApi(DataFlow::Node sink) {

    // javax.crypto.spec.PBEKeySpec
    exists(ClassInstanceExpr constructor |
        constructor.getConstructor().getDeclaringType()
            .hasQualifiedName("javax.crypto.spec", "PBEKeySpec") and
        sink.asExpr() = constructor.getArgument(0) and
        result = "javax.crypto.spec.PBEKeySpec"
    )
    or

    // java.security.KeyStore.load()
    exists(MethodCall call |
        call.getMethod().hasQualifiedName(
            "java.security", "KeyStore", "load"
        ) and
        sink.asExpr() = call.getArgument(1) and
        result = "java.security.KeyStore.load()"
    )
}

/**
 * Reports hard-coded password flows and includes the affected API
 * in the SARIF message for the extension to display.
 */
from DataFlow::Node source, DataFlow::Node sink
where HardcodedPasswordFlow::flow(source, sink)
select sink.asExpr(),
    "Hard-coded password detected. Affected API: " +
    getAffectedApi(sink)
