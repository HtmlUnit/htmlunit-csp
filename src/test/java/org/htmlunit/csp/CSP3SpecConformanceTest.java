/*
 * Copyright (c) 2023-2026 Ronald Brill.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.htmlunit.csp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;

import org.junit.jupiter.api.Test;

/**
 * Tests that demonstrate differences between the htmlunit-csp implementation
 * and the CSP3 specification at https://www.w3.org/TR/CSP3/#framework
 *
 * Each test documents a specific spec section and how the implementation diverges.
 */
public class CSP3SpecConformanceTest {

    // -----------------------------------------------------------------------
    // Difference 1: parseSerializedCSP rejects commas (spec does not)
    // -----------------------------------------------------------------------

    /**
     * CSP3 §6.6.2: parse a serialized CSP strictly-splits on ";".
     * Commas are NOT mentioned as special characters in this algorithm.
     * The implementation throws IllegalArgumentException for commas,
     * which is not per spec (the code itself acknowledges this).
     */
    @Test
    public void parseSerializedCSPRejectsCommas() {
        // Per spec, this should not throw — it should parse and produce
        // a directive set where one of the values contains a comma
        // (which would be an error in the value, not a thrown exception).
        assertThrows(IllegalArgumentException.class, () ->
            Policy.parseSerializedCSP(
                "default-src 'self', script-src 'none'",
                Policy.PolicyErrorConsumer.ignored)
        );
        // PASSES — proves the implementation deviates by throwing
    }

    // -----------------------------------------------------------------------
    // Difference 2: Duplicate directives still have their values processed
    // -----------------------------------------------------------------------

    /**
     * CSP3 §6.6.2 step 2.5: If the policy's directive set already contains
     * a directive whose name matches, the spec says to "continue" — skipping
     * the duplicate entirely without processing its values.
     *
     * The implementation still parses the duplicate's values and reports
     * errors from them.
     */
    @Test
    public void duplicateDirectiveValuesAreStillProcessed() {
        final ArrayList<String> messages = new ArrayList<>();
        final Policy.PolicyErrorConsumer consumer =
            (severity, message, directiveIndex, valueIndex) -> messages.add(message);

        // First occurrence is valid; second is a duplicate with an invalid value.
        Policy.parseSerializedCSP(
            "default-src 'self'; default-src 'not-a-keyword'", consumer);

        // The duplicate warning should be present
        assertTrue(messages.stream().anyMatch(m -> m.contains("Duplicate directive")),
            "Should warn about duplicate directive");

        // Per spec, the second directive should be skipped entirely, so
        // "Unrecognized source-expression 'not-a-keyword'" should NOT appear.
        // But the implementation does report it.
        boolean hasUnrecognizedError = messages.stream()
            .anyMatch(m -> m.contains("Unrecognized source-expression"));
        assertTrue(hasUnrecognizedError,
            "Implementation processes duplicate directive values (spec says skip them)");
    }

    // -----------------------------------------------------------------------
    // Difference 3: "referrer" directive discards its values
    // -----------------------------------------------------------------------

    /**
     * CSP3 §6.6.2: Unrecognized directives should still preserve their values.
     * The "referrer" directive is not in CSP3 (deprecated). Its values should
     * be kept for round-tripping, but the implementation drops them.
     */
    @Test
    public void referrerDirectiveDiscardsValues() {
        final Policy policy = Policy.parseSerializedCSP(
            "referrer no-referrer",
            Policy.PolicyErrorConsumer.ignored);

        // Per spec, values should be preserved: "referrer no-referrer"
        // Implementation discards them: "referrer"
        assertEquals("referrer", policy.toString(),
            "Values of referrer directive are discarded (spec says preserve)");
    }

    // -----------------------------------------------------------------------
    // Difference 4: Non-ASCII input throws instead of parsing gracefully
    // -----------------------------------------------------------------------

    /**
     * CSP3 §6.6.2: "A serialized CSP is an ASCII string" defines the type,
     * but does not specify throwing on non-ASCII. Browsers typically treat
     * non-ASCII policies as empty. The implementation throws.
     */
    @Test
    public void nonAsciiInputThrows() {
        assertThrows(IllegalArgumentException.class, () ->
            Policy.parseSerializedCSP(
                "default-src 'self' üñîçödé",
                Policy.PolicyErrorConsumer.ignored)
        );
        // PASSES — implementation throws on non-ASCII
    }

    // -----------------------------------------------------------------------
    // Difference 5: Policy list index counts skipped empty policies
    // -----------------------------------------------------------------------

    /**
     * When parseSerializedCSPList skips empty policies, the error indices
     * still count them, so error policyIndex doesn't match the position
     * in the resulting PolicyList.
     */
    @Test
    public void policyListIndexCountsSkippedEmptyPolicies() {
        final ArrayList<int[]> errorIndices = new ArrayList<>();
        final Policy.PolicyListErrorConsumer consumer =
            (severity, message, policyIndex, directiveIndex, valueIndex) ->
                errorIndices.add(new int[]{policyIndex, directiveIndex, valueIndex});

        // The leading comma creates an empty first policy
        final PolicyList list = Policy.parseSerializedCSPList(
            ", default-src 'not-a-keyword'", consumer);

        // Only one policy in the resulting list
        assertEquals(1, list.policies_().size());

        // But errors are reported at policyIndex=1 (not 0)
        assertFalse(errorIndices.isEmpty(), "Should have at least one error");
        assertEquals(1, errorIndices.get(0)[0],
            "Error policyIndex is 1 — counts the skipped empty policy");
    }

    // -----------------------------------------------------------------------
    // Difference 6: block-all-mixed-content inconsistent duplicate handling
    // -----------------------------------------------------------------------

    /**
     * For block-all-mixed-content, when a duplicate has values, the "does not
     * support values" error is NOT reported (because the duplicate branch
     * just sets wasDupe=true without checking values). Other directives
     * DO process values of their duplicates.
     */
    @Test
    public void blockAllMixedContentDuplicateSkipsValueCheck() {
        final ArrayList<String> messages = new ArrayList<>();
        final Policy.PolicyErrorConsumer consumer =
            (severity, message, directiveIndex, valueIndex) -> messages.add(message);

        Policy.parseSerializedCSP(
            "block-all-mixed-content; block-all-mixed-content 'none'", consumer);

        assertTrue(messages.contains("Duplicate directive block-all-mixed-content"));
        // The "does not support values" error is NOT emitted for the duplicate
        assertFalse(messages.stream().anyMatch(m -> m.contains("does not support values")),
            "block-all-mixed-content duplicate with values does NOT report value error");
    }
}