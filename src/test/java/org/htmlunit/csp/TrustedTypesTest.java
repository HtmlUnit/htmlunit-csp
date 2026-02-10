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

import org.htmlunit.csp.directive.RequireTrustedTypesForDirective;
import org.htmlunit.csp.directive.TrustedTypesDirective;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author Michael Smith
 */
public class TrustedTypesTest extends TestBase {

    // trusted-types directive tests

    @Test
    public void testTrustedTypesBasic() {
        Policy p;

        // Basic policy name
        p = Policy.parseSerializedCSP("trusted-types myPolicy", ThrowIfPolicyError);
        assertTrue(p.trustedTypes().isPresent());
        TrustedTypesDirective tt = p.trustedTypes().get();
        assertEquals(1, tt.getPolicyNames_().size());
        assertEquals("myPolicy", tt.getPolicyNames_().get(0));
        assertFalse(tt.none());
        assertFalse(tt.allowDuplicates());
        assertFalse(tt.star());

        // Multiple policy names
        p = Policy.parseSerializedCSP("trusted-types one two three", ThrowIfPolicyError);
        tt = p.trustedTypes().get();
        assertEquals(3, tt.getPolicyNames_().size());

        // Wildcard
        p = Policy.parseSerializedCSP("trusted-types *", ThrowIfPolicyError);
        tt = p.trustedTypes().get();
        assertTrue(tt.star());
        assertEquals(0, tt.getPolicyNames_().size());

        // Allow duplicates
        p = Policy.parseSerializedCSP("trusted-types myPolicy 'allow-duplicates'", ThrowIfPolicyError);
        tt = p.trustedTypes().get();
        assertTrue(tt.allowDuplicates());
        assertEquals(1, tt.getPolicyNames_().size());

        // Wildcard with allow-duplicates
        p = Policy.parseSerializedCSP("trusted-types * 'allow-duplicates'", ThrowIfPolicyError);
        tt = p.trustedTypes().get();
        assertTrue(tt.star());
        assertTrue(tt.allowDuplicates());

        // None keyword
        p = Policy.parseSerializedCSP("trusted-types 'none'", ThrowIfPolicyError);
        tt = p.trustedTypes().get();
        assertTrue(tt.none());
        assertEquals(0, tt.getPolicyNames_().size());
    }

    @Test
    public void testTrustedTypesPolicyNameCharacters() {
        Policy p;

        // Policy names can contain various characters per spec:
        // tt-policy-name = 1*( ALPHA / DIGIT / "-" / "#" / "=" / "_" / "/" / "@" / "." / "%" )
        p = Policy.parseSerializedCSP("trusted-types my-policy_name.v1", ThrowIfPolicyError);
        TrustedTypesDirective tt = p.trustedTypes().get();
        assertEquals(1, tt.getPolicyNames_().size());

        p = Policy.parseSerializedCSP("trusted-types policy#1 policy@domain", ThrowIfPolicyError);
        tt = p.trustedTypes().get();
        assertEquals(2, tt.getPolicyNames_().size());

        p = Policy.parseSerializedCSP("trusted-types path/to/policy policy=value", ThrowIfPolicyError);
        tt = p.trustedTypes().get();
        assertEquals(2, tt.getPolicyNames_().size());

        p = Policy.parseSerializedCSP("trusted-types policy%20name", ThrowIfPolicyError);
        tt = p.trustedTypes().get();
        assertEquals(1, tt.getPolicyNames_().size());
    }

    @Test
    public void testTrustedTypesRoundTrips() {
        roundTrips("trusted-types myPolicy");
        roundTrips("trusted-types one two three");
        roundTrips("trusted-types *");
        roundTrips("trusted-types 'none'");
        roundTrips("trusted-types myPolicy 'allow-duplicates'");
        roundTrips("trusted-types * 'allow-duplicates'");
    }

    @Test
    public void testTrustedTypesCaseInsensitiveKeywords() {
        // Keywords are case-insensitive per ABNF
        inTurkey(() -> {
            Policy p;

            p = Policy.parseSerializedCSP("trusted-types 'NONE'", ThrowIfPolicyError);
            assertTrue(p.trustedTypes().get().none());

            p = Policy.parseSerializedCSP("trusted-types 'ALLOW-DUPLICATES'", ThrowIfPolicyError);
            assertTrue(p.trustedTypes().get().allowDuplicates());

            p = Policy.parseSerializedCSP("TRUSTED-TYPES myPolicy", ThrowIfPolicyError);
            assertTrue(p.trustedTypes().isPresent());
        });
    }

    @Test
    public void testTrustedTypesErrors() {
        // 'none' combined with other values
        roundTrips(
                "trusted-types 'none' myPolicy",
                e(Policy.Severity.Error, "'none' must not be combined with any other trusted-types expression", 0, -1)
        );

        roundTrips(
                "trusted-types 'none' *",
                e(Policy.Severity.Error, "'none' must not be combined with any other trusted-types expression", 0, -1)
        );

        roundTrips(
                "trusted-types 'none' 'allow-duplicates'",
                e(Policy.Severity.Error, "'none' must not be combined with any other trusted-types expression", 0, -1)
        );

        // Invalid keyword
        roundTrips(
                "trusted-types 'invalid-keyword'",
                e(Policy.Severity.Error, "Unrecognized trusted-types keyword 'invalid-keyword'", 0, 0)
        );

        // Invalid policy name
        roundTrips(
                "trusted-types policy!name",
                e(Policy.Severity.Error, "Invalid trusted-types policy name policy!name", 0, 0)
        );

        // Duplicate policy name
        roundTrips(
                "trusted-types myPolicy myPolicy",
                e(Policy.Severity.Warning, "Duplicate policy name myPolicy", 0, 1)
        );

        // Different case policy names are NOT duplicates (case-sensitive per browser behavior)
        roundTrips(
                "trusted-types myPolicy MYPOLICY"
        );

        // Duplicate keyword
        roundTrips(
                "trusted-types 'allow-duplicates' 'allow-duplicates'",
                e(Policy.Severity.Warning, "Duplicate keyword 'allow-duplicates'", 0, 1)
        );

        // Duplicate wildcard
        roundTrips(
                "trusted-types * *",
                e(Policy.Severity.Warning, "Duplicate wildcard *", 0, 1)
        );

        // Duplicate directive
        roundTrips(
                "trusted-types one; trusted-types two",
                e(Policy.Severity.Warning, "Duplicate directive trusted-types", 1, -1)
        );
    }

    // require-trusted-types-for directive tests

    @Test
    public void testRequireTrustedTypesForBasic() {
        Policy p;

        p = Policy.parseSerializedCSP("require-trusted-types-for 'script'", ThrowIfPolicyError);
        assertTrue(p.requireTrustedTypesFor().isPresent());
        RequireTrustedTypesForDirective rttf = p.requireTrustedTypesFor().get();
        assertTrue(rttf.script());
    }

    @Test
    public void testRequireTrustedTypesForRoundTrips() {
        roundTrips("require-trusted-types-for 'script'");
    }

    @Test
    public void testRequireTrustedTypesForCaseInsensitive() {
        inTurkey(() -> {
            Policy p;

            p = Policy.parseSerializedCSP("require-trusted-types-for 'SCRIPT'", ThrowIfPolicyError);
            assertTrue(p.requireTrustedTypesFor().get().script());

            p = Policy.parseSerializedCSP("REQUIRE-TRUSTED-TYPES-FOR 'script'", ThrowIfPolicyError);
            assertTrue(p.requireTrustedTypesFor().isPresent());
        });
    }

    @Test
    public void testRequireTrustedTypesForErrors() {
        // Missing value
        roundTrips(
                "require-trusted-types-for",
                e(Policy.Severity.Error, "The require-trusted-types-for directive requires a value", 0, -1)
        );

        // Invalid keyword
        roundTrips(
                "require-trusted-types-for 'invalid'",
                e(Policy.Severity.Error, "Unrecognized require-trusted-types-for keyword 'invalid'", 0, 0)
        );

        // Value without quotes
        roundTrips(
                "require-trusted-types-for script",
                e(Policy.Severity.Error, "Unrecognized require-trusted-types-for value script - keywords must be wrapped in single quotes", 0, 0)
        );

        // Duplicate keyword
        roundTrips(
                "require-trusted-types-for 'script' 'script'",
                e(Policy.Severity.Warning, "Duplicate keyword 'script'", 0, 1)
        );

        // Duplicate directive
        roundTrips(
                "require-trusted-types-for 'script'; require-trusted-types-for 'script'",
                e(Policy.Severity.Warning, "Duplicate directive require-trusted-types-for", 1, -1)
        );
    }

    // Combined tests

    @Test
    public void testTrustedTypesWithRequireTrustedTypesFor() {
        Policy p = Policy.parseSerializedCSP("require-trusted-types-for 'script'; trusted-types myPolicy", ThrowIfPolicyError);
        assertTrue(p.requireTrustedTypesFor().isPresent());
        assertTrue(p.trustedTypes().isPresent());
        assertTrue(p.requireTrustedTypesFor().get().script());
        assertEquals(1, p.trustedTypes().get().getPolicyNames_().size());
    }

    // Manipulation tests

    @Test
    public void testTrustedTypesPolicyNamesCaseSensitive() {
        // Policy names are case-sensitive per browser behavior
        Policy p = Policy.parseSerializedCSP("trusted-types myPolicy MYPOLICY MyPolicy", ThrowIfPolicyError);
        TrustedTypesDirective tt = p.trustedTypes().get();

        // All three should be stored as separate policy names
        assertEquals(3, tt.getPolicyNames_().size());
        assertTrue(tt.getPolicyNames_().contains("myPolicy"));
        assertTrue(tt.getPolicyNames_().contains("MYPOLICY"));
        assertTrue(tt.getPolicyNames_().contains("MyPolicy"));
    }

    @Test
    public void testRequireTrustedTypesForManipulation() {
        Policy p = Policy.parseSerializedCSP("require-trusted-types-for 'script'", ThrowIfPolicyError);
        RequireTrustedTypesForDirective rttf = p.requireTrustedTypesFor().get();

        assertTrue(rttf.script());
        rttf.setScript_(false);
        assertFalse(rttf.script());
        rttf.setScript_(true);
        assertTrue(rttf.script());
    }

    // Helper methods

    private static void roundTrips(String input, PolicyError... errors) {
        serializesTo(input, input, errors);
    }

    private static void serializesTo(String input, String output, PolicyError... errors) {
        ArrayList<PolicyError> observedErrors = new ArrayList<>();
        Policy.PolicyErrorConsumer consumer = (severity, message, directiveIndex, valueIndex) -> {
            observedErrors.add(e(severity, message, directiveIndex, valueIndex));
        };
        Policy policy = Policy.parseSerializedCSP(input, consumer);
        assertEquals(errors.length, observedErrors.size(), "should have the expected number of errors");
        for (int i = 0; i < errors.length; ++i) {
            assertEquals(errors[i], observedErrors.get(i));
        }
        assertEquals(output, policy.toString());
    }
}