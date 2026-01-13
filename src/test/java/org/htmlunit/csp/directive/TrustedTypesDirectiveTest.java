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

package org.htmlunit.csp.directive;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

class TrustedTypesDirectiveTest {

    private List<String> errors;

    @BeforeEach
    void setup() {
        this.errors = new ArrayList<>();
    }

    @Test
    void testWildcardAllowed() {
        // Given / When
        // Wildcard policy
        new TrustedTypesDirective(List.of("*"),
                (severity, message, valueIndex) -> errors.add(message));
        // Then
        assertTrue(errors.isEmpty());
    }

    @Test
    void testEmptyPolicyNameError() {
        // Given / When // Then
        // Whitespace-only policy name
        assertThrows(IllegalArgumentException.class,
                () -> new TrustedTypesDirective(List.of("policy1", " "),
                        (severity, message, valueIndex) -> errors.add(message)));
    }

    @Test
    void testSimplePolicy() {
        // Given / When
        // Ex: trusted-types myPolicy default;
        new TrustedTypesDirective(List.of("mypolicy", "default"),
                (severity, message, valueIndex) -> errors.add(message));
        // Then
        assertTrue(errors.isEmpty());
    }

    @Test
    void testAllowDuplicatesKeyword() {
        // Given / When
        TrustedTypesDirective directive = new TrustedTypesDirective(List.of("'allow-duplicates'"),
                (severity, message, valueIndex) -> errors.add(message));
        // Then
        assertTrue(directive.isAllowDuplicates());
        assertFalse(directive.isAllowAnyPolicyName());
        assertTrue(directive.getAllowedPolicyNames().isEmpty());
        assertTrue(errors.isEmpty());
    }

    @Test
    void testNoneKeywordAlone() {
        // Given / When
        TrustedTypesDirective directive = new TrustedTypesDirective(List.of("'none'"),
                (severity, message, valueIndex) -> errors.add(message));
        // Then
        assertFalse(directive.isAllowAnyPolicyName());
        assertFalse(directive.isAllowDuplicates());
        assertTrue(directive.getAllowedPolicyNames().isEmpty());
        assertTrue(errors.isEmpty());
    }

    @Test
    void testNoneKeywordMixedWithPolicies() {
        // Given / When
        TrustedTypesDirective directive = new TrustedTypesDirective(List.of("'none'", "my-policy"),
                (severity, message, valueIndex) -> errors.add(message));
        // Then
        assertFalse(directive.isAllowAnyPolicyName());
        assertFalse(directive.isAllowDuplicates());
        assertEquals(Set.of("my-policy"), directive.getAllowedPolicyNames());
        assertEquals("Specifying trusted-types 'none' along with other values is invalid",
                errors.get(0));
    }

    @Test
    void testValidPolicyNames() {
        // Given / When
        TrustedTypesDirective directive = new TrustedTypesDirective(
                List.of("policy1", "policy-2_@.%", "#=/"),
                (severity, message, valueIndex) -> errors.add(message));
        // Then
        assertEquals(Set.of("policy1", "policy-2_@.%", "#=/"), directive.getAllowedPolicyNames());
        assertTrue(errors.isEmpty());
    }

    @Test
    void testCaseSensitivity() {
        // Given / When
        TrustedTypesDirective directive = new TrustedTypesDirective(
                List.of("Policy", "policy", "'Allow-Duplicates'"),
                (severity, message, valueIndex) -> errors.add(message));
        // Then
        // Policy names case-sensitive (both added separately)
        assertEquals(Set.of("Policy", "policy"), directive.getAllowedPolicyNames());
        // Keywords case-insensitive for inner content
        assertTrue(directive.isAllowDuplicates());
        assertTrue(errors.isEmpty());
    }

    @Test
    void testUnknownKeyword() {
        // Given / When
        new TrustedTypesDirective(List.of("'unknown'"),
                (severity, message, valueIndex) -> errors.add(message));
        // Then
        assertTrue(errors.size() == 1 && errors.get(0).contains("Unknown keyword"));
    }

    @Test
    void testMixedAll() {
        // Given / When
        TrustedTypesDirective directive = new TrustedTypesDirective(
                List.of("*", "'allow-duplicates'", "policy1", "'none'", "invalid!"),
                (severity, message, valueIndex) -> errors.add(message));
        // Then
        assertTrue(directive.isAllowAnyPolicyName());
        assertTrue(directive.isAllowDuplicates());
        assertEquals(Set.of("policy1"), directive.getAllowedPolicyNames());
        assertEquals(2, errors.size());
        assertTrue(errors
                .contains("Specifying trusted-types 'none' along with other values is invalid"));
        assertTrue(errors.contains(
                "Invalid policy name in trusted-types: invalid! (must be alphanumeric or -#=_/@.%)"));
    }

    @Test
    void testDuplicatesWhenNotAllowed() {
        // Given / When
        new TrustedTypesDirective(List.of("mypolicy", "mypolicy"),
                (severity, message, valueIndex) -> errors.add(message));
        // Then
        assertFalse(errors.isEmpty());
        assertEquals(errors.get(0), "Second attempt to add trusted-types policy: mypolicy");
    }
}
