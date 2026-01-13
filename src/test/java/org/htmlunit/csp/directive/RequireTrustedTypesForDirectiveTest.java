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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;

class RequireTrustedTypesForDirectiveTest {

    @Test
    void testValidScriptValue() {
        // Given
        List<String> errors = new ArrayList<>();
        // When
        // Valid value: 'script'
        RequireTrustedTypesForDirective directive = new RequireTrustedTypesForDirective(
                List.of("script"), (severity, message, valueIndex) -> errors.add(message));
        // Then
        assertTrue(directive.getValues().contains("script"));
        assertTrue(errors.isEmpty()); // No errors should be reported
    }

    @Test
    void testInvalidValue() {
        List<String> errors = new ArrayList<>();
        // Then
        // Invalid value: 'invalid'
        RequireTrustedTypesForDirective directive = new RequireTrustedTypesForDirective(
                List.of("invalid"), (severity, message, valueIndex) -> errors.add(message));
        // Then
        assertTrue(directive.getValues().contains("invalid"));
        assertEquals(1, errors.size()); // One error should be reported
        assertEquals("`require-trusted-types-for` only accepts 'script' as a value.",
                errors.get(0));
    }
    
    @Test
    void testInvalidValueAmonstMany() {
        // Given
        List<String> errors = new ArrayList<>();
        // When
        // Invalid value: 'invalid'
        RequireTrustedTypesForDirective directive = new RequireTrustedTypesForDirective(
                List.of("script", "invalid"), (severity, message, valueIndex) -> errors.add(message));
        // Then
        assertTrue(directive.getValues().contains("script"));
        assertTrue(directive.getValues().contains("invalid"));
        assertEquals(1, errors.size()); // One error should be reported
        assertEquals("`require-trusted-types-for` only accepts 'script' as a value.",
                errors.get(0));
    }
}