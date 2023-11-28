/*
 * Copyright (c) 2023 Ronald Brill.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
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
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;

public class LowLevelPolicyManipulationTest extends TestBase {
    @Test
    public void testAdd() {
        final Policy p;

        // Basic ability to add directives
        p = Policy.parseSerializedCSP("", throwIfPolicyError);
        assertFalse(p.getFetchDirective(FetchDirectiveKind.DefaultSrc).isPresent());
        add(
                p,
                "default-src",
                Arrays.asList("'self'")
        );
        assertTrue(p.getFetchDirective(FetchDirectiveKind.DefaultSrc).isPresent());
        assertTrue(p.getFetchDirective(FetchDirectiveKind.DefaultSrc).get().self());
        assertFalse(p.getFetchDirective(FetchDirectiveKind.DefaultSrc).get().unsafeInline());
        assertEquals("default-src 'self'", p.toString());

        // Supports adding duplicates
        add(
                p,
                "default-src",
                Arrays.asList("'unsafe-inline'"),
                e(Policy.Severity.Warning, "Duplicate directive default-src", -1)
        );
        assertTrue(p.getFetchDirective(FetchDirectiveKind.DefaultSrc).isPresent());
        assertTrue(p.getFetchDirective(FetchDirectiveKind.DefaultSrc).get().self());
        assertFalse(p.getFetchDirective(FetchDirectiveKind.DefaultSrc).get().unsafeInline());
        assertEquals("default-src 'self'; default-src 'unsafe-inline'", p.toString());

        // Supports adding directives with odd casing
        assertFalse(p.getFetchDirective(FetchDirectiveKind.ScriptSrc).isPresent());
        inTurkey(() -> {
            add(
                    p,
                    "SCRIPT-SRC",
                    Arrays.asList("'STRICT-DYNAMIC'")
            );
        });
        assertTrue(p.getFetchDirective(FetchDirectiveKind.ScriptSrc).isPresent());
        assertTrue(p.getFetchDirective(FetchDirectiveKind.ScriptSrc).get().strictDynamic());
        assertEquals("default-src 'self'; default-src 'unsafe-inline'; SCRIPT-SRC 'STRICT-DYNAMIC'", p.toString());

        // Supports adding unknown directives
        add(
                p,
                "not-a-directive",
                Arrays.asList(),
                e(Policy.Severity.Warning, "Unrecognized directive not-a-directive", -1)
        );
        assertEquals("default-src 'self'; default-src 'unsafe-inline'; SCRIPT-SRC 'STRICT-DYNAMIC'; not-a-directive", p.toString());

        // Supports adding directives with unreasonable values
        add(
                p,
                "sandbox",
                Arrays.asList("allow-nonsense"),
                e(Policy.Severity.Error, "Unrecognized sandbox keyword allow-nonsense", 0)
        );
        assertEquals("default-src 'self'; default-src 'unsafe-inline'; SCRIPT-SRC 'STRICT-DYNAMIC'; not-a-directive; sandbox allow-nonsense", p.toString());

        // TODO tests for invalid inputs
    }

    @Test
    public void testRemove() {
        Policy p;

        p = Policy.parseSerializedCSP("default-src a; script-src b; img-src c", throwIfPolicyError);
        assertTrue(p.getFetchDirective(FetchDirectiveKind.DefaultSrc).isPresent());
        assertTrue(p.getFetchDirective(FetchDirectiveKind.ScriptSrc).isPresent());
        assertTrue(p.getFetchDirective(FetchDirectiveKind.ImgSrc).isPresent());

        // Basic ability to remove things
        assertTrue(p.remove("script-src"));
        assertTrue(p.getFetchDirective(FetchDirectiveKind.DefaultSrc).isPresent());
        assertFalse(p.getFetchDirective(FetchDirectiveKind.ScriptSrc).isPresent());
        assertTrue(p.getFetchDirective(FetchDirectiveKind.ImgSrc).isPresent());
        assertEquals("default-src a; img-src c", p.toString());

        assertTrue(p.remove("default-src"));
        assertFalse(p.getFetchDirective(FetchDirectiveKind.DefaultSrc).isPresent());
        assertFalse(p.getFetchDirective(FetchDirectiveKind.ScriptSrc).isPresent());
        assertTrue(p.getFetchDirective(FetchDirectiveKind.ImgSrc).isPresent());
        assertEquals("img-src c", p.toString());

        // Removes all copies
        p = Policy.parseSerializedCSP("default-src a; script-src b; img-src c; script-src d", Policy.PolicyErrorConsumer.ignored);
        assertTrue(p.getFetchDirective(FetchDirectiveKind.DefaultSrc).isPresent());
        assertTrue(p.getFetchDirective(FetchDirectiveKind.ScriptSrc).isPresent());
        assertTrue(p.getFetchDirective(FetchDirectiveKind.ImgSrc).isPresent());
        assertEquals("default-src a; script-src b; img-src c; script-src d", p.toString());

        assertTrue(p.remove("script-src"));
        assertTrue(p.getFetchDirective(FetchDirectiveKind.DefaultSrc).isPresent());
        assertFalse(p.getFetchDirective(FetchDirectiveKind.ScriptSrc).isPresent());
        assertTrue(p.getFetchDirective(FetchDirectiveKind.ImgSrc).isPresent());
        assertEquals("default-src a; img-src c", p.toString());

        // Removing is case-insensitive
        inTurkey(() -> {
            Policy p2 = Policy.parseSerializedCSP("scrIPT-src a", Policy.PolicyErrorConsumer.ignored);
            assertTrue(p2.getFetchDirective(FetchDirectiveKind.ScriptSrc).isPresent());

            assertTrue(p2.remove("SCRipt-SRC"));
            assertFalse(p2.getFetchDirective(FetchDirectiveKind.ScriptSrc).isPresent());
            assertEquals("", p2.toString());

            p2 = Policy.parseSerializedCSP("script-src a", Policy.PolicyErrorConsumer.ignored);
            assertTrue(p2.getFetchDirective(FetchDirectiveKind.ScriptSrc).isPresent());

            assertTrue(p2.remove("SCRIPT-SRC"));
            assertFalse(p2.getFetchDirective(FetchDirectiveKind.ScriptSrc).isPresent());
            assertEquals("", p2.toString());
        });

        // Returns false if nothing is removed
        p = Policy.parseSerializedCSP("default-src a; script-src b; img-src c", throwIfPolicyError);
        assertFalse(p.remove("font-src"));
        assertFalse(p.remove("not-a-directive"));
        assertEquals("default-src a; script-src b; img-src c", p.toString());

        // Can remove nonsense directives
        p = Policy.parseSerializedCSP("default-src a; not-a-directive b", Policy.PolicyErrorConsumer.ignored);
        assertTrue(p.remove("not-a-directive"));
        assertEquals("default-src a", p.toString());

        // Every kind of directive is removable
        p = Policy.parseSerializedCSP("base-uri 'self'", throwIfPolicyError);
        assertTrue(p.baseUri().isPresent());
        assertTrue(p.remove("base-uri"));
        assertFalse(p.remove("base-uri"));
        assertFalse(p.baseUri().isPresent());
        assertEquals("", p.toString());

        p = Policy.parseSerializedCSP("block-all-mixed-content", throwIfPolicyError);
        assertTrue(p.blockAllMixedContent());
        assertTrue(p.remove("block-all-mixed-content"));
        assertFalse(p.remove("block-all-mixed-content"));
        assertFalse(p.blockAllMixedContent());
        assertEquals("", p.toString());

        p = Policy.parseSerializedCSP("form-action 'self'", throwIfPolicyError);
        assertTrue(p.formAction().isPresent());
        assertTrue(p.remove("form-action"));
        assertFalse(p.remove("form-action"));
        assertFalse(p.formAction().isPresent());
        assertEquals("", p.toString());

        p = Policy.parseSerializedCSP("frame-ancestors 'self'", throwIfPolicyError);
        assertTrue(p.frameAncestors().isPresent());
        assertTrue(p.remove("frame-ancestors"));
        assertFalse(p.remove("frame-ancestors"));
        assertFalse(p.frameAncestors().isPresent());
        assertEquals("", p.toString());

        p = Policy.parseSerializedCSP("navigate-to 'self'", throwIfPolicyError);
        assertTrue(p.navigateTo().isPresent());
        assertTrue(p.remove("navigate-to"));
        assertFalse(p.remove("navigate-to"));
        assertFalse(p.navigateTo().isPresent());
        assertEquals("", p.toString());

        p = Policy.parseSerializedCSP("plugin-types a/b", throwIfPolicyError);
        assertTrue(p.pluginTypes().isPresent());
        assertTrue(p.remove("plugin-types"));
        assertFalse(p.remove("plugin-types"));
        assertFalse(p.pluginTypes().isPresent());
        assertEquals("", p.toString());

        p = Policy.parseSerializedCSP("report-to 'self'", throwIfPolicyError);
        assertTrue(p.reportTo().isPresent());
        assertTrue(p.remove("report-to"));
        assertFalse(p.remove("report-to"));
        assertFalse(p.reportTo().isPresent());
        assertEquals("", p.toString());

        p = Policy.parseSerializedCSP("report-uri 'self'", Policy.PolicyErrorConsumer.ignored);
        assertTrue(p.reportUri().isPresent());
        assertTrue(p.remove("report-uri"));
        assertFalse(p.remove("report-uri"));
        assertFalse(p.reportUri().isPresent());
        assertEquals("", p.toString());

        p = Policy.parseSerializedCSP("sandbox allow-downloads", throwIfPolicyError);
        assertTrue(p.sandbox().isPresent());
        assertTrue(p.remove("sandbox"));
        assertFalse(p.remove("sandbox"));
        assertFalse(p.sandbox().isPresent());
        assertEquals("", p.toString());

        p = Policy.parseSerializedCSP("upgrade-insecure-requests", throwIfPolicyError);
        assertTrue(p.upgradeInsecureRequests());
        assertTrue(p.remove("upgrade-insecure-requests"));
        assertFalse(p.remove("upgrade-insecure-requests"));
        assertFalse(p.upgradeInsecureRequests());
        assertEquals("", p.toString());
    }

    @Test
    public void testAddAssertsNonemptyNames() {
        assertThrows(IllegalArgumentException.class, () -> {
            final Policy p = Policy.parseSerializedCSP("", throwIfPolicyError);
            p.add("", Collections.emptyList(), Directive.DirectiveErrorConsumer.ignored);
        });
    }

    @Test
    public void testAddAssertsAsciiInNames() {
        assertThrows(IllegalArgumentException.class, () -> {
            final Policy p = Policy.parseSerializedCSP("", throwIfPolicyError);
            p.add("é", Collections.emptyList(), Directive.DirectiveErrorConsumer.ignored);
        });
    }

    @Test
    public void testAddAssertsNoCommasInNames() {
        assertThrows(IllegalArgumentException.class, () -> {
            final Policy p = Policy.parseSerializedCSP("", throwIfPolicyError);
            p.add(",", Collections.emptyList(), Directive.DirectiveErrorConsumer.ignored);
        });
    }

    @Test
    public void testAddAssertsNoSemisInNames() {
        assertThrows(IllegalArgumentException.class, () -> {
            final Policy p = Policy.parseSerializedCSP("", throwIfPolicyError);
            p.add(";", Collections.emptyList(), Directive.DirectiveErrorConsumer.ignored);
        });
    }

    @Test
    public void testAddAssertsNonemptyValues() {
        assertThrows(IllegalArgumentException.class, () -> {
            final Policy p = Policy.parseSerializedCSP("", throwIfPolicyError);
            p.add("default-src", Collections.singletonList(""), Directive.DirectiveErrorConsumer.ignored);
        });
    }

    @Test
    public void testAddAssertsAsciiInValues() {
        assertThrows(IllegalArgumentException.class, () -> {
            final Policy p = Policy.parseSerializedCSP("", throwIfPolicyError);
            p.add("default-src", Collections.singletonList("é"), Directive.DirectiveErrorConsumer.ignored);
        });
    }

    @Test
    public void testAddAssertsNoCommasInValues() {
        assertThrows(IllegalArgumentException.class, () -> {
            final Policy p = Policy.parseSerializedCSP("", throwIfPolicyError);
            p.add("default-src", Collections.singletonList(","), Directive.DirectiveErrorConsumer.ignored);
        });
    }

    @Test
    public void testAddAssertsNoSemisInValues() {
        assertThrows(IllegalArgumentException.class, () -> {
            final Policy p = Policy.parseSerializedCSP("", throwIfPolicyError);
            p.add("default-src", Collections.singletonList(";"), Directive.DirectiveErrorConsumer.ignored);
        });
    }

    private static void add(final Policy p, final String name, final List<String> values, final DirectiveError... errors) {
        final ArrayList<DirectiveError> observedErrors = new ArrayList<>();
        final Directive.DirectiveErrorConsumer consumer = (severity, message, valueIndex) -> {
            observedErrors.add(e(severity, message, valueIndex));
        };
        p.add(name, values, consumer);
        assertEquals(errors.length, observedErrors.size());
        for (int i = 0; i < errors.length; ++i) {
            assertEquals(errors[i], observedErrors.get(i));
        }
    }

}
