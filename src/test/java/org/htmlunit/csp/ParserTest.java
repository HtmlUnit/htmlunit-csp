/*
 * Copyright (c) 2023-2025 Ronald Brill.
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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;

import org.htmlunit.csp.Policy.PolicyErrorConsumer;
import org.htmlunit.csp.value.Scheme;
import org.junit.jupiter.api.Test;

public class ParserTest extends TestBase {
    @Test
    public void emptyPolicy() {
        roundTrips("");
        serializesTo(";", "");

        final PolicyList p = Policy.parseSerializedCSPList("", ThrowIfPolicyListError);
        assertEquals("", p.toString());
    }

    @Test
    public void list() {
        PolicyList p = Policy.parseSerializedCSPList("DEFAULT-SRC 'NONE', default-src 'none'", ThrowIfPolicyListError);
        assertEquals("DEFAULT-SRC 'NONE', default-src 'none'", p.toString());

        final ArrayList<PolicyListError> observedErrors = new ArrayList<>();
        final Policy.PolicyListErrorConsumer consumer = (severity, message, policyIndex, directiveIndex, valueIndex) -> {
            observedErrors.add(e(severity, message, policyIndex, directiveIndex, valueIndex));
        };
        p = Policy.parseSerializedCSPList("default-src 'none', default-src 'not-a-keyword'; script-src asdf asdf", consumer);
        assertEquals("default-src 'none', default-src 'not-a-keyword'; script-src asdf asdf", p.toString());

        final PolicyListError[] errors = {
                e(Policy.Severity.Error, "Unrecognized source-expression 'not-a-keyword'", 1, 0, 0),
                e(Policy.Severity.Warning, "Duplicate host asdf", 1, 1, 1)
        };
        assertEquals(errors.length, observedErrors.size());
        for (int i = 0; i < errors.length; ++i) {
            assertEquals(errors[i], observedErrors.get(i));
        }
    }

    @Test
    void referrerDirectiveShouldWarn() {
        serializesTo(
                "referrer no-referrer", "referrer",
                e(Policy.Severity.Warning, "The referrer directive has been deprecated in favor of the Referrer-Policy header", 0, -1)
        );
    }

    @Test
    public void simpleCases() {
        Policy p;

        p = Policy.parseSerializedCSP("base-uri a", ThrowIfPolicyError);
        assertTrue(p.baseUri().isPresent());

        p = Policy.parseSerializedCSP("block-all-mixed-content", ThrowIfPolicyError);
        assertTrue(p.blockAllMixedContent());

        p = Policy.parseSerializedCSP("form-action a", ThrowIfPolicyError);
        assertTrue(p.formAction().isPresent());

        p = Policy.parseSerializedCSP("frame-ancestors 'none'", ThrowIfPolicyError);
        assertTrue(p.frameAncestors().isPresent());

        p = Policy.parseSerializedCSP("navigate-to 'none'", ThrowIfPolicyError);
        assertTrue(p.navigateTo().isPresent());

        p = Policy.parseSerializedCSP("plugin-types a/b", PolicyErrorConsumer.ignored);
        assertTrue(p.pluginTypes().isPresent());

        p = Policy.parseSerializedCSP("report-to a", ThrowIfPolicyError);
        assertTrue(p.reportTo().isPresent());

        p = Policy.parseSerializedCSP("report-uri http://example.com", Policy.PolicyErrorConsumer.ignored);
        assertTrue(p.reportUri().isPresent());

        p = Policy.parseSerializedCSP("sandbox", ThrowIfPolicyError);
        assertTrue(p.sandbox().isPresent());

        p = Policy.parseSerializedCSP("upgrade-insecure-requests", ThrowIfPolicyError);
        assertTrue(p.upgradeInsecureRequests());

        p = Policy.parseSerializedCSP("child-src a", ThrowIfPolicyError);
        assertTrue(p.getFetchDirective(FetchDirectiveKind.ChildSrc).isPresent());

        p = Policy.parseSerializedCSP("connect-src a", ThrowIfPolicyError);
        assertTrue(p.getFetchDirective(FetchDirectiveKind.ConnectSrc).isPresent());

        p = Policy.parseSerializedCSP("default-src a", ThrowIfPolicyError);
        assertTrue(p.getFetchDirective(FetchDirectiveKind.DefaultSrc).isPresent());

        p = Policy.parseSerializedCSP("font-src a", ThrowIfPolicyError);
        assertTrue(p.getFetchDirective(FetchDirectiveKind.FontSrc).isPresent());

        p = Policy.parseSerializedCSP("frame-src a", ThrowIfPolicyError);
        assertTrue(p.getFetchDirective(FetchDirectiveKind.FrameSrc).isPresent());

        p = Policy.parseSerializedCSP("img-src a", ThrowIfPolicyError);
        assertTrue(p.getFetchDirective(FetchDirectiveKind.ImgSrc).isPresent());

        p = Policy.parseSerializedCSP("manifest-src a", ThrowIfPolicyError);
        assertTrue(p.getFetchDirective(FetchDirectiveKind.ManifestSrc).isPresent());

        p = Policy.parseSerializedCSP("media-src a", ThrowIfPolicyError);
        assertTrue(p.getFetchDirective(FetchDirectiveKind.MediaSrc).isPresent());

        p = Policy.parseSerializedCSP("object-src a", ThrowIfPolicyError);
        assertTrue(p.getFetchDirective(FetchDirectiveKind.ObjectSrc).isPresent());

        p = Policy.parseSerializedCSP("prefetch-src a", PolicyErrorConsumer.ignored);
        assertTrue(p.getFetchDirective(FetchDirectiveKind.PrefetchSrc).isPresent());

        p = Policy.parseSerializedCSP("script-src-attr a", ThrowIfPolicyError);
        assertTrue(p.getFetchDirective(FetchDirectiveKind.ScriptSrcAttr).isPresent());

        p = Policy.parseSerializedCSP("script-src a", ThrowIfPolicyError);
        assertTrue(p.getFetchDirective(FetchDirectiveKind.ScriptSrc).isPresent());

        p = Policy.parseSerializedCSP("script-src-elem a", ThrowIfPolicyError);
        assertTrue(p.getFetchDirective(FetchDirectiveKind.ScriptSrcElem).isPresent());

        p = Policy.parseSerializedCSP("style-src-attr a", ThrowIfPolicyError);
        assertTrue(p.getFetchDirective(FetchDirectiveKind.StyleSrcAttr).isPresent());

        p = Policy.parseSerializedCSP("style-src a", ThrowIfPolicyError);
        assertTrue(p.getFetchDirective(FetchDirectiveKind.StyleSrc).isPresent());

        p = Policy.parseSerializedCSP("style-src-elem a", ThrowIfPolicyError);
        assertTrue(p.getFetchDirective(FetchDirectiveKind.StyleSrcElem).isPresent());

        p = Policy.parseSerializedCSP("worker-src a", ThrowIfPolicyError);
        assertTrue(p.getFetchDirective(FetchDirectiveKind.WorkerSrc).isPresent());
    }

    @Test
    public void preservesMalformed() {
        roundTrips(
                "not-a-directive foo",
                e(Policy.Severity.Warning, "Unrecognized directive not-a-directive", 0, -1)
        );

        roundTrips(
                "default-src 'not-keyword'",
                e(Policy.Severity.Error, "Unrecognized source-expression 'not-keyword'", 0, 0)
        );

        roundTrips(
                "default-src 'self'a",
                e(Policy.Severity.Error, "Unrecognized source-expression 'self'a", 0, 0)
        );

        roundTrips(
                "default-src 'sha257-000'",
                e(Policy.Severity.Error, "'sha...' source-expression uses an unrecognized algorithm or does not match the base64-value grammar (or is missing its trailing \"'\")", 0, 0)
        );

        roundTrips(
                "default-src 'sha256-000'",
                e(Policy.Severity.Warning, "Wrong length for sha256: expected 44, got 3", 0, 0)
        );

        roundTrips(
                "default-src 'sha256-$$'",
                e(Policy.Severity.Error, "'sha...' source-expression uses an unrecognized algorithm or does not match the base64-value grammar (or is missing its trailing \"'\")", 0, 0)
        );

        roundTrips(
                "base-uri 'not-keyword'",
                e(Policy.Severity.Error, "Unrecognized source-expression 'not-keyword'", 0, 0)
        );

        roundTrips(
                "block-all-mixed-content 'none'",
                e(Policy.Severity.Error, "The block-all-mixed-content directive does not support values", 0, 0)
        );

        roundTrips(
                "form-action 'not-keyword'",
                e(Policy.Severity.Error, "Unrecognized source-expression 'not-keyword'", 0, 0)
        );

        roundTrips(
                "frame-ancestors 'nonce-asdf'",
                e(Policy.Severity.Error, "Unrecognized ancestor-source 'nonce-asdf'", 0, 0)
        );

        roundTrips(
                "navigate-to 'not-keyword'",
                e(Policy.Severity.Error, "Unrecognized source-expression 'not-keyword'", 0, 0)
        );

        roundTrips(
                "plugin-types a",
                e(Policy.Severity.Warning, "The plugin-types directive has been deprecated", 0, -1),
                e(Policy.Severity.Error, "Expecting media-type but found \"a\"", 0, 0)
        );

        roundTrips(
                "report-to",
                e(Policy.Severity.Error, "The report-to directive requires a value", 0, -1)
        );

        roundTrips(
                "prefetch-src a",
                e(Policy.Severity.Warning, "The prefetch-src directive has been deprecated", 0, -1)
        );

        roundTrips(
                "report-to (a)",
                e(Policy.Severity.Error, "Expecting RFC 7230 token but found \"(a)\"", 0, 0)
        );

        roundTrips(
                "report-to a b",
                e(Policy.Severity.Error, "The report-to directive requires exactly one value (found 2)", 0, 1)
        );

        roundTrips(
                "report-uri a a",
                e(Policy.Severity.Warning, "The report-uri directive has been deprecated in favor of the new report-to directive", 0, -1),
                e(Policy.Severity.Info, "Duplicate report-to URI; are you sure you intend to get multiple copies of each report?", 0, 1)
        );

        roundTrips(
                "sandbox allow-nonsense",
                e(Policy.Severity.Error, "Unrecognized sandbox keyword allow-nonsense", 0, 0)
        );

        roundTrips(
                "sandbox allow-scripts allow-scripts",
                e(Policy.Severity.Warning, "Duplicate sandbox keyword allow-scripts", 0, 1)
        );

        roundTrips(
                "upgrade-insecure-requests a",
                e(Policy.Severity.Error, "The upgrade-insecure-requests directive does not support values", 0, 0)
        );

        roundTrips(
                "&",
                e(Policy.Severity.Error, "Directive name & contains characters outside the range ALPHA / DIGIT / \"-\"", 0, -1)
        );

        roundTrips(
                "default-src'self'",
                e(Policy.Severity.Error, "Directive name default-src'self' contains characters outside the range ALPHA / DIGIT / \"-\"", 0, -1)
        );

        roundTrips(
                "default-src'self' a",
                e(Policy.Severity.Error, "Directive name default-src'self' contains characters outside the range ALPHA / DIGIT / \"-\"", 0, -1)
        );

        roundTrips(
                "default-src'self'a",
                e(Policy.Severity.Error, "Directive name default-src'self'a contains characters outside the range ALPHA / DIGIT / \"-\"", 0, -1)
        );
    }

    @Test
    public void preservesDuplicates() {
        roundTrips(
                "base-uri a; base-uri a",
                e(Policy.Severity.Warning, "Duplicate directive base-uri", 1, -1)
        );

        roundTrips(
                "block-all-mixed-content; block-all-mixed-content",
                e(Policy.Severity.Warning, "Duplicate directive block-all-mixed-content", 1, -1)
        );

        roundTrips(
                "form-action a; form-action a",
                e(Policy.Severity.Warning, "Duplicate directive form-action", 1, -1)
        );

        roundTrips(
                "frame-ancestors 'none'; frame-ancestors 'none'",
                e(Policy.Severity.Warning, "Duplicate directive frame-ancestors", 1, -1)
        );

        roundTrips(
                "navigate-to 'none'; navigate-to 'none'",
                e(Policy.Severity.Warning, "Duplicate directive navigate-to", 1, -1)
        );

        roundTrips(
                "plugin-types a/b; plugin-types a/b",
                e(Policy.Severity.Warning, "The plugin-types directive has been deprecated", 0, -1),
                e(Policy.Severity.Warning, "The plugin-types directive has been deprecated", 1, -1),
                e(Policy.Severity.Warning, "Duplicate directive plugin-types", 1, -1)
        );

        roundTrips(
                "report-to a; report-to a",
                e(Policy.Severity.Warning, "Duplicate directive report-to", 1, -1)
        );

        roundTrips(
                "report-uri http://example.com; report-uri http://example.com",
                e(Policy.Severity.Warning, "The report-uri directive has been deprecated in favor of the new report-to directive", 0, -1),
                e(Policy.Severity.Warning, "The report-uri directive has been deprecated in favor of the new report-to directive", 1, -1),
                e(Policy.Severity.Warning, "Duplicate directive report-uri", 1, -1)
        );

        roundTrips(
                "sandbox; sandbox",
                e(Policy.Severity.Warning, "Duplicate directive sandbox", 1, -1)
        );

        roundTrips(
                "upgrade-insecure-requests; upgrade-insecure-requests",
                e(Policy.Severity.Warning, "Duplicate directive upgrade-insecure-requests", 1, -1)
        );

        roundTrips(
                "child-src a; child-src a",
                e(Policy.Severity.Warning, "Duplicate directive child-src", 1, -1)
        );

        roundTrips(
                "connect-src a; connect-src a",
                e(Policy.Severity.Warning, "Duplicate directive connect-src", 1, -1)
        );

        roundTrips(
                "default-src a; default-src a",
                e(Policy.Severity.Warning, "Duplicate directive default-src", 1, -1)
        );

        roundTrips(
                "font-src a; font-src a",
                e(Policy.Severity.Warning, "Duplicate directive font-src", 1, -1)
        );

        roundTrips(
                "frame-src a; frame-src a",
                e(Policy.Severity.Warning, "Duplicate directive frame-src", 1, -1)
        );

        roundTrips(
                "img-src a; img-src a",
                e(Policy.Severity.Warning, "Duplicate directive img-src", 1, -1)
        );

        roundTrips(
                "manifest-src a; manifest-src a",
                e(Policy.Severity.Warning, "Duplicate directive manifest-src", 1, -1)
        );

        roundTrips(
                "media-src a; media-src a",
                e(Policy.Severity.Warning, "Duplicate directive media-src", 1, -1)
        );

        roundTrips(
                "object-src a; object-src a",
                e(Policy.Severity.Warning, "Duplicate directive object-src", 1, -1)
        );

        roundTrips(
                "prefetch-src a; prefetch-src a",
                e(Policy.Severity.Warning, "The prefetch-src directive has been deprecated", 0, -1),
                e(Policy.Severity.Warning, "The prefetch-src directive has been deprecated", 1, -1),
                e(Policy.Severity.Warning, "Duplicate directive prefetch-src", 1, -1)
        );

        roundTrips(
                "script-src-attr a; script-src-attr a",
                e(Policy.Severity.Warning, "Duplicate directive script-src-attr", 1, -1)
        );

        roundTrips(
                "script-src a; script-src a",
                e(Policy.Severity.Warning, "Duplicate directive script-src", 1, -1)
        );

        roundTrips(
                "script-src-elem a; script-src-elem a",
                e(Policy.Severity.Warning, "Duplicate directive script-src-elem", 1, -1)
        );

        roundTrips(
                "style-src-attr a; style-src-attr a",
                e(Policy.Severity.Warning, "Duplicate directive style-src-attr", 1, -1)
        );

        roundTrips(
                "style-src a; style-src a",
                e(Policy.Severity.Warning, "Duplicate directive style-src", 1, -1)
        );

        roundTrips(
                "style-src-elem a; style-src-elem a",
                e(Policy.Severity.Warning, "Duplicate directive style-src-elem", 1, -1)
        );

        roundTrips(
                "worker-src a; worker-src a",
                e(Policy.Severity.Warning, "Duplicate directive worker-src", 1, -1)
        );
    }

    @Test
    public void preservesWeirdness() {
        roundTrips(
                "deFAult-src 'SeLf'"
        );

        roundTrips(
                "sandbox AlLoW-ScRiPtS"
        );

        // TODO there should be an error emitted for this, since it's not a valid percent encoding
        roundTrips(
                "script-src example.com/%ef"
        );

        // Note the use of both '_' and '/' - that's allowed!
        roundTrips(
                "default-src 'sha256-CihokcEcBW4atb_CW/XWsvWwbTjqwQlE9nj9ii5ww5M='",
                e(Policy.Severity.Warning, "'_' and '-' in hashes can never match actual elements", 0, 0)
        );
    }

    @Test
    public void whitespace() {
        serializesTo(
                " default-src  a  ",
                "default-src a"
        );

        serializesTo(
                ";; default-src a ;; img-src b ;;",
                "default-src a; img-src b"
        );

        serializesTo(
                "default-src\na;\rscript-src\fb",
                "default-src a; script-src b"
        );
    }

    @Test
    public void none() {
        // This asserts that it serializes to the same, uppercased, value
        roundTrips(
                "default-src 'NONE'"
        );

        roundTrips(
                "default-src",
                e(Policy.Severity.Error, "Source-expression lists cannot be empty (use 'none' instead)", 0, -1)
        );

        roundTrips(
                "default-src 'NONE' a",
                e(Policy.Severity.Error, "'none' must not be combined with any other source-expression", 0, 1)
        );

        roundTrips(
                "default-src 'NONE' 'none'",
                e(Policy.Severity.Error, "'none' must not be combined with any other source-expression", 0, 1)
        );

        roundTrips(
                "default-src a 'NONE'",
                e(Policy.Severity.Error, "'none' must not be combined with any other source-expression", 0, 1)
        );
    }

    @Test
    public void casing() {
        inTurkey(() -> {
            Policy p;

            p = Policy.parseSerializedCSP("SCRIPT-SRC 'UNSAFE-INLINE'", ThrowIfPolicyError);
            assertTrue(p.getFetchDirective(FetchDirectiveKind.ScriptSrc).isPresent());
            assertTrue(p.getFetchDirective(FetchDirectiveKind.ScriptSrc).get().unsafeInline());

            p = Policy.parseSerializedCSP("sandbox AlLoW-ScRiPtS", ThrowIfPolicyError);
            assertTrue(p.sandbox().isPresent());
            assertTrue(p.sandbox().get().allowScripts());

            p = Policy.parseSerializedCSP("BLOCK-ALL-MIXED-CONTENT", ThrowIfPolicyError);
            assertTrue(p.blockAllMixedContent());

            p = Policy.parseSerializedCSP("default-src FILE:", ThrowIfPolicyError);
            assertTrue(p.getFetchDirective(FetchDirectiveKind.DefaultSrc).get().getSchemes().contains(Scheme.parseScheme("file:").get()));
        });
    }

    @Test
    public void warnings() {
        inTurkey(() -> {
            roundTrips(
                    "default-src none",
                    e(Policy.Severity.Warning, "This host name is unusual, and likely meant to be a keyword that is missing the required quotes: 'none'.", 0, 0)
            );

            roundTrips(
                    "default-src 'unsafe-inline' 'UNSAFE-INLINE'",
                    e(Policy.Severity.Warning, "Duplicate source-expression 'unsafe-inline'", 0, 1)
            );

            roundTrips(
                    "default-src 'unsafe-eval' 'UNSAFE-EVAL'",
                    e(Policy.Severity.Warning, "Duplicate source-expression 'unsafe-eval'", 0, 1)
            );

            roundTrips(
                    "default-src 'strict-dynamic' 'STRICT-DYNAMIC'",
                    e(Policy.Severity.Warning, "Duplicate source-expression 'strict-dynamic'", 0, 1)
            );

            roundTrips(
                    "script-src 'wasm-unsafe-eval' 'WASM-UNSAFE-EVAL'",
                    e(Policy.Severity.Warning, "Duplicate source-expression 'wasm-unsafe-eval'", 0, 1)
            );

            roundTrips(
                    "default-src 'unsafe-hashes' 'UNSAFE-HASHES'",
                    e(Policy.Severity.Warning, "Duplicate source-expression 'unsafe-hashes'", 0, 1)
            );

            roundTrips(
                    "default-src 'report-sample' 'REPORT-SAMPLE'",
                    e(Policy.Severity.Warning, "Duplicate source-expression 'report-sample'", 0, 1)
            );

            roundTrips(
                    "default-src 'unsafe-allow-redirects' 'UNSAFE-ALLOW-REDIRECTS'",
                    e(Policy.Severity.Warning, "Duplicate source-expression 'unsafe-allow-redirects'", 0, 1)
            );

            roundTrips(
                    "default-src 'self' 'self'",
                    e(Policy.Severity.Warning, "Duplicate source-expression 'self'", 0, 1)
            );

            roundTrips(
                    "default-src * *",
                    e(Policy.Severity.Warning, "Duplicate source-expression *", 0, 1)
            );

            roundTrips(
                    "default-src http: http:",
                    e(Policy.Severity.Warning, "Duplicate scheme http:", 0, 1)
            );

            roundTrips(
                    "default-src a a",
                    e(Policy.Severity.Warning, "Duplicate host a", 0, 1)
            );

            roundTrips(
                    "default-src 'none' foo",
                    e(Policy.Severity.Error, "'none' must not be combined with any other source-expression", 0, 1)
            );

            roundTrips(
                    "default-src 'unsafe-redirect'",
                    e(Policy.Severity.Error, "'unsafe-redirect' has been removed from CSP as of version 2.0", 0, 0)
            );

            roundTrips(
                    "default-src 'unsafe-hashed-attributes'",
                    e(Policy.Severity.Error, "'unsafe-hashed-attributes' was renamed to 'unsafe-hashes' in June 2018", 0, 0)
            );

            roundTrips(
                    "sandbox 'allow-scripts'",
                    e(Policy.Severity.Error, "Unrecognized sandbox keyword 'allow-scripts' - note that sandbox keywords do not have \"'\"s", 0, 0)
            );

            roundTrips(
                    "sandbox allow-downloads ALLOW-DOWNLOADS",
                    e(Policy.Severity.Warning, "Duplicate sandbox keyword allow-downloads", 0, 1)
            );

            roundTrips(
                    "sandbox allow-forms ALLOW-FORMS",
                    e(Policy.Severity.Warning, "Duplicate sandbox keyword allow-forms", 0, 1)
            );

            roundTrips(
                    "sandbox allow-modals ALLOW-MODALS",
                    e(Policy.Severity.Warning, "Duplicate sandbox keyword allow-modals", 0, 1)
            );

            roundTrips(
                    "sandbox allow-orientation-lock ALLOW-ORIENTATION-LOCK",
                    e(Policy.Severity.Warning, "Duplicate sandbox keyword allow-orientation-lock", 0, 1)
            );

            roundTrips(
                    "sandbox allow-pointer-lock ALLOW-POINTER-LOCK",
                    e(Policy.Severity.Warning, "Duplicate sandbox keyword allow-pointer-lock", 0, 1)
            );

            roundTrips(
                    "sandbox allow-popups ALLOW-POPUPS",
                    e(Policy.Severity.Warning, "Duplicate sandbox keyword allow-popups", 0, 1)
            );

            roundTrips(
                    "sandbox allow-popups-to-escape-sandbox ALLOW-POPUPS-TO-ESCAPE-SANDBOX",
                    e(Policy.Severity.Warning, "Duplicate sandbox keyword allow-popups-to-escape-sandbox", 0, 1)
            );

            roundTrips(
                    "sandbox allow-presentation ALLOW-PRESENTATION",
                    e(Policy.Severity.Warning, "Duplicate sandbox keyword allow-presentation", 0, 1)
            );

            roundTrips(
                    "sandbox allow-same-origin ALLOW-SAME-ORIGIN",
                    e(Policy.Severity.Warning, "Duplicate sandbox keyword allow-same-origin", 0, 1)
            );

            roundTrips(
                    "sandbox allow-scripts ALLOW-SCRIPTS",
                    e(Policy.Severity.Warning, "Duplicate sandbox keyword allow-scripts", 0, 1)
            );

            roundTrips(
                    "sandbox allow-storage-access-by-user-activation ALLOW-STORAGE-ACCESS-BY-USER-activation",
                    e(Policy.Severity.Warning, "Duplicate sandbox keyword allow-storage-access-by-user-activation", 0, 1)
            );

            roundTrips(
                    "sandbox allow-top-navigation ALLOW-TOP-NAVIGATION",
                    e(Policy.Severity.Warning, "Duplicate sandbox keyword allow-top-navigation", 0, 1)
            );

            roundTrips(
                    "sandbox allow-top-navigation-by-user-activation ALLOW-TOP-NAVIGATION-BY-USER-ACTIVATION",
                    e(Policy.Severity.Warning, "Duplicate sandbox keyword allow-top-navigation-by-user-activation", 0, 1)
            );

            roundTrips(
                    "report-uri",
                    e(Policy.Severity.Warning, "The report-uri directive has been deprecated in favor of the new report-to directive", 0, -1),
                    e(Policy.Severity.Error, "The report-uri value requires at least one value", 0, -1)
            );

            roundTrips(
                    "frame-ancestors",
                    e(Policy.Severity.Error, "Ancestor-source lists cannot be empty (use 'none' instead)", 0, -1)
            );

            roundTrips(
                    "frame-ancestors 'none' 'NONE'",
                    e(Policy.Severity.Error, "'none' must not be combined with any other ancestor-source", 0, 2)
            );

            roundTrips(
                    "plugin-types */*",
                    e(Policy.Severity.Warning, "The plugin-types directive has been deprecated", 0, -1),
                    e(Policy.Severity.Warning, "Media types can only be matched literally. Make sure using `*` is not an oversight.", 0, 0)
            );
        });
    }

    @Test
    public void assertsAscii() {
        assertThrows(IllegalArgumentException.class, () -> {
            Policy.parseSerializedCSP("\uD835\uDC9C", Policy.PolicyErrorConsumer.ignored);
        });
    }

    @Test
    public void assertsNoCommas() {
        assertThrows(IllegalArgumentException.class, () -> {
            Policy.parseSerializedCSP("a ,", Policy.PolicyErrorConsumer.ignored);
        });
    }

    private static void roundTrips(final String input, final PolicyError... errors) {
        serializesTo(input, input, errors);
    }

    private static void serializesTo(final String input, final String output, final PolicyError... errors) {
        final ArrayList<PolicyError> observedErrors = new ArrayList<>();
        final Policy.PolicyErrorConsumer consumer = (severity, message, directiveIndex, valueIndex) -> {
            observedErrors.add(e(severity, message, directiveIndex, valueIndex));
        };
        final Policy policy = Policy.parseSerializedCSP(input, consumer);
        assertEquals(errors.length, observedErrors.size());
        for (int i = 0; i < errors.length; ++i) {
            assertEquals(errors[i], observedErrors.get(i));
        }
        assertEquals(output, policy.toString());
    }

    /**
     * Test for https://github.com/shapesecurity/salvation/issues/244.
     */
    @Test
    public void invalidHashSyntax() {
        final ArrayList<PolicyListError> observedErrors = new ArrayList<>();
        final Policy.PolicyListErrorConsumer consumer = (severity, message, policyIndex, directiveIndex, valueIndex) -> {
            observedErrors.add(e(severity, message, policyIndex, directiveIndex, valueIndex));
        };

        final PolicyList p = Policy.parseSerializedCSPList(
                "default-src 'none'; script-src 'sha256- RFWPLDbv2BY+rCkDzsE+0fr8ylGr2R2faWMhq4lfEQc=';", consumer);
        assertEquals("default-src 'none'; script-src 'sha256- RFWPLDbv2BY+rCkDzsE+0fr8ylGr2R2faWMhq4lfEQc='", p.toString());

        final PolicyListError[] errors = {
                e(Policy.Severity.Error, "'sha...' source-expression uses an unrecognized algorithm "
                        + "or does not match the base64-value grammar (or is missing its trailing \"'\")", 0, 1, 0),
                e(Policy.Severity.Error, "Unrecognized source-expression RFWPLDbv2BY+rCkDzsE+0fr8ylGr2R2faWMhq4lfEQc='", 0, 1, 1)
        };
        assertEquals(errors.length, observedErrors.size());
        for (int i = 0; i < errors.length; ++i) {
            assertEquals(errors[i], observedErrors.get(i));
        }
    }
}
