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
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import org.htmlunit.csp.url.URI;
import org.htmlunit.csp.url.URLWithScheme;
import org.junit.jupiter.api.Test;

/**
 * CSP3 fetch directive fallback, {@code -elem}/{@code -attr} precedence and eval-related keywords.
 *
 * @see <a href="https://www.w3.org/TR/CSP3/#directive-fallback-list">CSP3 fallback list</a>
 * @see <a href="https://www.w3.org/TR/CSP3/#can-compile-strings">CSP3 can compile strings</a>
 */
public class Csp3SurfaceTest extends TestBase {

    private static final URLWithScheme ORIGIN = URI.parseURI("https://example.com").orElseThrow();
    private static final Optional<URLWithScheme> SAME = Optional.of(ORIGIN);
    private static final Optional<URLWithScheme> OTHER =
            Optional.of(URI.parseURI("https://other.example").orElseThrow());

    private static Policy policy(final String csp) {
        return Policy.parseSerializedCSP(csp, Policy.PolicyErrorConsumer.ignored);
    }

    private static PolicyList list(final String... csps) {
        return PolicyList.ofSerialized(List.of(csps), Policy.PolicyListErrorConsumer.ignored);
    }

    private static void assertKeywordWarnings(final String directive, final String keyword) {
        final List<PolicyError> errors = new ArrayList<>();
        final Policy.PolicyErrorConsumer consumer = (severity, message, directiveIndex, valueIndex) ->
                errors.add(e(severity, message, directiveIndex, valueIndex));

        Policy.parseSerializedCSP(directive + " '" + keyword + "' '" + keyword.toUpperCase(Locale.ROOT) + "'",
                consumer);
        assertEquals(List.of(
                e(Policy.Severity.Warning, "Duplicate source-expression '" + keyword + "'", 0, 1)), errors);

        errors.clear();
        Policy.parseSerializedCSP(directive + " " + keyword, consumer);
        assertEquals(1, errors.size());
        assertTrue(errors.get(0).message_().contains("missing the required quotes: '" + keyword + "'"),
                errors.get(0).message_());
    }

    private static boolean worker(final Policy p, final Optional<URLWithScheme> url) {
        return p.allowsWorker(url, SAME);
    }

    private static boolean frame(final Policy p, final Optional<URLWithScheme> url) {
        return p.allowsFrame(url, SAME);
    }

    // fallback

    @Test
    public void childSrcAndDefaultSrcResolveWithoutThrowing() {
        final Policy p = policy("default-src 'none'; child-src 'self'");
        assertSame(p.getFetchDirective(FetchDirectiveKind.ChildSrc).get(),
                p.getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.ChildSrc).get());
        assertSame(p.getFetchDirective(FetchDirectiveKind.DefaultSrc).get(),
                p.getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.DefaultSrc).get());

        // child-src falls back to default-src (extension, spec has an empty list)
        final Policy onlyDefault = policy("default-src 'self'");
        assertSame(onlyDefault.getFetchDirective(FetchDirectiveKind.DefaultSrc).get(),
                onlyDefault.getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.ChildSrc).get());

        assertFalse(policy("img-src 'self'")
                .getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.ChildSrc).isPresent());
        assertFalse(policy("child-src 'self'")
                .getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.DefaultSrc).isPresent());
    }

    @Test
    public void workerFallsBackToChildThenScriptThenDefault() {
        // worker-src > child-src > script-src > default-src
        assertTrue(worker(policy("worker-src 'self'; child-src 'none'; script-src 'none'"), SAME));
        assertFalse(worker(policy("worker-src 'none'; child-src 'self'; script-src 'self'"), SAME));
        assertTrue(worker(policy("child-src 'self'; script-src 'none'; default-src 'none'"), SAME));
        assertFalse(worker(policy("child-src 'none'; script-src 'self'; default-src 'self'"), SAME));
        assertTrue(worker(policy("script-src 'self'; default-src 'none'"), SAME));
        assertFalse(worker(policy("script-src 'none'; default-src 'self'"), SAME));
        assertTrue(worker(policy("default-src 'self'"), SAME));
        assertFalse(worker(policy("default-src 'self'"), OTHER));
        assertTrue(worker(policy("img-src 'none'"), OTHER));
    }

    @Test
    public void scriptSrcElemAndAttrDoNotGovernWorkers() {
        // https://www.w3.org/TR/CSP3/#directive-script-src-elem
        assertTrue(worker(policy("script-src-elem 'none'"), SAME));
        assertTrue(worker(policy("script-src-attr 'none'; default-src 'self'"), SAME));
        assertFalse(worker(policy("script-src-elem 'self'; script-src 'none'"), SAME));
    }

    @Test
    public void frameFallsBackToChildThenDefaultSkippingScriptSrc() {
        assertTrue(frame(policy("frame-src 'self'; child-src 'none'"), SAME));
        assertFalse(frame(policy("frame-src 'none'; child-src 'self'"), SAME));
        assertTrue(frame(policy("child-src 'self'; default-src 'none'"), SAME));
        assertFalse(frame(policy("child-src 'none'; default-src 'self'"), SAME));
        assertTrue(frame(policy("default-src 'self'"), SAME));
        // frame-src does not consult script-src
        assertTrue(frame(policy("script-src 'none'"), SAME));
        assertTrue(frame(policy("script-src 'none'; default-src 'self'"), SAME));
    }

    @Test
    public void fallbackThroughPolicyList() {
        // each policy resolves its own chain, then they are ANDed
        final PolicyList l = list("child-src 'self'; default-src 'none'", "worker-src https://other.example");
        assertFalse(l.allowsWorker(SAME, SAME));
        assertFalse(l.allowsWorker(OTHER, SAME));
        assertTrue(list("child-src 'self'", "default-src 'self'").allowsFrame(SAME, SAME));
        assertFalse(list("child-src 'self'", "default-src 'self'").allowsFrame(OTHER, SAME));
    }

    // -elem / -attr

    @Test
    public void scriptSrcElemOverridesScriptSrcForElements() {
        final Policy p = policy("script-src-elem https://other.example 'nonce-abc'; script-src 'self' 'unsafe-inline'");
        assertTrue(p.allowsExternalScript(Optional.empty(), Optional.empty(), OTHER, Optional.of(false), SAME));
        assertFalse(p.allowsExternalScript(Optional.empty(), Optional.empty(), SAME, Optional.of(false), SAME));
        assertTrue(p.allowsInlineScript(Optional.of("abc"), Optional.empty(), Optional.of(false)));
        // script-src's 'unsafe-inline' is not inherited by script-src-elem
        assertFalse(p.allowsInlineScript(Optional.empty(), Optional.empty(), Optional.of(false)));
        // script-src-attr absent, so event handlers fall back to script-src
        assertTrue(p.allowsScriptAsAttribute(Optional.empty()));
    }

    @Test
    public void scriptSrcAttrOverridesScriptSrcForAttributes() {
        final Policy p = policy("script-src-attr 'none'; script-src 'unsafe-inline'");
        assertFalse(p.allowsScriptAsAttribute(Optional.empty()));
        assertTrue(p.allowsInlineScript(Optional.empty(), Optional.empty(), Optional.of(false)));

        assertTrue(policy("script-src-attr 'unsafe-inline'; script-src 'none'")
                .allowsScriptAsAttribute(Optional.empty()));
        assertFalse(policy("script-src-attr 'unsafe-inline'; script-src 'none'")
                .allowsInlineScript(Optional.empty(), Optional.empty(), Optional.of(false)));
    }

    @Test
    public void styleSrcElemAndAttrPrecedence() {
        final Policy p = policy("style-src-elem https://other.example; style-src-attr 'unsafe-inline'; style-src 'none'");
        assertTrue(p.allowsExternalStyle(Optional.empty(), OTHER, SAME));
        assertFalse(p.allowsExternalStyle(Optional.empty(), SAME, SAME));
        assertFalse(p.allowsInlineStyle(Optional.empty(), Optional.empty()));
        assertTrue(p.allowsStyleAsAttribute(Optional.empty()));

        final Policy q = policy("style-src-elem 'unsafe-inline'; style-src 'none'");
        assertTrue(q.allowsInlineStyle(Optional.empty(), Optional.empty()));
        assertFalse(q.allowsStyleAsAttribute(Optional.empty()));
    }

    @Test
    public void javascriptUrlUsesScriptSrcElem() {
        // CSP3 "effective directive for inline checks": navigation -> script-src-elem
        assertTrue(policy("script-src-elem 'unsafe-inline'; script-src 'none'")
                .allowsJavascriptUrlNavigation(Optional.empty(), SAME));
        assertFalse(policy("script-src-elem 'none'; script-src 'unsafe-inline'")
                .allowsJavascriptUrlNavigation(Optional.empty(), SAME));
    }

    // eval

    @Test
    public void evalIgnoresElemAndAttr() {
        // https://www.w3.org/TR/CSP3/#directive-script-src (note on script-src-elem / -attr)
        assertFalse(policy("script-src-elem 'unsafe-eval'; script-src 'none'").allowsEval());
        assertTrue(policy("script-src-elem 'none'; script-src 'unsafe-eval'").allowsEval());
        assertFalse(policy("script-src-attr 'unsafe-eval'; default-src 'none'").allowsEval());
        assertTrue(policy("script-src-elem 'none'; default-src 'unsafe-eval'").allowsEval());
    }

    @Test
    public void wasmUnsafeEval() {
        assertTrue(policy("img-src 'none'").allowsWasmEval());
        assertFalse(policy("script-src 'self'").allowsWasmEval());
        assertTrue(policy("script-src 'self' 'wasm-unsafe-eval'").allowsWasmEval());
        assertTrue(policy("script-src 'self' 'unsafe-eval'").allowsWasmEval());
        assertTrue(policy("default-src 'wasm-unsafe-eval'").allowsWasmEval());
        // script-src governs, default-src is not consulted
        assertFalse(policy("script-src 'self'; default-src 'wasm-unsafe-eval'").allowsWasmEval());
        // elem/attr are not consulted
        assertFalse(policy("script-src-elem 'wasm-unsafe-eval'; script-src 'none'").allowsWasmEval());
        // wasm-unsafe-eval does not allow eval
        assertFalse(policy("script-src 'wasm-unsafe-eval'").allowsEval());
        assertTrue(policy("script-src 'wasm-unsafe-eval'").allowsWasmEval());

        assertFalse(list("script-src 'wasm-unsafe-eval'", "script-src 'self'").allowsWasmEval());
        assertTrue(list("script-src 'wasm-unsafe-eval'", "default-src 'unsafe-eval'").allowsWasmEval());
    }

    @Test
    public void trustedTypesEvalKeyword() {
        final Policy p = Policy.parseSerializedCSP("script-src 'self' 'TRUSTED-TYPES-EVAL'", ThrowIfPolicyError);
        assertTrue(p.getFetchDirective(FetchDirectiveKind.ScriptSrc).get().trustedTypesEval());
        assertFalse(policy("script-src 'self'").getFetchDirective(FetchDirectiveKind.ScriptSrc).get()
                .trustedTypesEval());
        assertEquals("script-src 'self' 'TRUSTED-TYPES-EVAL'", p.toString());

        assertKeywordWarnings("script-src", "trusted-types-eval");
    }

    @Test
    public void trustedTypesEvalRequiresEnforcement() {
        // https://www.w3.org/TR/CSP3/#can-compile-strings
        final String tte = "script-src 'trusted-types-eval'";
        // no Trusted Types enforcement: plain 'trusted-types-eval' allows nothing
        assertFalse(policy(tte).allowsTrustedTypesEval());
        assertFalse(policy(tte).allowsEval());
        // with enforcement
        final Policy enforced = policy(tte + "; require-trusted-types-for 'script'");
        assertTrue(enforced.allowsTrustedTypesEval());
        // strings stay blocked
        assertFalse(enforced.allowsEval());
        // 'unsafe-eval' allows both
        assertTrue(policy("script-src 'unsafe-eval'").allowsTrustedTypesEval());
        assertTrue(policy("script-src 'unsafe-eval'").allowsEval());
        // no governing directive
        assertTrue(policy("img-src 'none'").allowsTrustedTypesEval());
        // falls back to default-src
        assertTrue(policy("default-src 'trusted-types-eval'; require-trusted-types-for 'script'")
                .allowsTrustedTypesEval());
        // script-src governs
        assertFalse(policy("script-src 'self'; default-src 'trusted-types-eval'; "
                + "require-trusted-types-for 'script'").allowsTrustedTypesEval());
        // elem is not consulted
        assertFalse(policy("script-src-elem 'trusted-types-eval'; script-src 'none'; "
                + "require-trusted-types-for 'script'").allowsTrustedTypesEval());
    }

    @Test
    public void trustedTypesEvalEnforcementIsListWide() {
        // CSP3 evaluates "does sink type require trusted types" over the global's whole CSP list,
        // so enforcement in one policy activates 'trusted-types-eval' in another.
        final PolicyList l = list("script-src 'trusted-types-eval'", "require-trusted-types-for 'script'");
        assertTrue(l.allowsTrustedTypesEval());
        assertFalse(l.allowsEval());
        // a policy with a plain script-src still blocks
        assertFalse(list("script-src 'trusted-types-eval'", "script-src 'self'",
                "require-trusted-types-for 'script'").allowsTrustedTypesEval());
        // no enforcement anywhere
        assertFalse(list("script-src 'trusted-types-eval'", "default-src 'self'").allowsTrustedTypesEval());
        // empty list is unrestricted
        assertTrue(new PolicyList(List.of()).allowsTrustedTypesEval());
        assertTrue(new PolicyList(List.of()).allowsWasmEval());
    }

    @Test
    public void unsafeWebTransportHashesKeyword() {
        final Policy p = Policy.parseSerializedCSP("connect-src 'self' 'UNSAFE-WEBTRANSPORT-HASHES'", ThrowIfPolicyError);
        assertTrue(p.getFetchDirective(FetchDirectiveKind.ConnectSrc).get().unsafeWebTransportHashes());
        assertFalse(policy("connect-src 'self'").getFetchDirective(FetchDirectiveKind.ConnectSrc).get()
                .unsafeWebTransportHashes());
        assertEquals("connect-src 'self' 'UNSAFE-WEBTRANSPORT-HASHES'", p.toString());

        assertKeywordWarnings("connect-src", "unsafe-webtransport-hashes");
    }

    @Test
    public void webTransportWithCertificateHashes() {
        // https://www.w3.org/TR/CSP3/#connect-src-pre-request
        assertTrue(policy("img-src 'none'").allowsWebTransportWithCertificateHashes());
        assertFalse(policy("connect-src 'self'").allowsWebTransportWithCertificateHashes());
        assertFalse(policy("connect-src *").allowsWebTransportWithCertificateHashes());
        assertTrue(policy("connect-src 'unsafe-webtransport-hashes'").allowsWebTransportWithCertificateHashes());
        // falls back to default-src
        assertFalse(policy("default-src 'self'").allowsWebTransportWithCertificateHashes());
        assertTrue(policy("default-src 'unsafe-webtransport-hashes'").allowsWebTransportWithCertificateHashes());
        // connect-src governs, default-src is not consulted
        assertFalse(policy("connect-src 'self'; default-src 'unsafe-webtransport-hashes'")
                .allowsWebTransportWithCertificateHashes());
        // the keyword does not allow other connections
        assertFalse(policy("connect-src 'unsafe-webtransport-hashes'").allowsConnection(OTHER, SAME));

        assertFalse(list("connect-src 'unsafe-webtransport-hashes'", "connect-src 'self'")
                .allowsWebTransportWithCertificateHashes());
        assertTrue(list("connect-src 'unsafe-webtransport-hashes'", "img-src 'none'")
                .allowsWebTransportWithCertificateHashes());
        assertTrue(new PolicyList(List.of()).allowsWebTransportWithCertificateHashes());
    }

    @Test
    public void reportHashKeywords() {
        final Policy p = Policy.parseSerializedCSP("script-src 'self' 'report-sha256' 'REPORT-SHA512'; report-to ep",
                ThrowIfPolicyError);
        assertEquals(List.of("sha256", "sha512"),
                p.getFetchDirective(FetchDirectiveKind.ScriptSrc).get().getReportHashAlgorithms());
        assertEquals("script-src 'self' 'report-sha256' 'REPORT-SHA512'; report-to ep", p.toString());
        // reporting only: enforcement is unchanged
        assertFalse(p.allowsExternalScript(Optional.empty(), Optional.empty(), OTHER, Optional.of(false), SAME));
        assertTrue(policy("script-src 'self'").getFetchDirective(FetchDirectiveKind.ScriptSrc).get()
                .getReportHashAlgorithms().isEmpty());

        assertKeywordWarnings("script-src", "report-sha384");
    }

    private static List<PolicyError> parseErrors(final String csp) {
        final List<PolicyError> errors = new ArrayList<>();
        Policy.parseSerializedCSP(csp, (severity, message, directiveIndex, valueIndex) ->
                errors.add(e(severity, message, directiveIndex, valueIndex)));
        return errors;
    }

    private static PolicyError warning(final String message, final int directiveIndex) {
        return e(Policy.Severity.Warning, message, directiveIndex, -1);
    }

    @Test
    public void inertKeywordsWarn() {
        assertEquals(List.of(
                warning("'wasm-unsafe-eval' has no effect in script-src-elem, "
                        + "it is only used from script-src and default-src", 0),
                warning("'trusted-types-eval' has no effect in script-src-elem, "
                        + "it is only used from script-src and default-src", 0),
                warning("'unsafe-webtransport-hashes' has no effect in img-src, "
                        + "it is only used from connect-src and default-src", 1)),
                parseErrors("script-src-elem 'wasm-unsafe-eval' 'trusted-types-eval'; "
                        + "img-src 'unsafe-webtransport-hashes'"));

        // non-fetch source lists too
        assertEquals(List.of(
                warning("'unsafe-eval' has no effect in base-uri, it is only used from script-src and default-src", 0)),
                parseErrors("base-uri 'unsafe-eval'"));

        // no warning where the keyword is used
        assertEquals(List.of(), parseErrors("script-src 'unsafe-eval' 'wasm-unsafe-eval' 'trusted-types-eval'; "
                + "connect-src 'unsafe-webtransport-hashes'"));
        assertEquals(List.of(), parseErrors("default-src 'unsafe-eval' 'wasm-unsafe-eval' 'trusted-types-eval' "
                + "'unsafe-webtransport-hashes'"));
    }

    @Test
    public void unsafeEvalInOtherDirectivesWarns() {
        assertEquals(List.of(
                warning("'unsafe-eval' has no effect in script-src-elem, "
                        + "it is only used from script-src and default-src", 0)),
                parseErrors("script-src-elem 'unsafe-eval'; script-src 'self'"));
    }

    @Test
    public void reportHashKeywordsOnlyApplyToScriptLikeDirectives() {
        final String reason = "it only applies to directives that impact script-like destinations "
                + "(script-src, script-src-elem, worker-src, child-src, default-src)";
        assertEquals(List.of(warning("'report-sha256' has no effect in img-src, " + reason, 0)),
                parseErrors("img-src 'report-sha256'"));
        assertEquals(List.of(
                warning("'report-sha384' has no effect in script-src-attr, " + reason, 0),
                warning("'report-sha512' has no effect in script-src-attr, " + reason, 0)),
                parseErrors("script-src-attr 'report-sha384' 'report-sha512'"));
        for (final String directive : List.of("script-src", "script-src-elem", "worker-src", "child-src",
                "default-src")) {
            assertEquals(List.of(), parseErrors(directive + " 'report-sha256'"), directive);
        }
    }

    @Test
    public void defaultSrcKeywordsShadowedByMoreSpecificDirectiveWarn() {
        assertEquals(List.of(
                warning("'unsafe-eval' has no effect in default-src, script-src is present and governs instead", 0),
                warning("'wasm-unsafe-eval' has no effect in default-src, "
                        + "script-src is present and governs instead", 0),
                warning("'trusted-types-eval' has no effect in default-src, "
                        + "script-src is present and governs instead", 0)),
                parseErrors("default-src 'unsafe-eval' 'wasm-unsafe-eval' 'trusted-types-eval'; script-src 'self'"));
        // order independent, reported at default-src
        assertEquals(List.of(
                warning("'unsafe-eval' has no effect in default-src, script-src is present and governs instead", 1)),
                parseErrors("script-src 'self'; default-src 'unsafe-eval'"));
        assertEquals(List.of(
                warning("'unsafe-webtransport-hashes' has no effect in default-src, "
                        + "connect-src is present and governs instead", 0)),
                parseErrors("default-src 'unsafe-webtransport-hashes'; connect-src 'self'"));
        // script-src-elem does not shadow eval, so no warning
        assertEquals(List.of(), parseErrors("default-src 'unsafe-eval'; script-src-elem 'self'"));
        // behaviour matches the warning
        assertFalse(policy("default-src 'unsafe-eval'; script-src 'self'").allowsEval());
    }

    @Test
    public void evalQueriesOnOriginWrapper() {
        final PolicyInOrigin p = new PolicyInOrigin(
                policy("script-src 'wasm-unsafe-eval' 'trusted-types-eval'; connect-src 'unsafe-webtransport-hashes'; "
                        + "require-trusted-types-for 'script'"), ORIGIN);
        assertFalse(p.allowsEval());
        assertTrue(p.allowsWasmEval());
        assertTrue(p.allowsTrustedTypesEval());
        assertTrue(p.allowsWebTransportWithCertificateHashes());

        final PolicyListInOrigin l = new PolicyListInOrigin(
                list("script-src 'self'", "connect-src 'self'"), ORIGIN);
        assertFalse(l.allowsWasmEval());
        assertFalse(l.allowsTrustedTypesEval());
        assertFalse(l.allowsWebTransportWithCertificateHashes());
    }

    @Test
    public void trustedTypesEvalForReportOnlyUsesEnforcedRequirement() {
        // CSP3 counts only enforced policies towards "Trusted Types required", also for Report-Only checks
        final PolicyList enforced = list("require-trusted-types-for 'script'");
        final PolicyList reportOnly = list("script-src 'trusted-types-eval'");
        assertFalse(reportOnly.allowsTrustedTypesEval());
        assertTrue(reportOnly.allowsTrustedTypesEval(enforced.enforcesTrustedTypesForScript()));
        assertTrue(reportOnly.getPolicies().get(0).allowsTrustedTypesEval(enforced.enforcesTrustedTypesForScript()));

        // a Report-Only require-trusted-types-for does not count
        final PolicyList reportOnlyRequiring = list(
                "script-src 'trusted-types-eval'; require-trusted-types-for 'script'");
        assertTrue(reportOnlyRequiring.allowsTrustedTypesEval());
        assertFalse(reportOnlyRequiring.allowsTrustedTypesEval(false));
        assertFalse(reportOnlyRequiring.getPolicies().get(0).allowsTrustedTypesEval(false));
    }

    @Test
    public void trustedTypesEvalInMetaPolicy() {
        // require-trusted-types-for is honoured when delivered via meta
        final Policy meta = Policy.parseSerializedCSP(
                "script-src 'trusted-types-eval'; require-trusted-types-for 'script'",
                Policy.PolicyErrorConsumer.ignored, true);
        assertTrue(meta.allowsTrustedTypesEval());
        assertFalse(meta.allowsEval());

        // header policy opts in 'trusted-types-eval', meta policy enforces Trusted Types
        final Policy header = policy("script-src 'trusted-types-eval'");
        final Policy enforcing = Policy.parseSerializedCSP(
                "require-trusted-types-for 'script'", Policy.PolicyErrorConsumer.ignored, true);
        assertTrue(new PolicyList(List.of(header, enforcing)).allowsTrustedTypesEval());
        assertFalse(new PolicyList(List.of(header)).allowsTrustedTypesEval());
    }
}
