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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.htmlunit.csp.directive.SourceExpressionDirective;
import org.htmlunit.csp.url.URI;
import org.junit.jupiter.api.Test;

/**
 * The path part of a source expression is only compared if the request was not redirected, see
 * <a href="https://w3c.github.io/webappsec-csp/#match-url-to-source-expression">Does url match
 * expression in origin with redirect count</a> (step 6).
 *
 * @author Ronald Brill
 */
public class RedirectPathMatchingTest extends TestBase {

    private static final Optional<URI> ORIGIN = url("https://example.com");

    /** A URL-based query of {@link CspQueries} with the {@code redirected} flag. */
    @FunctionalInterface
    private interface RedirectQuery {
        boolean allows(CspQueries queries, Optional<URI> url, boolean redirected);
    }

    /** Old (no {@code redirected} parameter) query, to make sure it behaves like {@code redirected == false}. */
    @FunctionalInterface
    private interface PlainQuery {
        boolean allows(CspQueries queries, Optional<URI> url);
    }

    private static final Map<String, RedirectQuery> QUERIES = new LinkedHashMap<>();
    private static final Map<String, PlainQuery> PLAIN_QUERIES = new LinkedHashMap<>();

    static {
        QUERIES.put("script-src", (q, u, r) -> q.allowsExternalScript(Optional.empty(), Optional.empty(), u,
                Optional.of(true), ORIGIN, r));
        QUERIES.put("style-src", (q, u, r) -> q.allowsExternalStyle(Optional.empty(), u, ORIGIN, r));
        QUERIES.put("frame-src", (q, u, r) -> q.allowsFrame(u, ORIGIN, r));
        QUERIES.put("connect-src", (q, u, r) -> q.allowsConnection(u, ORIGIN, true, r));
        QUERIES.put("font-src", (q, u, r) -> q.allowsFont(u, ORIGIN, r));
        QUERIES.put("img-src", (q, u, r) -> q.allowsImage(u, ORIGIN, r));
        QUERIES.put("manifest-src", (q, u, r) -> q.allowsApplicationManifest(u, ORIGIN, r));
        QUERIES.put("media-src", (q, u, r) -> q.allowsMedia(u, ORIGIN, r));
        QUERIES.put("object-src", (q, u, r) -> q.allowsObject(u, ORIGIN, r));
        QUERIES.put("prefetch-src", (q, u, r) -> q.allowsPrefetch(u, ORIGIN, r));
        QUERIES.put("worker-src", (q, u, r) -> q.allowsWorker(u, ORIGIN, r));

        PLAIN_QUERIES.put("script-src", (q, u) -> q.allowsExternalScript(Optional.empty(), Optional.empty(), u,
                Optional.of(true), ORIGIN));
        PLAIN_QUERIES.put("style-src", (q, u) -> q.allowsExternalStyle(Optional.empty(), u, ORIGIN));
        PLAIN_QUERIES.put("frame-src", (q, u) -> q.allowsFrame(u, ORIGIN));
        PLAIN_QUERIES.put("connect-src", (q, u) -> q.allowsConnection(u, ORIGIN));
        PLAIN_QUERIES.put("font-src", (q, u) -> q.allowsFont(u, ORIGIN));
        PLAIN_QUERIES.put("img-src", (q, u) -> q.allowsImage(u, ORIGIN));
        PLAIN_QUERIES.put("manifest-src", (q, u) -> q.allowsApplicationManifest(u, ORIGIN));
        PLAIN_QUERIES.put("media-src", (q, u) -> q.allowsMedia(u, ORIGIN));
        PLAIN_QUERIES.put("object-src", (q, u) -> q.allowsObject(u, ORIGIN));
        PLAIN_QUERIES.put("prefetch-src", (q, u) -> q.allowsPrefetch(u, ORIGIN));
        PLAIN_QUERIES.put("worker-src", (q, u) -> q.allowsWorker(u, ORIGIN));
    }

    private static Optional<URI> url(final String url) {
        final Optional<URI> parsed = URI.parseURI(url);
        assertTrue(parsed.isPresent(), "unparsable test url " + url);
        return parsed;
    }

    // prefetch-src is deprecated and produces a warning, everything else has to parse cleanly
    private static Policy policy(final String serialized) {
        return Policy.parseSerializedCSP(serialized,
                serialized.startsWith("prefetch-src") ? Policy.PolicyErrorConsumer.ignored : ThrowIfPolicyError);
    }

    private static PolicyList list(final String... serialized) {
        return PolicyList.ofSerialized(List.of(serialized),
                serialized[0].startsWith("prefetch-src") ? Policy.PolicyListErrorConsumer.ignored
                        : ThrowIfPolicyListError);
    }

    @Test
    public void directoryPathMatchesOtherPathOnlyWhenRedirected() {
        for (final Map.Entry<String, RedirectQuery> entry : QUERIES.entrySet()) {
            final String directive = entry.getKey();
            final Policy p = policy(directive + " https://example.com/allowed/");
            final Optional<URI> other = url("https://example.com/other/x.js");
            final Optional<URI> inside = url("https://example.com/allowed/x.js");

            assertTrue(entry.getValue().allows(p, other, true), directive);
            assertFalse(entry.getValue().allows(p, other, false), directive);
            assertFalse(PLAIN_QUERIES.get(directive).allows(p, other), directive);

            assertTrue(entry.getValue().allows(p, inside, true), directive);
            assertTrue(entry.getValue().allows(p, inside, false), directive);
            assertTrue(PLAIN_QUERIES.get(directive).allows(p, inside), directive);
        }
    }

    @Test
    public void exactFileMatchesOtherFileOnlyWhenRedirected() {
        for (final Map.Entry<String, RedirectQuery> entry : QUERIES.entrySet()) {
            final String directive = entry.getKey();
            final Policy p = policy(directive + " https://example.com/allowed/a.js");
            final Optional<URI> other = url("https://example.com/b.js");

            assertTrue(entry.getValue().allows(p, other, true), directive);
            assertFalse(entry.getValue().allows(p, other, false), directive);
            assertFalse(PLAIN_QUERIES.get(directive).allows(p, other), directive);
        }
    }

    @Test
    public void hostPortAndSchemeStillCheckedWhenRedirected() {
        for (final Map.Entry<String, RedirectQuery> entry : QUERIES.entrySet()) {
            final String directive = entry.getKey();
            final Policy p = policy(directive + " https://example.com/allowed/");

            // control: same host, port and scheme
            assertTrue(entry.getValue().allows(p, url("https://example.com/elsewhere"), true), directive);

            assertFalse(entry.getValue().allows(p, url("https://evil.example/allowed/x.js"), true), directive);
            assertFalse(entry.getValue().allows(p, url("https://sub.example.com/allowed/x.js"), true), directive);
            assertFalse(entry.getValue().allows(p, url("https://example.com:8443/allowed/x.js"), true), directive);
            assertFalse(entry.getValue().allows(p, url("http://example.com/allowed/x.js"), true), directive);
        }
    }

    @Test
    public void wildcardHostAndSchemeOnlySourcesAreUnaffected() {
        final Policy p = policy("img-src https://*.example.com/allowed/ data:");
        assertTrue(p.allowsImage(url("https://cdn.example.com/other/x.png"), ORIGIN, true));
        assertFalse(p.allowsImage(url("https://cdn.example.com/other/x.png"), ORIGIN, false));
        assertFalse(p.allowsImage(url("https://cdn.example.org/allowed/x.png"), ORIGIN, true));

        final Policy self = policy("img-src 'self'");
        assertTrue(self.allowsImage(url("https://example.com/any/x.png"), ORIGIN, true));
        assertFalse(self.allowsImage(url("https://other.example/any/x.png"), ORIGIN, true));
    }

    @Test
    public void webSocketMappingAndRedirectAreIndependent() {
        final Policy p = policy("connect-src https://example.com/allowed/");
        final Optional<URI> ws = url("wss://example.com/other/socket");

        // spec mode maps wss: to https:, so only the path differs
        assertTrue(p.allowsConnection(ws, ORIGIN, true, true));
        assertFalse(p.allowsConnection(ws, ORIGIN, true, false));
        assertFalse(p.allowsConnection(ws, ORIGIN, true));

        // browser mode does not map, so the scheme does not match even after a redirect
        assertFalse(p.allowsConnection(ws, ORIGIN, false, true));
    }

    @Test
    public void staticMatcher() {
        final Policy p = policy("img-src https://example.com/allowed/");
        final Optional<URI> other = url("https://example.com/other/x.png");
        final SourceExpressionDirective list =
                p.getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.ImgSrc).orElseThrow();

        assertTrue(Policy.doesUrlMatchSourceListInOrigin(other.get(), list, ORIGIN, true));
        assertFalse(Policy.doesUrlMatchSourceListInOrigin(other.get(), list, ORIGIN, false));
        assertFalse(Policy.doesUrlMatchSourceListInOrigin(other.get(), list, ORIGIN));
    }

    @Test
    public void policyListPassesRedirectedToEveryPolicy() {
        final PolicyList l = list("img-src https://example.com/allowed/", "img-src https://example.com/also/");
        final Optional<URI> other = url("https://example.com/other/x.png");

        assertTrue(l.allowsImage(other, ORIGIN, true));
        assertFalse(l.allowsImage(other, ORIGIN, false));
        assertFalse(l.allowsImage(other, ORIGIN));

        // the host still has to match in every policy
        final PolicyList hosts = list("img-src https://example.com/allowed/", "img-src https://cdn.example/");
        assertFalse(hosts.allowsImage(other, ORIGIN, true));

        for (final Map.Entry<String, RedirectQuery> entry : QUERIES.entrySet()) {
            final String directive = entry.getKey();
            final PolicyList pl = list(directive + " https://example.com/allowed/", "default-src https://example.com/x/");
            assertTrue(entry.getValue().allows(pl, other, true), directive);
            assertFalse(entry.getValue().allows(pl, other, false), directive);
        }
    }

    @Test
    public void navigationIgnoresPathOfRedirectTarget() {
        final Policy p = policy("navigate-to 'unsafe-allow-redirects' https://example.com/allowed/");
        final Optional<URI> start = url("https://example.com/allowed/start");

        // redirect target on an other path is allowed
        assertTrue(p.allowsNavigation(start, Optional.of(true), url("https://example.com/other/end"), ORIGIN));
        // but host, port and scheme are still checked
        assertFalse(p.allowsNavigation(start, Optional.of(true), url("https://evil.example/allowed/end"), ORIGIN));
        assertFalse(p.allowsNavigation(start, Optional.of(true), url("https://example.com:8443/allowed/end"), ORIGIN));
        assertFalse(p.allowsNavigation(start, Optional.of(true), url("http://example.com/allowed/end"), ORIGIN));

        // the initial url is not redirected, so its path is compared
        assertFalse(p.allowsNavigation(url("https://example.com/other/start"), Optional.of(false),
                Optional.empty(), ORIGIN));
        // unknown whether redirected: both urls are checked, only the redirect target without the path
        assertTrue(p.allowsNavigation(start, Optional.empty(), url("https://example.com/other/end"), ORIGIN));
        assertFalse(p.allowsNavigation(url("https://example.com/other/start"), Optional.empty(),
                url("https://example.com/other/end"), ORIGIN));

        // without 'unsafe-allow-redirects' only the initial url is checked
        final Policy noRedirects = policy("navigate-to https://example.com/allowed/");
        assertTrue(noRedirects.allowsNavigation(start, Optional.of(true), url("https://evil.example/x"), ORIGIN));
        assertFalse(noRedirects.allowsNavigation(url("https://example.com/other/start"), Optional.of(true),
                url("https://example.com/allowed/end"), ORIGIN));
    }

    @Test
    public void formActionPerRequestIgnoresPathOfRedirectTarget() {
        final Policy p = policy("form-action https://example.com/allowed/");
        final Optional<URI> other = url("https://example.com/other/done");

        // a redirect target on an other path is allowed
        assertTrue(p.allowsFormAction(other, ORIGIN, true));
        // the submission itself still has its path compared
        assertFalse(p.allowsFormAction(other, ORIGIN, false));
        assertFalse(p.allowsFormAction(other, Optional.of(false), Optional.empty(), ORIGIN));
        assertTrue(p.allowsFormAction(url("https://example.com/allowed/submit"), ORIGIN, false));

        // host, port and scheme are still checked for a redirect target
        assertFalse(p.allowsFormAction(url("https://evil.example/allowed/done"), ORIGIN, true));
        assertFalse(p.allowsFormAction(url("https://example.com:8443/allowed/done"), ORIGIN, true));
        assertFalse(p.allowsFormAction(url("http://example.com/allowed/done"), ORIGIN, true));

        // unknown url
        assertFalse(p.allowsFormAction(Optional.empty(), ORIGIN, true));
        assertFalse(p.allowsFormAction(Optional.empty(), ORIGIN, false));
    }

    @Test
    public void formActionPerRequestMatchesWholeSubmissionForInitialRequest() {
        final List<String> policies = List.of("form-action https://example.com/allowed/",
                "navigate-to https://example.com/allowed/",
                "navigate-to 'unsafe-allow-redirects' https://example.com/allowed/",
                "form-action 'self'", "form-action 'none'", "img-src 'none'", "sandbox");
        final List<String> urls = List.of("https://example.com/allowed/x", "https://example.com/other/x",
                "https://evil.example/allowed/x");
        for (final String serialized : policies) {
            final Policy p = policy(serialized);
            for (final String u : urls) {
                assertTrue(p.allowsFormAction(url(u), ORIGIN, false)
                        == p.allowsFormAction(url(u), Optional.of(false), Optional.empty(), ORIGIN),
                        serialized + " " + u);
            }
        }
    }

    @Test
    public void formActionPerRequestNavigateToFallback() {
        // without 'unsafe-allow-redirects' navigate-to only checks the submission itself
        final Policy plain = policy("navigate-to https://example.com/allowed/");
        assertTrue(plain.allowsFormAction(url("https://evil.example/x"), ORIGIN, true));
        assertFalse(plain.allowsFormAction(url("https://example.com/other/submit"), ORIGIN, false));

        // with 'unsafe-allow-redirects' redirect targets are checked, without the path
        final Policy redirects = policy("navigate-to 'unsafe-allow-redirects' https://example.com/allowed/");
        assertTrue(redirects.allowsFormAction(url("https://example.com/other/done"), ORIGIN, true));
        assertFalse(redirects.allowsFormAction(url("https://evil.example/allowed/done"), ORIGIN, true));
        assertFalse(redirects.allowsFormAction(url("https://example.com/other/submit"), ORIGIN, false));

        // form-action wins over navigate-to, also for redirects
        final Policy both = policy("form-action https://example.com/allowed/; "
                + "navigate-to 'unsafe-allow-redirects' https://evil.example/");
        assertTrue(both.allowsFormAction(url("https://example.com/other/done"), ORIGIN, true));
        assertFalse(both.allowsFormAction(url("https://evil.example/done"), ORIGIN, true));

        // no directive at all
        assertTrue(policy("img-src 'none'").allowsFormAction(url("https://evil.example/x"), ORIGIN, true));
    }

    @Test
    public void formActionPerRequestPolicyList() {
        final PolicyList l = list("form-action https://example.com/allowed/", "form-action https://example.com/");
        assertTrue(l.allowsFormAction(url("https://example.com/other/done"), ORIGIN, true));
        assertFalse(l.allowsFormAction(url("https://example.com/other/done"), ORIGIN, false));
        assertFalse(list("form-action https://example.com/allowed/", "form-action https://cdn.example/")
                .allowsFormAction(url("https://example.com/other/done"), ORIGIN, true));
    }

    @Test
    public void formActionFallbackToNavigateToIgnoresPathOfRedirectTarget() {
        final Policy p = policy("navigate-to 'unsafe-allow-redirects' https://example.com/allowed/");
        final Optional<URI> start = url("https://example.com/allowed/submit");

        assertTrue(p.allowsFormAction(start, Optional.of(true), url("https://example.com/other/done"), ORIGIN));
        assertFalse(p.allowsFormAction(start, Optional.of(true), url("https://evil.example/allowed/done"), ORIGIN));

        // form-action itself only checks the initial url (it does not follow redirects)
        final Policy formAction = policy("form-action https://example.com/allowed/");
        assertTrue(formAction.allowsFormAction(start, Optional.of(true), url("https://evil.example/x"), ORIGIN));
        assertFalse(formAction.allowsFormAction(url("https://example.com/other/submit"), Optional.of(false),
                Optional.empty(), ORIGIN));
    }
}
