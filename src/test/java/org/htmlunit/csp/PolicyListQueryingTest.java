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

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import org.htmlunit.csp.Policy.PolicyListErrorConsumer;
import org.htmlunit.csp.url.URI;
import org.htmlunit.csp.url.URLWithScheme;
import org.junit.jupiter.api.Test;

/**
 * Multi-policy query-time AND behavior on {@link PolicyList} /
 * {@link PolicyListInOrigin}.
 *
 * @see <a href="https://w3c.github.io/webappsec-csp/#multiple-policies">CSP3 multiple policies</a>
 * @see <a href="https://content-security-policy.com/examples/multiple-csp-headers/">Foundeo examples</a>
 */
public class PolicyListQueryingTest extends TestBase {

    private static final URLWithScheme ORIGIN = URI.parseURI("https://example.com").orElseThrow();

    @Test
    public void ambiguousImgSrcHostsEffectivelyNone() {
        // Content-Security-Policy: img-src img.example.com;
        // Content-Security-Policy: img-src more-images.example.com;
        final PolicyListInOrigin list = ofSerialized(
                List.of("img-src img.example.com", "img-src more-images.example.com"));

        assertFalse(list.allowsImageFromSource(uri("https://img.example.com/a.png")));
        assertFalse(list.allowsImageFromSource(uri("https://more-images.example.com/b.png")));
        assertFalse(list.allowsImageFromSource(uri("https://other.example.com/c.png")));
        assertEquals(2, list.getPolicyList().getPolicies().size());
    }

    @Test
    public void nestedRestrictivenessBlocksExtraHost() {
        // img-src 'self'  AND  img-src 'self' img.example.com  → only 'self' survives
        final PolicyListInOrigin list = ofSerialized(
                List.of("img-src 'self'", "img-src 'self' img.example.com"));

        assertTrue(list.allowsImageFromSource(uri("https://example.com/logo.png")));
        assertFalse(list.allowsImageFromSource(uri("https://img.example.com/a.png")));
    }

    @Test
    public void defaultSrcFallbackAcrossPolicies() {
        // default-src 'self'  AND  img-src 'self' img.example.com
        final PolicyListInOrigin list = ofSerialized(
                List.of("default-src 'self'", "img-src 'self' img.example.com"));

        assertTrue(list.allowsImageFromSource(uri("https://example.com/logo.png")));
        assertFalse(list.allowsImageFromSource(uri("https://img.example.com/a.png")));
    }

    /**
     * Both policies omit the fetch directive, so each falls back to its own
     * {@code default-src}. AND is the overlap of those default-src lists.
     */
    @Test
    public void defaultSrcOverlapWhenBothFallBack() {
        // default-src a.com  ∩  default-src a.com b.com  → only a.com for images
        final PolicyListInOrigin hostOverlap = ofSerialized(List.of(
                "default-src https://a.example.com",
                "default-src https://a.example.com https://b.example.com"));

        assertTrue(hostOverlap.allowsImageFromSource(uri("https://a.example.com/i.png")));
        assertFalse(hostOverlap.allowsImageFromSource(uri("https://b.example.com/i.png")));
        assertTrue(hostOverlap.allowsScriptFromSource(uri("https://a.example.com/app.js")));
        assertFalse(hostOverlap.allowsScriptFromSource(uri("https://b.example.com/app.js")));

        // Asymmetric: one side only 'self', other allows a third-party via default-src
        final PolicyListInOrigin asymmetric = ofSerialized(List.of(
                "default-src 'self'",
                "default-src 'self' https://cdn.example.com"));

        assertTrue(asymmetric.allowsFontFromSource(uri("https://example.com/f.woff2")));
        assertFalse(asymmetric.allowsFontFromSource(uri("https://cdn.example.com/f.woff2")));

        // Both default-src 'none' → nothing allowed for fetch types that fall back
        final PolicyListInOrigin bothNone = ofSerialized(List.of(
                "default-src 'none'",
                "default-src 'none'"));

        assertFalse(bothNone.allowsImageFromSource(uri("https://example.com/i.png")));
        assertFalse(bothNone.allowsScriptFromSource(uri("https://example.com/app.js")));
        assertFalse(bothNone.allowsConnection(uri("https://example.com/api")));
    }

    @Test
    public void orderDoesNotMatter() {
        final PolicyListInOrigin aThenB = ofSerialized(
                List.of("img-src img.example.com", "img-src more-images.example.com"));
        final PolicyListInOrigin bThenA = ofSerialized(
                List.of("img-src more-images.example.com", "img-src img.example.com"));

        final URLWithScheme img = uri("https://img.example.com/a.png");
        final URLWithScheme more = uri("https://more-images.example.com/b.png");
        assertEquals(aThenB.allowsImageFromSource(img), bThenA.allowsImageFromSource(img));
        assertEquals(aThenB.allowsImageFromSource(more), bThenA.allowsImageFromSource(more));
    }

    @Test
    public void overlappingHostsAllowed() {
        final PolicyListInOrigin list = ofSerialized(
                List.of("img-src https://cdn.example.com", "img-src https://cdn.example.com https://other.example.com"));

        assertTrue(list.allowsImageFromSource(uri("https://cdn.example.com/a.png")));
        assertFalse(list.allowsImageFromSource(uri("https://other.example.com/a.png")));
    }

    @Test
    public void emptyListAllowsEverything() {
        final PolicyList empty = new PolicyList(Collections.emptyList());
        assertTrue(empty.allowsImage(Optional.of(uri("https://anywhere.example/x")), Optional.of(ORIGIN)));
        assertTrue(empty.allowsEval());
        assertTrue(new PolicyListInOrigin(empty, ORIGIN).allowsUnsafeInlineScript());
        assertThrows(UnsupportedOperationException.class,
                () -> empty.getPolicies().add(Policy.parseSerializedCSP("default-src 'none'",
                        Policy.PolicyErrorConsumer.ignored)));
    }

    @Test
    public void ofSerializedParsesCommaSeparatedHeaderValues() {
        // One header value that is itself a CSP list, plus another header
        final PolicyList list = PolicyList.ofSerialized(
                List.of("img-src a.example, script-src 'none'", "connect-src 'self'"),
                PolicyListErrorConsumer.ignored);

        assertEquals(3, list.getPolicies().size());
    }

    @Test
    public void unsafeInlineRequiresAllPolicies() {
        final PolicyListInOrigin bothAllow = ofSerialized(
                List.of("script-src 'unsafe-inline'", "default-src 'unsafe-inline'"));
        assertTrue(bothAllow.allowsUnsafeInlineScript());

        final PolicyListInOrigin oneBlocks = ofSerialized(
                List.of("script-src 'unsafe-inline'", "script-src 'none'"));
        assertFalse(oneBlocks.allowsUnsafeInlineScript());
    }

    @Test
    public void allowsEvalRequiresAllPolicies() {
        final PolicyList bothAllow = PolicyList.ofSerialized(
                List.of("script-src 'unsafe-eval'", "default-src 'unsafe-eval'"),
                PolicyListErrorConsumer.ignored);
        assertTrue(bothAllow.allowsEval());

        final PolicyList oneBlocks = PolicyList.ofSerialized(
                List.of("script-src 'unsafe-eval'", "script-src 'none'"),
                PolicyListErrorConsumer.ignored);
        assertFalse(oneBlocks.allowsEval());
    }

    @Test
    public void parseSerializedCSPListAlsoAnds() {
        final PolicyList list = Policy.parseSerializedCSPList(
                "img-src img.example.com, img-src more-images.example.com",
                PolicyListErrorConsumer.ignored);
        final PolicyListInOrigin bound = new PolicyListInOrigin(list, ORIGIN);

        assertFalse(bound.allowsImageFromSource(uri("https://img.example.com/a.png")));
        assertFalse(bound.allowsImageFromSource(uri("https://more-images.example.com/b.png")));
    }

    /**
     * Typical SaaS baseline (self + CDNs + analytics) plus a second edge/WAF header that
     * drops third-party scripts and connections.
     */
    @Test
    public void saasBaselineTightenedByEdgeHeader() {
        final String appPolicy = String.join(" ",
                "default-src 'self';",
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://www.googletagmanager.com;",
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;",
                "font-src 'self' https://fonts.gstatic.com data:;",
                "img-src 'self' data: https: blob:;",
                "connect-src 'self' https://api.example.com https://www.google-analytics.com;",
                "frame-src 'self' https://js.stripe.com;",
                "object-src 'none';",
                "base-uri 'self';",
                "form-action 'self';",
                "frame-ancestors 'self';",
                "upgrade-insecure-requests");

        final String edgeTighten = String.join(" ",
                "default-src 'self';",
                "script-src 'self';",
                "style-src 'self' 'unsafe-inline';",
                "font-src 'self' data:;",
                "img-src 'self' data: https:;",
                "connect-src 'self' https://api.example.com;",
                "frame-src 'self';",
                "object-src 'none';",
                "base-uri 'self';",
                "form-action 'self';",
                "frame-ancestors 'self'");

        final PolicyListInOrigin list = ofSerializedIgnored(List.of(appPolicy, edgeTighten));

        assertTrue(list.allowsScriptFromSource(uri("https://example.com/app.js")));
        assertFalse(list.allowsScriptFromSource(uri("https://cdn.jsdelivr.net/npm/vue@3/dist/vue.global.js")));
        assertFalse(list.allowsScriptFromSource(uri("https://www.googletagmanager.com/gtm.js")));
        assertTrue(list.allowsConnection(uri("https://api.example.com/v1/users")));
        assertFalse(list.allowsConnection(uri("https://www.google-analytics.com/g/collect")));
        assertFalse(list.allowsFrameFromSource(uri("https://js.stripe.com/v3/")));
        assertTrue(list.allowsImageFromSource(uri("https://cdn.example.net/hero.webp")));
        assertFalse(list.allowsUnsafeInlineScript());
        assertTrue(list.allowsUnsafeInlineStyle());
        assertFalse(list.allowsEval());
    }

    /**
     * Marketing stack (GTM / GA / fonts) intersected with a stricter product policy that
     * only permits first-party scripts — common when product and marketing CSPs both ship.
     */
    @Test
    public void marketingStackIntersectedWithProductLockdown() {
        final String marketing = String.join(" ",
                "default-src 'none';",
                "script-src 'self' https://www.googletagmanager.com https://www.google-analytics.com"
                        + " https://tagmanager.google.com 'unsafe-inline';",
                "style-src 'self' https://fonts.googleapis.com https://tagmanager.google.com 'unsafe-inline';",
                "font-src 'self' https://fonts.gstatic.com data:;",
                "img-src 'self' data: https://www.google-analytics.com https://www.googletagmanager.com"
                        + " https://*.googleusercontent.com;",
                "connect-src 'self' https://www.google-analytics.com https://analytics.google.com"
                        + " https://stats.g.doubleclick.net;",
                "frame-src https://www.googletagmanager.com;");

        final String product = String.join(" ",
                "default-src 'self';",
                "script-src 'self';",
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;",
                "font-src 'self' https://fonts.gstatic.com;",
                "img-src 'self' data: https:;",
                "connect-src 'self';",
                "frame-src 'none';",
                "object-src 'none'");

        final PolicyListInOrigin list = ofSerializedIgnored(List.of(marketing, product));

        assertTrue(list.allowsScriptFromSource(uri("https://example.com/bundle.js")));
        assertFalse(list.allowsScriptFromSource(uri("https://www.googletagmanager.com/gtm.js")));
        assertTrue(list.allowsStyleFromSource(uri("https://fonts.googleapis.com/css2?family=Inter")));
        assertTrue(list.allowsFontFromSource(uri("https://fonts.gstatic.com/s/inter/v12/font.woff2")));
        assertFalse(list.allowsConnection(uri("https://www.google-analytics.com/g/collect")));
        assertFalse(list.allowsFrameFromSource(uri("https://www.googletagmanager.com/ns.html")));
        assertFalse(list.allowsUnsafeInlineScript());
        assertTrue(list.allowsUnsafeInlineStyle());
    }

    /**
     * Enforce header + page meta policy (meta often used for app-generated directives).
     * Intersection still applies; {@code report-uri} / {@code frame-ancestors} only on
     * the header policy (and meta is parsed with {@code deliveredViaMeta = true}).
     */
    @Test
    public void headerPlusMetaDualDelivery() {
        final String headerText = String.join(" ",
                "default-src 'self';",
                "script-src 'self' https://cdn.example.com;",
                "img-src 'self' https://images.example.com;",
                "connect-src 'self';",
                "frame-ancestors 'none';",
                "report-uri /csp-report");

        final String metaText = String.join(" ",
                "default-src 'self';",
                "script-src 'self';",
                "img-src 'self' https://images.example.com https://cdn.example.com;",
                "connect-src 'self' https://api.example.com");

        final Policy header = Policy.parseSerializedCSP(
                headerText, Policy.PolicyErrorConsumer.ignored, false);
        final Policy meta = Policy.parseSerializedCSP(
                metaText, Policy.PolicyErrorConsumer.ignored, true);
        assertTrue(meta.deliveredViaMeta());
        assertFalse(header.deliveredViaMeta());

        final PolicyListInOrigin list = new PolicyListInOrigin(
                new PolicyList(List.of(header, meta)), ORIGIN);

        assertTrue(list.allowsScriptFromSource(uri("https://example.com/main.js")));
        assertFalse(list.allowsScriptFromSource(uri("https://cdn.example.com/vendor.js")));
        assertTrue(list.allowsImageFromSource(uri("https://images.example.com/a.png")));
        assertFalse(list.allowsImageFromSource(uri("https://cdn.example.com/b.png")));
        assertFalse(list.allowsConnection(uri("https://api.example.com/x")));
        assertFalse(list.allowsFrameAncestor(uri("https://evil.example/")));
        assertFalse(list.allowsFrameAncestor(uri("https://example.com/")));
    }

    /**
     * {@code navigate-to} / {@code javascript:} URL navigation must pass every policy.
     */
    @Test
    public void navigationAndJavascriptUrlRequireAllPolicies() {
        final PolicyListInOrigin nav = ofSerialized(List.of(
                "navigate-to https://a.example.com",
                "navigate-to https://a.example.com https://b.example.com"));

        assertTrue(nav.allowsNavigation(uri("https://a.example.com/page")));
        assertFalse(nav.allowsNavigation(uri("https://b.example.com/page")));
        assertFalse(nav.allowsNavigation(uri("https://c.example.com/page")));

        final PolicyList bothAllowJs = PolicyList.ofSerialized(
                List.of(
                        "script-src 'unsafe-inline'; navigate-to javascript:",
                        "default-src 'unsafe-inline'; navigate-to javascript:"),
                PolicyListErrorConsumer.ignored);
        assertTrue(bothAllowJs.allowsJavascriptUrlNavigation(
                Optional.of("alert(1)"), Optional.of(ORIGIN)));

        final PolicyList oneBlocksJs = PolicyList.ofSerialized(
                List.of(
                        "script-src 'unsafe-inline'; navigate-to javascript:",
                        "navigate-to 'none'"),
                PolicyListErrorConsumer.ignored);
        assertFalse(oneBlocksJs.allowsJavascriptUrlNavigation(
                Optional.of("alert(1)"), Optional.of(ORIGIN)));
    }

    /**
     * Meta {@code frame-ancestors} / {@code sandbox} are ignored for query; header
     * copies still AND. Fetch directives on the meta policy still participate.
     */
    @Test
    public void headerPlusMetaIgnoresMetaInvalidDirectivesForQuery() {
        final Policy header = Policy.parseSerializedCSP(
                "default-src 'self'; frame-ancestors 'none'", Policy.PolicyErrorConsumer.ignored, false);
        final Policy meta = Policy.parseSerializedCSP(
                "script-src 'self'; frame-ancestors 'none'; sandbox",
                Policy.PolicyErrorConsumer.ignored, true);

        final PolicyListInOrigin list = new PolicyListInOrigin(
                new PolicyList(List.of(header, meta)), ORIGIN);

        // Meta sandbox does not block scripts; both policies allow 'self' scripts
        assertTrue(list.allowsScriptFromSource(uri("https://example.com/app.js")));
        assertFalse(list.allowsScriptFromSource(uri("https://cdn.example.com/x.js")));

        // Header frame-ancestors 'none' still blocks; meta's copy is ignored for query
        assertFalse(list.allowsFrameAncestor(uri("https://evil.example/")));
        assertFalse(list.allowsFrameAncestor(uri("https://example.com/")));

        // Meta-only invalid directives: no header frame-ancestors → allow ancestors;
        // meta sandbox does not block forms/scripts by itself
        final Policy headerFetchOnly = Policy.parseSerializedCSP(
                "script-src 'self'", Policy.PolicyErrorConsumer.ignored, false);
        final PolicyListInOrigin metaFaOnly = new PolicyListInOrigin(
                new PolicyList(List.of(headerFetchOnly, meta)), ORIGIN);
        assertTrue(metaFaOnly.allowsFrameAncestor(uri("https://evil.example/")));
        assertTrue(metaFaOnly.allowsScriptFromSource(uri("https://example.com/app.js")));
        assertTrue(metaFaOnly.allowsFormAction(uri("https://example.com/submit")));
    }

    /**
     * Busy multi-CDN allowlists with only partial host overlap across two headers.
     */
    @Test
    public void multiCdnAllowlistsPartialOverlap() {
        final String policyA = String.join(" ",
                "default-src 'none';",
                "script-src 'self' https://cdn.jsdelivr.net https://unpkg.com https://cdnjs.cloudflare.com;",
                "style-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com;",
                "font-src https://fonts.gstatic.com https://cdn.jsdelivr.net;",
                "img-src 'self' https://cdn.jsdelivr.net data: blob:;",
                "worker-src 'self' blob:;");

        final String policyB = String.join(" ",
                "default-src 'none';",
                "script-src 'self' https://cdn.jsdelivr.net https://static.cloudflareinsights.com;",
                "style-src 'self' https://fonts.googleapis.com;",
                "font-src https://fonts.gstatic.com;",
                "img-src 'self' data:;",
                "worker-src 'self';");

        final PolicyListInOrigin list = ofSerializedIgnored(List.of(policyA, policyB));

        assertTrue(list.allowsScriptFromSource(uri("https://cdn.jsdelivr.net/npm/lodash@4/lodash.min.js")));
        assertFalse(list.allowsScriptFromSource(uri("https://unpkg.com/react@18/umd/react.production.min.js")));
        assertFalse(list.allowsScriptFromSource(uri("https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js")));
        assertFalse(list.allowsScriptFromSource(uri("https://static.cloudflareinsights.com/beacon.min.js")));
        assertTrue(list.allowsStyleFromSource(uri("https://fonts.googleapis.com/css?family=Roboto")));
        assertFalse(list.allowsStyleFromSource(uri("https://cdn.jsdelivr.net/npm/bootstrap@5/dist/css/bootstrap.min.css")));
        assertTrue(list.allowsFontFromSource(uri("https://fonts.gstatic.com/s/roboto/v30/font.woff2")));
        assertFalse(list.allowsImageFromSource(uri("https://cdn.jsdelivr.net/gh/foo/bar/logo.png")));
        assertTrue(list.allowsWorkerFromSource(uri("https://example.com/sw.js")));
        assertFalse(list.allowsWorkerFromSource(uri("https://cdn.jsdelivr.net/worker.js")));
    }

    /**
     * Wildcard host in one policy, concrete host in the other — intersection is hosts that
     * match the wildcard <em>and</em> appear (or are covered) in the second policy.
     */
    @Test
    public void wildcardHostIntersectConcreteHosts() {
        final PolicyListInOrigin list = ofSerializedIgnored(List.of(
                "script-src https://*.example.net https://cdn.partner.com",
                "script-src https://assets.example.net https://cdn.partner.com https://extra.example.net"));

        assertTrue(list.allowsScriptFromSource(uri("https://assets.example.net/app.js")));
        assertTrue(list.allowsScriptFromSource(uri("https://cdn.partner.com/lib.js")));
        assertTrue(list.allowsScriptFromSource(uri("https://extra.example.net/x.js")));
        assertFalse(list.allowsScriptFromSource(uri("https://other.example.net/x.js")));
        assertFalse(list.allowsScriptFromSource(uri("https://cdn.other.com/x.js")));
    }

    /**
     * Two host-source wildcards AND'd: a URL must match <em>both</em> patterns.
     * Nested wildcards share hosts in the overlap; disjoint wildcards allow nothing.
     */
    @Test
    public void wildcardHostIntersectWildcardHost() {
        // Nested: *.cdn.example.com ⊂ *.example.com (for matching purposes)
        final PolicyListInOrigin nested = ofSerializedIgnored(List.of(
                "script-src https://*.example.com",
                "script-src https://*.cdn.example.com"));

        assertTrue(nested.allowsScriptFromSource(uri("https://assets.cdn.example.com/app.js")));
        assertTrue(nested.allowsScriptFromSource(uri("https://a.b.cdn.example.com/x.js")));
        assertFalse(nested.allowsScriptFromSource(uri("https://www.example.com/app.js")));
        assertFalse(nested.allowsScriptFromSource(uri("https://cdn.example.com/app.js")));
        assertFalse(nested.allowsScriptFromSource(uri("https://other.example.net/app.js")));

        // Disjoint registrable domains → no host satisfies both
        final PolicyListInOrigin disjoint = ofSerializedIgnored(List.of(
                "img-src https://*.example.com",
                "img-src https://*.example.net"));

        assertFalse(disjoint.allowsImageFromSource(uri("https://a.example.com/i.png")));
        assertFalse(disjoint.allowsImageFromSource(uri("https://a.example.net/i.png")));
        assertFalse(disjoint.allowsImageFromSource(uri("https://a.example.org/i.png")));

        // Scheme-part-match: http source allows https URL; https source does not allow http URL
        final PolicyListInOrigin schemeAndHost = ofSerializedIgnored(List.of(
                "script-src https://*.assets.example.com",
                "script-src http://*.assets.example.com"));

        assertTrue(schemeAndHost.allowsScriptFromSource(uri("https://cdn.assets.example.com/lib.js")));
        assertFalse(schemeAndHost.allowsScriptFromSource(uri("http://cdn.assets.example.com/lib.js")));

        // https://* ∩ https://*.partner.com
        final PolicyListInOrigin starScheme = ofSerializedIgnored(List.of(
                "script-src https://*",
                "script-src https://*.partner.com"));

        assertTrue(starScheme.allowsScriptFromSource(uri("https://cdn.partner.com/a.js")));
        assertFalse(starScheme.allowsScriptFromSource(uri("https://cdn.other.com/a.js")));
        assertFalse(starScheme.allowsScriptFromSource(uri("http://cdn.partner.com/a.js")));
    }

    /**
     * Three policies (primary app, payment iframe vendor allowlist, reporting/monitoring
     * lockdown) — resource must pass all three.
     */
    @Test
    public void threeLayerCorporatePolicies() {
        final String app = String.join(" ",
                "default-src 'self';",
                "script-src 'self' https://js.stripe.com https://checkout.paypal.com;",
                "frame-src 'self' https://js.stripe.com https://hooks.stripe.com https://www.paypal.com;",
                "connect-src 'self' https://api.stripe.com https://api.paypal.com;",
                "img-src 'self' data: https:;",
                "style-src 'self' 'unsafe-inline';",
                "object-src 'none'");

        final String paymentsOnly = String.join(" ",
                "default-src 'none';",
                "script-src 'self' https://js.stripe.com;",
                "frame-src https://js.stripe.com https://hooks.stripe.com;",
                "connect-src 'self' https://api.stripe.com;",
                "img-src 'self' data:;",
                "style-src 'self' 'unsafe-inline';",
                "object-src 'none'");

        final String monitor = "default-src 'self'; script-src 'self'; connect-src 'self'; frame-src 'self'; object-src 'none'";

        final PolicyListInOrigin list = ofSerializedIgnored(List.of(app, paymentsOnly, monitor));

        assertTrue(list.allowsScriptFromSource(uri("https://example.com/checkout.js")));
        assertFalse(list.allowsScriptFromSource(uri("https://js.stripe.com/v3/")));
        assertFalse(list.allowsScriptFromSource(uri("https://checkout.paypal.com/js")));
        assertFalse(list.allowsFrameFromSource(uri("https://js.stripe.com/v3/")));
        assertFalse(list.allowsConnection(uri("https://api.stripe.com/v1/tokens")));
        assertTrue(list.allowsConnection(uri("https://example.com/api/order")));
        // monitor falls back to default-src 'self' for style → no 'unsafe-inline'
        assertFalse(list.allowsUnsafeInlineStyle());
        assertFalse(list.allowsUnsafeInlineScript());
    }

    /**
     * Host / scheme matching is ASCII case-insensitive across separately parsed policies
     * (CSP3 host-part / scheme-part match). Differently cased hosts in two policies still
     * share an intersection — Path A never merges strings, so Salvation #120-style case
     * loss on intersect does not apply.
     */
    @Test
    public void hostCaseInsensitiveAcrossPolicies() {
        final PolicyListInOrigin list = ofSerializedIgnored(List.of(
                "img-src https://CDN.Example.COM",
                "img-src HTTPS://cdn.example.com"));

        assertTrue(list.allowsImageFromSource(uri("https://cdn.example.com/a.png")));
        assertTrue(list.allowsImageFromSource(uri("https://CDN.EXAMPLE.COM/a.png")));
        assertTrue(list.allowsImageFromSource(uri("HTTPS://CdN.ExAmPlE.cOm/a.png")));
        assertFalse(list.allowsImageFromSource(uri("https://other.example.com/a.png")));
    }

    /**
     * Path matching is case-sensitive. Same path casing in both policies allows that path;
     * mismatched path casing across policies yields empty intersection for those URLs.
     */
    @Test
    public void pathCaseSensitiveAcrossPolicies() {
        final PolicyListInOrigin sameCase = ofSerializedIgnored(List.of(
                "script-src https://cdn.example.com/App/",
                "script-src https://cdn.example.com/App/ https://cdn.example.com/other/"));

        assertTrue(sameCase.allowsScriptFromSource(uri("https://cdn.example.com/App/x.js")));
        assertFalse(sameCase.allowsScriptFromSource(uri("https://cdn.example.com/app/x.js")));
        assertFalse(sameCase.allowsScriptFromSource(uri("https://cdn.example.com/other/x.js")));

        // /App/ ∩ /app/ — no URL path satisfies both (case-sensitive)
        final PolicyListInOrigin mismatchedCase = ofSerializedIgnored(List.of(
                "script-src https://cdn.example.com/App/",
                "script-src https://cdn.example.com/app/"));

        assertFalse(mismatchedCase.allowsScriptFromSource(uri("https://cdn.example.com/App/x.js")));
        assertFalse(mismatchedCase.allowsScriptFromSource(uri("https://cdn.example.com/app/x.js")));
    }

    /**
     * Invalid {@code 'none' host} in one directive: parse reports an error, but the host
     * expression still participates in matching (same as single-policy query behavior).
     * Under AND, a pure {@code 'none'} sibling policy still blocks.
     */
    @Test
    public void noneCombinedWithHostUnderAnd() {
        // Garbage directive alone (via PolicyList of one) still allows the host
        final PolicyListInOrigin garbageAlone = ofSerializedIgnored(List.of(
                "script-src 'none' https://cdn.example.com"));
        assertTrue(garbageAlone.allowsScriptFromSource(uri("https://cdn.example.com/a.js")));
        assertFalse(garbageAlone.allowsScriptFromSource(uri("https://other.example.com/a.js")));

        // Overlap with a second policy that also lists the host → allow
        final PolicyListInOrigin overlap = ofSerializedIgnored(List.of(
                "script-src 'none' https://cdn.example.com",
                "script-src https://cdn.example.com https://other.example.com"));
        assertTrue(overlap.allowsScriptFromSource(uri("https://cdn.example.com/a.js")));
        assertFalse(overlap.allowsScriptFromSource(uri("https://other.example.com/a.js")));

        // Pure 'none' in the other policy → block everything
        final PolicyListInOrigin noneSibling = ofSerializedIgnored(List.of(
                "script-src 'none' https://cdn.example.com",
                "script-src 'none'"));
        assertFalse(noneSibling.allowsScriptFromSource(uri("https://cdn.example.com/a.js")));
    }

    /**
     * Nonce present in both policies allows inline; second policy without the nonce blocks
     * even if the first would allow via nonce.
     */
    @Test
    public void nonceMustSatisfyEveryPolicy() {
        final PolicyList both = PolicyList.ofSerialized(
                List.of(
                        "script-src 'nonce-abc123' 'strict-dynamic'",
                        "script-src 'nonce-abc123' https://cdn.example.com"),
                PolicyListErrorConsumer.ignored);
        assertTrue(both.allowsInlineScript(
                Optional.of("abc123"), Optional.of("console.log(1)"), Optional.of(false)));

        final PolicyList mismatched = PolicyList.ofSerialized(
                List.of(
                        "script-src 'nonce-abc123'",
                        "script-src 'nonce-other'"),
                PolicyListErrorConsumer.ignored);
        assertFalse(mismatched.allowsInlineScript(
                Optional.of("abc123"), Optional.of("console.log(1)"), Optional.of(false)));
        assertFalse(mismatched.allowsInlineScript(
                Optional.of("other"), Optional.of("console.log(1)"), Optional.of(false)));
    }

    private static PolicyListInOrigin ofSerialized(final List<String> values) {
        return new PolicyListInOrigin(
                PolicyList.ofSerialized(values, ThrowIfPolicyListError), ORIGIN);
    }

    private static PolicyListInOrigin ofSerializedIgnored(final List<String> values) {
        return new PolicyListInOrigin(
                PolicyList.ofSerialized(values, PolicyListErrorConsumer.ignored), ORIGIN);
    }

    private static URLWithScheme uri(final String url) {
        return URI.parseURI(url).orElseThrow();
    }
}
