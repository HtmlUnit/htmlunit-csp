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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;
import java.util.function.Supplier;

import org.htmlunit.csp.directive.FrameAncestorsDirective;
import org.htmlunit.csp.directive.PluginTypesDirective;
import org.htmlunit.csp.directive.ReportUriDirective;
import org.htmlunit.csp.directive.SandboxDirective;
import org.htmlunit.csp.directive.SourceExpressionDirective;
import org.htmlunit.csp.value.RFC7230Token;
import org.junit.jupiter.api.Test;

public class HighLevelPolicyManipulationTest extends TestBase {
    private final class SourceDirectiveKind {
        private final String repr_;
        private final Function<Policy, SourceExpressionDirective> get_;

        private SourceDirectiveKind(final String repr, final Function<Policy, SourceExpressionDirective> get) {
            repr_ = repr;
            get_ = get;
        }
    }

    /*
// TODO we'll need more tests for using the generic parser for schemes, hosts, nonces, hashes
// and specific cases for their parsers

\             'http:'
 'FILE:'
 'example.com'
    case-insensitivity of hosts (maybe)
    default port thing
 'example.com/foo'
    case-sensitivity of paths
 'nonce-asdf'
    duplicate nonce
    non-base64 nonce
 hash
    duplicate hash
    unrecognized hash
    hash which is not base64
    hash whose length is inappropriate for its algorithm

\             not-a-host-source
 @
    case-sensitivity of these

 */

    @Test
    public void testSourceExpressionDirectives() {
        inTurkey(() -> {
            final List<SourceDirectiveKind> directives = new ArrayList<>();
            directives.add(new SourceDirectiveKind(
                "base-uri",
                p -> p.baseUri().get()
            ));
            directives.add(new SourceDirectiveKind(
                "form-action",
                p -> p.formAction().get()
            ));
            directives.add(new SourceDirectiveKind(
                "navigate-to",
                p -> p.navigateTo().get()
            ));
            for (final FetchDirectiveKind kind : FetchDirectiveKind.values()) {
                directives.add(new SourceDirectiveKind(kind.getRepr(), p -> p.getFetchDirective(kind).get()));
            }

            for (final SourceDirectiveKind kind : directives) {
                final String none = "'NoNe'";
                final Policy p = Policy.parseSerializedCSP(kind.repr_ + " " + none, throwIfPolicyError_);
                final SourceExpressionDirective d = kind.get_.apply(p);

                final ArrayList<Supplier<Boolean>> assertions = new ArrayList<>();

                final Runnable assertAll = () -> {
                    for (final Supplier<Boolean> assertion : assertions) {
                        assertTrue(assertion.get());
                    }
                };

                final Supplier<Boolean> notStar = () -> !d.star();
                assertions.add(notStar);

                final Supplier<Boolean> notSelf = () -> !d.self();
                assertions.add(notSelf);

                final Supplier<Boolean> schemesIsEmpty = () -> d.getSchemes().isEmpty();
                assertions.add(schemesIsEmpty);

                final Supplier<Boolean> hostsIsEmpty = () -> d.getHosts().isEmpty();
                assertions.add(hostsIsEmpty);

                final Supplier<Boolean> notUnsafeInline = () -> !d.unsafeInline();
                assertions.add(notUnsafeInline);

                final Supplier<Boolean> notUnsafeEval = () -> !d.unsafeEval();
                assertions.add(notUnsafeEval);

                final Supplier<Boolean> notStrictDynamic = () -> !d.strictDynamic();
                assertions.add(notStrictDynamic);

                final Supplier<Boolean> notUnsafeHashes = () -> !d.unsafeHashes();
                assertions.add(notUnsafeHashes);

                final Supplier<Boolean> notReportSample = () -> !d.reportSample();
                assertions.add(notReportSample);

                final Supplier<Boolean> notUnsafeAllowRedirects = () -> !d.unsafeAllowRedirects();
                assertions.add(notUnsafeAllowRedirects);

                final Supplier<Boolean> noncesIsEmpty = () -> d.getNonces().isEmpty();
                assertions.add(noncesIsEmpty);

                final Supplier<Boolean> hashesIsEmpty = () -> d.getHashes().isEmpty();
                assertions.add(hashesIsEmpty);

                // 'none'
                assertAll.run();

                // casing of 'none' is preserved when no manipulation occurs
                assertEquals(kind.repr_ + " " + none, p.toString());
            }
        });
    }

    @Test
    public void testFrameAncestorsDirective() {
        inTurkey(() -> {
            final String none = "'NoNe'";
            final Policy p = Policy.parseSerializedCSP("frame-ancestors " + none, throwIfPolicyError_);
            assertTrue(p.frameAncestors().isPresent());
            final FrameAncestorsDirective d = p.frameAncestors().get();

            final ArrayList<Supplier<Boolean>> assertions = new ArrayList<>();

            final Runnable assertAll = () -> {
                for (final Supplier<Boolean> assertion : assertions) {
                    assertTrue(assertion.get());
                }
            };

            final Supplier<Boolean> notStar = () -> !d.star();
            assertions.add(notStar);

            final Supplier<Boolean> notSelf = () -> !d.self();
            assertions.add(notSelf);

            final Supplier<Boolean> schemesIsEmpty = () -> d.getSchemes().isEmpty();
            assertions.add(schemesIsEmpty);

            final Supplier<Boolean> hostsIsEmpty = () -> d.getHosts().isEmpty();
            assertions.add(hostsIsEmpty);

            // 'none'
            assertAll.run();

            // casing of 'none' is preserved when no manipulation occurs
            assertEquals("frame-ancestors " + none, p.toString());
        });
    }

    @Test
    public void testPluginTypesDirective() {
        inTurkey(() -> {
            final Policy p = Policy.parseSerializedCSP("plugin-types", throwIfPolicyError_);
            final PluginTypesDirective d = p.pluginTypes().get();

            assertTrue(d.getMediaTypes().isEmpty());
            assertEquals("plugin-types", p.toString());
        });
    }

    @Test
    public void testReportUriDirective() {
        inTurkey(() -> {
            final Policy p = Policy.parseSerializedCSP("report-uri http://example.com", Policy.PolicyErrorConsumer.ignored);
            final ReportUriDirective d = p.reportUri().get();

            assertEquals(Arrays.asList("http://example.com"), d.getUris());
            assertEquals("report-uri http://example.com", p.toString());
        });
    }

    @Test
    public void testSandboxDirective() {
        inTurkey(() -> {
            final Policy p = Policy.parseSerializedCSP("sandbox", throwIfPolicyError_);
            final SandboxDirective d = p.sandbox().get();

            assertFalse(d.allowDownloads());
            assertFalse(d.allowForms());
            assertFalse(d.allowModals());
            assertFalse(d.allowOrientationLock());
            assertFalse(d.allowPointerLock());
            assertFalse(d.allowPopups());
            assertFalse(d.allowPopupsToEscapeSandbox());
            assertFalse(d.allowPresentation());
            assertFalse(d.allowSameOrigin());
            assertFalse(d.allowScripts());
            assertFalse(d.allowStorageAccessByUserActivation());
            assertFalse(d.allowTopNavigation());
            assertFalse(d.allowTopNavigationByUserActivation());
            assertEquals("sandbox", p.toString());

        });
    }

    @Test
    public void testReportToDirective() {
        Policy p = Policy.parseSerializedCSP("", throwIfPolicyError_);

        // Setting overwrites existing
        p = Policy.parseSerializedCSP("report-to a", Policy.PolicyErrorConsumer.ignored);
        assertEquals(rfc7230Token("a"), p.reportTo().get());
        assertEquals("report-to a", p.toString());

        // Only the first directive is overwritten
        p = Policy.parseSerializedCSP("report-to a; report-to b", Policy.PolicyErrorConsumer.ignored);
        assertEquals(rfc7230Token("a"), p.reportTo().get());
        assertEquals("report-to a; report-to b", p.toString());

        // Malformed values are overwritten
        p = Policy.parseSerializedCSP("report-to a b; default-src *", Policy.PolicyErrorConsumer.ignored);
        assertFalse(p.reportTo().isPresent());
        assertEquals("report-to a b; default-src *", p.toString());

        p = Policy.parseSerializedCSP("report-to; default-src *", Policy.PolicyErrorConsumer.ignored);
        assertFalse(p.reportTo().isPresent());
        assertEquals("report-to; default-src *", p.toString());
    }

    @Test
    public void testBooleanDirectives() {
        final Policy p = Policy.parseSerializedCSP("", throwIfPolicyError_);
        assertFalse(p.blockAllMixedContent());
        assertFalse(p.upgradeInsecureRequests());

        p.setBlockAllMixedContent(true);
        assertTrue(p.blockAllMixedContent());
        assertFalse(p.upgradeInsecureRequests());
        assertEquals("block-all-mixed-content", p.toString());

        p.setBlockAllMixedContent(true);
        assertTrue(p.blockAllMixedContent());
        assertFalse(p.upgradeInsecureRequests());
        assertEquals("block-all-mixed-content", p.toString());

        p.setUpgradeInsecureRequests(true);
        assertTrue(p.blockAllMixedContent());
        assertTrue(p.upgradeInsecureRequests());
        assertEquals("block-all-mixed-content; upgrade-insecure-requests", p.toString());

        p.setUpgradeInsecureRequests(true);
        assertTrue(p.blockAllMixedContent());
        assertTrue(p.upgradeInsecureRequests());
        assertEquals("block-all-mixed-content; upgrade-insecure-requests", p.toString());

        p.setBlockAllMixedContent(false);
        assertFalse(p.blockAllMixedContent());
        assertTrue(p.upgradeInsecureRequests());
        assertEquals("upgrade-insecure-requests", p.toString());

        p.setBlockAllMixedContent(false);
        assertFalse(p.blockAllMixedContent());
        assertTrue(p.upgradeInsecureRequests());
        assertEquals("upgrade-insecure-requests", p.toString());

        p.setUpgradeInsecureRequests(false);
        assertFalse(p.blockAllMixedContent());
        assertFalse(p.upgradeInsecureRequests());
        assertEquals("", p.toString());

        p.setUpgradeInsecureRequests(false);
        assertFalse(p.blockAllMixedContent());
        assertFalse(p.upgradeInsecureRequests());
        assertEquals("", p.toString());
    }

    @Test
    public void testWarnings() {
        inTurkey(() -> {
            final Policy p = Policy.parseSerializedCSP("default-src *", throwIfPolicyError_);
            final SourceExpressionDirective d = p.getFetchDirective(FetchDirectiveKind.DefaultSrc).get();

//            d.addHost(Host.parseHost("*").get(), manipulationErrorConsumer);
//            assertErrors(
//                    e(Directive.ManipulationErrorConsumer.Severity.Warning, "Duplicate host *")
//            );
        });
    }

    private RFC7230Token rfc7230Token(final String token) {
        return RFC7230Token.parseRFC7230Token(token).get();
    }
}
