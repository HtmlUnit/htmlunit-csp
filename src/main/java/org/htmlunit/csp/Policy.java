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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.EnumMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;

import org.htmlunit.csp.directive.FrameAncestorsDirective;
import org.htmlunit.csp.directive.HostSourceDirective;
import org.htmlunit.csp.directive.PluginTypesDirective;
import org.htmlunit.csp.directive.ReportUriDirective;
import org.htmlunit.csp.directive.RequireTrustedTypesForDirective;
import org.htmlunit.csp.directive.SandboxDirective;
import org.htmlunit.csp.directive.SourceExpressionDirective;
import org.htmlunit.csp.directive.TrustedTypesDirective;
import org.htmlunit.csp.url.GUID;
import org.htmlunit.csp.url.URI;
import org.htmlunit.csp.url.URLWithScheme;
import org.htmlunit.csp.value.Hash;
import org.htmlunit.csp.value.Host;
import org.htmlunit.csp.value.MediaType;
import org.htmlunit.csp.value.RFC7230Token;
import org.htmlunit.csp.value.Scheme;

/**
 * Represents a single parsed Content Security Policy.
 * <p>
 * A {@code Policy} is created by parsing a serialized CSP string via
 * {@link #parseSerializedCSP(String, PolicyErrorConsumer)} or by parsing a comma-separated
 * list of policies via {@link #parseSerializedCSPList(String, PolicyListErrorConsumer)}.
 * </p>
 * <p>
 * The class preserves the original case, order, duplicate directives, unrecognized directives,
 * and unrecognized values to support round-tripping. Whitespace and empty directives/policies
 * are not preserved.
 * </p>
 * <p>
 * High-level query methods such as {@link #allowsExternalScript} and {@link #allowsInlineScript}
 * implement the matching algorithms defined in the
 * <a href="https://w3c.github.io/webappsec-csp/">CSP specification</a>.
 * </p>
 *
 * @see <a href="https://w3c.github.io/webappsec-csp/">W3C Content Security Policy Level 3</a>
 */
public final class Policy {
    // Things we don't preserve:
    // - Whitespace
    // - Empty directives or policies (as in `; ;` or `, ,`)
    // Things we do preserve:
    // - Source-expression lists being genuinely empty vs consisting of 'none'
    // - Case (as in lowercase vs uppercase)
    // - Order
    // - Duplicate directives
    // - Unrecognized directives
    // - Values in directives which forbid them
    // - Duplicate values
    // - Unrecognized values

    private final List<NamedDirective> directives_ = new ArrayList<>();

    private boolean blockAllMixedContent_;

    private SourceExpressionDirective baseUri_;
    private SourceExpressionDirective formAction_;
    private FrameAncestorsDirective frameAncestors_;
    private SourceExpressionDirective navigateTo_;
    private PluginTypesDirective pluginTypes_;
    private TrustedTypesDirective trustedTypes_;
    private RequireTrustedTypesForDirective requireTrustedTypesFor_;

    private FetchDirectiveKind prefetchSrc_;
    private RFC7230Token reportTo_;
    private ReportUriDirective reportUri_;
    private SandboxDirective sandbox_;
    private boolean upgradeInsecureRequests_;

    private final EnumMap<FetchDirectiveKind, SourceExpressionDirective> fetchDirectives_
                    = new EnumMap<>(FetchDirectiveKind.class);

    private Policy() {
        // pass
    }

    /**
     * Parses a serialized CSP list (comma-separated policies) into a {@link PolicyList}.
     * <p>
     * Implements the
     * <a href="https://w3c.github.io/webappsec-csp/#parse-serialized-policy-list">parse a
     * serialized CSP list</a> algorithm. The input must be an ASCII string. Empty policies
     * (those that contain no directives) are omitted from the resulting list.
     * </p>
     *
     * @param serialized the comma-separated serialized CSP list to parse
     * @param policyListErrorConsumer a consumer that receives any errors or warnings
     *        encountered during parsing
     * @return the parsed {@link PolicyList}
     * @throws IllegalArgumentException if {@code serialized} contains non-ASCII characters
     */
    public static PolicyList parseSerializedCSPList(final String serialized,
                        final PolicyListErrorConsumer policyListErrorConsumer) {
        // "A serialized CSP list is an ASCII string"
        enforceAscii(serialized);

        final List<Policy> policies = new ArrayList<>();

        // java's lambdas are dumb
        final int[] index = {0};
        final PolicyErrorConsumer policyErrorConsumer =
                (Severity severity, String message, int directiveIndex, int valueIndex) ->
                        policyListErrorConsumer.add(severity, message, index[0], directiveIndex, valueIndex);

        // https://infra.spec.whatwg.org/#split-on-commas
        for (final String token : serialized.split(",")) {
            final Policy policy = parseSerializedCSP(token, policyErrorConsumer);
            if (policy.directives_.isEmpty()) {
                ++index[0];
                continue;
            }

            policies.add(policy);

            ++index[0];
        }
        return new PolicyList(policies);
    }

    /**
     * Parses a single serialized CSP string into a {@link Policy}.
     * <p>
     * Implements the
     * <a href="https://w3c.github.io/webappsec-csp/#parse-serialized-policy">parse a
     * serialized CSP</a> algorithm. The input must be an ASCII string and must not
     * contain commas; for comma-separated CSP lists use
     * {@link #parseSerializedCSPList(String, PolicyListErrorConsumer)}.
     * </p>
     *
     * @param serialized the serialized CSP string to parse (must not contain commas)
     * @param policyErrorConsumer a consumer that receives any errors or warnings
     *        encountered during parsing
     * @return the parsed {@link Policy}
     * @throws IllegalArgumentException if {@code serialized} contains non-ASCII characters
     *         or contains a comma
     */
    public static Policy parseSerializedCSP(final String serialized, final PolicyErrorConsumer policyErrorConsumer) {
        // "A serialized CSP is an ASCII string", and browsers do in fact reject CSPs which contain non-ASCII characters
        enforceAscii(serialized);
        if (serialized.contains(",")) {
            // This is not quite per spec, but
            throw new IllegalArgumentException(
                    "Serialized CSPs cannot contain commas - you may have wanted parseSerializedCSPList");
        }

        // java's lambdas are dumb
        final int[] index = {0};
        final Directive.DirectiveErrorConsumer directiveErrorConsumer =
                (Severity severity, String message, int valueIndex) ->
                        policyErrorConsumer.add(severity, message, index[0], valueIndex);

        final Policy policy = new Policy();

        // https://infra.spec.whatwg.org/#strictly-split
        for (final String token : serialized.split(";")) {
            final String trimmedLeadingAndTrailingWhitespace = Utils.trimAsciiWhitespace(token);
            if (trimmedLeadingAndTrailingWhitespace.isEmpty()) {
                ++index[0];
                continue;
            }
            final String directiveName = Utils.extractLeadingToken(trimmedLeadingAndTrailingWhitespace);

            // Note: we do not lowercase directive names or
            // skip duplicates during parsing, to allow round-tripping even invalid policies

            final String remainingToken = trimmedLeadingAndTrailingWhitespace.substring(directiveName.length());

            final List<String> directiveValues = Utils.splitOnAsciiWhitespace(remainingToken);

            policy.add(directiveName, directiveValues, directiveErrorConsumer);

            ++index[0];
        }

        return policy;
    }

    // We do not provide a generic method for updating an existing directive in-place.
    // Just remove the existing one and add it back.
    private Directive add(final String name, final List<String> values,
                            final Directive.DirectiveErrorConsumer directiveErrorConsumer) {
        enforceAscii(name);

        // the parser will never hit these errors by construction, but use of the manipulation APIs can
        if (Directive.containsNonDirectiveCharacter(name)) {
            throw new IllegalArgumentException("directive names must not contain whitespace, ',', or ';'");
        }
        if (name.isEmpty()) {
            throw new IllegalArgumentException("directive names must not be empty");
        }

        boolean wasDupe = false;
        final Directive newDirective;
        final String lowercaseDirectiveName = name.toLowerCase(Locale.ROOT);
        switch (lowercaseDirectiveName) {
            case "base-uri":
                // https://w3c.github.io/webappsec-csp/#directive-base-uri
                final SourceExpressionDirective baseUriDirective
                        = new SourceExpressionDirective(values, directiveErrorConsumer);
                if (baseUri_ == null) {
                    baseUri_ = baseUriDirective;
                }
                else {
                    wasDupe = true;
                }
                newDirective = baseUriDirective;
                break;

            case "block-all-mixed-content":
                // https://www.w3.org/TR/mixed-content/#strict-opt-in
                if (blockAllMixedContent_) {
                    wasDupe = true;
                }
                else {
                    if (!values.isEmpty()) {
                        directiveErrorConsumer.add(Severity.Error,
                                        "The block-all-mixed-content directive does not support values", 0);
                    }
                    blockAllMixedContent_ = true;
                }
                newDirective = new Directive(values);
                break;

            case "form-action":
                // https://w3c.github.io/webappsec-csp/#directive-form-action
                final SourceExpressionDirective formActionDirective
                        = new SourceExpressionDirective(values, directiveErrorConsumer);
                if (formAction_ == null) {
                    formAction_ = formActionDirective;
                }
                else {
                    wasDupe = true;
                }
                newDirective = formActionDirective;
                break;

            case "frame-ancestors":
                // https://w3c.github.io/webappsec-csp/#directive-frame-ancestors
                // TODO contemplate warning for paths, which are always ignored: frame-ancestors only matches
                // against origins: https://w3c.github.io/webappsec-csp/#frame-ancestors-navigation-response
                final FrameAncestorsDirective frameAncestorsDirective
                        = new FrameAncestorsDirective(values, directiveErrorConsumer);
                if (frameAncestors_ == null) {
                    frameAncestors_ = frameAncestorsDirective;
                }
                else {
                    wasDupe = true;
                }
                newDirective = frameAncestorsDirective;
                break;

            case "navigate-to":
                // https://w3c.github.io/webappsec-csp/#directive-navigate-to
                // For some ungodly reason "navigate-to" is a list of source expressions while "frame-ancestors" is not
                // There is no logic here
                final SourceExpressionDirective navigateToDirective
                        = new SourceExpressionDirective(values, directiveErrorConsumer);
                if (navigateTo_ == null) {
                    navigateTo_ = navigateToDirective;
                }
                else {
                    wasDupe = true;
                }
                newDirective = navigateToDirective;
                break;

            case "plugin-types":
                // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/plugin-types
                directiveErrorConsumer.add(Severity.Warning, "The plugin-types directive has been deprecated", -1);
                final PluginTypesDirective pluginTypesDirective
                        = new PluginTypesDirective(values, directiveErrorConsumer);
                if (pluginTypes_ == null) {
                    pluginTypes_ = pluginTypesDirective;
                }
                else {
                    wasDupe = true;
                }
                newDirective = pluginTypesDirective;
                break;

            case "report-to":
                // https://w3c.github.io/webappsec-csp/#directive-report-to
                if (reportTo_ == null) {
                    if (values.isEmpty()) {
                        directiveErrorConsumer.add(Severity.Error, "The report-to directive requires a value", -1);
                    }
                    else if (values.size() == 1) {
                        final String token = values.get(0);
                        final Optional<RFC7230Token> matched = RFC7230Token.parseRFC7230Token(token);
                        if (matched.isPresent()) {
                            reportTo_ = matched.get();
                        }
                        else {
                            directiveErrorConsumer.add(Severity.Error,
                                                        "Expecting RFC 7230 token but found \"" + token + "\"", 0);
                        }
                    }
                    else {
                        directiveErrorConsumer.add(Severity.Error,
                                "The report-to directive requires exactly one value (found " + values.size() + ")", 1);
                    }
                }
                else {
                    wasDupe = true;
                }
                newDirective = new Directive(values);
                break;

            case "referrer":
                // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/referrer
                directiveErrorConsumer.add(Severity.Warning,
                        "The referrer directive has been deprecated in favor of the Referrer-Policy header",
                        -1);
                // We don't currently handle it further than this.
                newDirective = new Directive(Collections.emptyList());
                break;

            case "report-uri":
                // https://w3c.github.io/webappsec-csp/#directive-report-uri
                directiveErrorConsumer.add(Severity.Warning,
                        "The report-uri directive has been deprecated in favor of the new report-to directive", -1);

                final ReportUriDirective reportUriDirective = new ReportUriDirective(values, directiveErrorConsumer);
                if (reportUri_ == null) {
                    reportUri_ = reportUriDirective;
                }
                else {
                    wasDupe = true;
                }
                newDirective = reportUriDirective;
                break;

            case "sandbox":
                // https://w3c.github.io/webappsec-csp/#directive-sandbox
                final SandboxDirective sandboxDirective = new SandboxDirective(values, directiveErrorConsumer);
                if (sandbox_ == null) {
                    sandbox_ = sandboxDirective;
                }
                else {
                    wasDupe = true;
                }
                newDirective = sandboxDirective;
                break;

            case "trusted-types":
                // https://w3c.github.io/trusted-types/dist/spec/#trusted-types-csp-directive
                final TrustedTypesDirective trustedTypesDirective =
                        new TrustedTypesDirective(values, directiveErrorConsumer);
                if (trustedTypes_ == null) {
                    trustedTypes_ = trustedTypesDirective;
                }
                else {
                    wasDupe = true;
                }
                newDirective = trustedTypesDirective;
                break;

            case "require-trusted-types-for":
                // https://w3c.github.io/trusted-types/dist/spec/#require-trusted-types-for-csp-directive
                final RequireTrustedTypesForDirective requireTrustedTypesForDirective =
                        new RequireTrustedTypesForDirective(values, directiveErrorConsumer);
                if (requireTrustedTypesFor_ == null) {
                    requireTrustedTypesFor_ = requireTrustedTypesForDirective;
                }
                else {
                    wasDupe = true;
                }
                newDirective = requireTrustedTypesForDirective;
                break;

            case "upgrade-insecure-requests":
                // https://www.w3.org/TR/upgrade-insecure-requests/#delivery
                if (upgradeInsecureRequests_) {
                    wasDupe = true;
                }
                else {
                    if (!values.isEmpty()) {
                        directiveErrorConsumer.add(Severity.Error,
                                "The upgrade-insecure-requests directive does not support values", 0);
                    }
                    upgradeInsecureRequests_ = true;
                }
                newDirective = new Directive(values);
                break;

            default:
                if (!Directive.IS_DIRECTIVE_NAME.test(name)) {
                    directiveErrorConsumer.add(Severity.Error,
                                    "Directive name " + name
                                        + " contains characters outside the range ALPHA / DIGIT / \"-\"", -1);
                    newDirective = new Directive(values);
                    break;
                }
                final FetchDirectiveKind fetchDirectiveKind = FetchDirectiveKind.fromString(lowercaseDirectiveName);
                if (fetchDirectiveKind != null) {
                    if (FetchDirectiveKind.PrefetchSrc == fetchDirectiveKind) {
                        directiveErrorConsumer.add(Severity.Warning,
                                                    "The prefetch-src directive has been deprecated", -1);
                    }
                    final SourceExpressionDirective thisDirective
                                = new SourceExpressionDirective(values, directiveErrorConsumer);
                    if (fetchDirectives_.containsKey(fetchDirectiveKind)) {
                        wasDupe = true;
                    }
                    else {
                        fetchDirectives_.put(fetchDirectiveKind, thisDirective);
                    }
                    newDirective = thisDirective;
                    break;
                }
                directiveErrorConsumer.add(Severity.Warning, "Unrecognized directive " + lowercaseDirectiveName, -1);
                newDirective = new Directive(values);
                break;
        }

        directives_.add(new NamedDirective(name, newDirective));
        if (wasDupe) {
            directiveErrorConsumer.add(Severity.Warning, "Duplicate directive " + lowercaseDirectiveName, -1);
        }
        return newDirective;
    }

    /**
     * Serializes this policy back to its string representation.
     * <p>
     * Directives are separated by {@code "; "}. The original case, order, and values
     * (including duplicates and unrecognized entries) are preserved.
     * </p>
     *
     * @return the serialized CSP string
     */
    @Override
    public String toString() {
        final StringBuilder out = new StringBuilder();
        boolean first = true;
        for (final NamedDirective directive : directives_) {
            if (!first) {
                out.append("; "); // The whitespace is not strictly necessary but is probably valuable
            }
            first = false;
            out.append(directive.name_);
            for (final String value : directive.directive_.getValues()) {
                out.append(' ').append(value);
            }
        }
        return out.toString();
    }

    // Accessors

    /**
     * Returns the parsed {@code base-uri} directive, if present.
     *
     * @return an {@link Optional} containing the {@link SourceExpressionDirective} for
     *         {@code base-uri}, or empty if the directive was not specified
     * @see <a href="https://w3c.github.io/webappsec-csp/#directive-base-uri">base-uri directive</a>
     */
    public Optional<SourceExpressionDirective> baseUri() {
        return Optional.ofNullable(baseUri_);
    }

    /**
     * Returns whether the {@code block-all-mixed-content} directive is present.
     *
     * @return {@code true} if the policy contains the {@code block-all-mixed-content} directive
     * @see <a href="https://www.w3.org/TR/mixed-content/#strict-opt-in">block-all-mixed-content</a>
     */
    public boolean blockAllMixedContent() {
        return blockAllMixedContent_;
    }

    /**
     * Returns the parsed {@code form-action} directive, if present.
     *
     * @return an {@link Optional} containing the {@link SourceExpressionDirective} for
     *         {@code form-action}, or empty if the directive was not specified
     * @see <a href="https://w3c.github.io/webappsec-csp/#directive-form-action">form-action directive</a>
     */
    public Optional<SourceExpressionDirective> formAction() {
        return Optional.ofNullable(formAction_);
    }

    /**
     * Returns the parsed {@code frame-ancestors} directive, if present.
     *
     * @return an {@link Optional} containing the {@link FrameAncestorsDirective},
     *         or empty if the directive was not specified
     * @see <a href="https://w3c.github.io/webappsec-csp/#directive-frame-ancestors">frame-ancestors directive</a>
     */
    public Optional<FrameAncestorsDirective> frameAncestors() {
        return Optional.ofNullable(frameAncestors_);
    }

    /**
     * Returns the parsed {@code navigate-to} directive, if present.
     *
     * @return an {@link Optional} containing the {@link SourceExpressionDirective} for
     *         {@code navigate-to}, or empty if the directive was not specified
     * @see <a href="https://w3c.github.io/webappsec-csp/#directive-navigate-to">navigate-to directive</a>
     */
    public Optional<SourceExpressionDirective> navigateTo() {
        return Optional.ofNullable(navigateTo_);
    }

    /**
     * Returns the parsed {@code plugin-types} directive, if present.
     * <p>Note: the {@code plugin-types} directive has been deprecated.</p>
     *
     * @return an {@link Optional} containing the {@link PluginTypesDirective},
     *         or empty if the directive was not specified
     */
    public Optional<PluginTypesDirective> pluginTypes() {
        return Optional.ofNullable(pluginTypes_);
    }

    /**
     * Returns the {@code prefetch-src} fetch directive kind, if present.
     * <p>Note: the {@code prefetch-src} directive has been deprecated. The actual parsed
     * directive data is available via {@link #getFetchDirective(FetchDirectiveKind)} with
     * {@link FetchDirectiveKind#PrefetchSrc}.</p>
     *
     * @return an {@link Optional} containing the {@link FetchDirectiveKind} for
     *         {@code prefetch-src}, or empty if not present
     */
    public Optional<FetchDirectiveKind> prefetchSrc() {
        return Optional.ofNullable(prefetchSrc_);
    }

    /**
     * Returns the parsed {@code report-to} directive value, if present.
     *
     * @return an {@link Optional} containing the {@link RFC7230Token} representing the
     *         report-to group name, or empty if the directive was not specified
     * @see <a href="https://w3c.github.io/webappsec-csp/#directive-report-to">report-to directive</a>
     */
    public Optional<RFC7230Token> reportTo() {
        return Optional.ofNullable(reportTo_);
    }

    /**
     * Returns the parsed {@code report-uri} directive, if present.
     * <p>Note: the {@code report-uri} directive has been deprecated in favor of
     * {@code report-to}.</p>
     *
     * @return an {@link Optional} containing the {@link ReportUriDirective},
     *         or empty if the directive was not specified
     * @see <a href="https://w3c.github.io/webappsec-csp/#directive-report-uri">report-uri directive</a>
     */
    public Optional<ReportUriDirective> reportUri() {
        return Optional.ofNullable(reportUri_);
    }

    /**
     * Returns the parsed {@code sandbox} directive, if present.
     *
     * @return an {@link Optional} containing the {@link SandboxDirective},
     *         or empty if the directive was not specified
     * @see <a href="https://w3c.github.io/webappsec-csp/#directive-sandbox">sandbox directive</a>
     */
    public Optional<SandboxDirective> sandbox() {
        return Optional.ofNullable(sandbox_);
    }

    /**
     * Returns the parsed {@code trusted-types} directive, if present.
     *
     * @return an {@link Optional} containing the {@link TrustedTypesDirective},
     *         or empty if the directive was not specified
     * @see <a href="https://w3c.github.io/trusted-types/dist/spec/#trusted-types-csp-directive">
     *      trusted-types directive</a>
     */
    public Optional<TrustedTypesDirective> trustedTypes() {
        return Optional.ofNullable(trustedTypes_);
    }

    /**
     * Indicates if wildcard policy names are permitted in the trusted-types directive.
     * When true, any policy name is allowed, which may reduce security.
     *
     * @return true if wildcard policy names (*) are permitted, false if not present or not permitted
     */
    public boolean allowsWildcardPolicyNames() {
        return trustedTypes_ != null && trustedTypes_.allowsWildcardPolicyNames();
    }

    /**
     * Returns the parsed {@code require-trusted-types-for} directive, if present.
     *
     * @return an {@link Optional} containing the {@link RequireTrustedTypesForDirective},
     *         or empty if the directive was not specified
     * @see <a href="https://w3c.github.io/trusted-types/dist/spec/#require-trusted-types-for-csp-directive">
     *      require-trusted-types-for directive</a>
     */
    public Optional<RequireTrustedTypesForDirective> requireTrustedTypesFor() {
        return Optional.ofNullable(requireTrustedTypesFor_);
    }

    /**
     * Returns whether the {@code upgrade-insecure-requests} directive is present.
     *
     * @return {@code true} if the policy contains the {@code upgrade-insecure-requests} directive
     * @see <a href="https://www.w3.org/TR/upgrade-insecure-requests/#delivery">
     *      upgrade-insecure-requests</a>
     */
    public boolean upgradeInsecureRequests() {
        return upgradeInsecureRequests_;
    }

    /**
     * Returns the parsed fetch directive of the specified kind, if present.
     * <p>
     * Fetch directives include {@code default-src}, {@code script-src}, {@code style-src},
     * {@code img-src}, {@code font-src}, {@code connect-src}, {@code media-src},
     * {@code object-src}, {@code frame-src}, {@code child-src}, {@code worker-src},
     * {@code manifest-src}, and their {@code -elem} / {@code -attr} variants.
     * </p>
     *
     * @param kind the {@link FetchDirectiveKind} to look up
     * @return an {@link Optional} containing the {@link SourceExpressionDirective} for the
     *         requested fetch directive, or empty if not present
     */
    public Optional<SourceExpressionDirective> getFetchDirective(final FetchDirectiveKind kind) {
        return Optional.ofNullable(fetchDirectives_.get(kind));
    }

    // High-level querying

    /**
     * Determines whether this policy allows loading an external script.
     * <p>
     * For each argument, if the value provided is {@link Optional#empty()}, this method
     * returns {@code true} only if there is no value for the {@code Optional.of()} case
     * of that parameter which would cause it to return {@code false}.
     * </p>
     * <p>
     * Take care with {@code integrity}: a script can be allowed by CSP but blocked by
     * <a href="https://www.w3.org/TR/SRI/">Subresource Integrity</a> if its integrity is wrong.
     * Also note that "the URL" is somewhat fuzzy because of redirects.
     * </p>
     *
     * @param nonce the nonce attribute value of the script element, if any
     * @param integrity the integrity attribute value (SRI metadata), if any
     * @param scriptUrl the URL of the external script, if known
     * @param parserInserted whether the script element is parser-inserted;
     *        {@link Optional#empty()} if unknown
     * @param origin the origin of the protected resource, if known
     * @return {@code true} if this policy allows the external script
     * @see <a href="https://w3c.github.io/webappsec-csp/#script-pre-request">
     *      script-pre-request check</a>
     * @see <a href="https://w3c.github.io/webappsec-csp/#script-post-request">
     *      script-post-request check</a>
     */
    public boolean allowsExternalScript(
            final Optional<String> nonce,
            final Optional<String> integrity,
            final Optional<? extends URLWithScheme> scriptUrl,
            final Optional<Boolean> parserInserted,
            final Optional<? extends URLWithScheme> origin) {
        if (sandbox_ != null && !sandbox_.allowScripts()) {
            return false;
        }

        // Effective directive is "script-src-elem" per
        // https://w3c.github.io/webappsec-csp/#effective-directive-for-a-request
        final SourceExpressionDirective directive =
                getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.ScriptSrcElem).orElse(null);
        if (directive == null) {
            return true;
        }
        if (nonce.isPresent()) {
            final String actualNonce = nonce.get();
            if (actualNonce.length() > 0
                    && directive.getNonces().stream().anyMatch(n -> n.base64ValuePart().equals(actualNonce))) {
                return true;
            }
        }
        if (integrity.isPresent() && !directive.getHashes().isEmpty()) {
            final String integritySources = integrity.get();
            boolean bypassDueToIntegrityMatch = true;
            boolean atLeastOneValidIntegrity = false;
            // https://www.w3.org/TR/SRI/#parse-metadata
            for (final String source : Utils.splitOnAsciiWhitespace(integritySources)) {
                final Optional<Hash> parsedIntegritySource = Hash.parseHash("'" + source + "'");
                if (parsedIntegritySource.isEmpty()) {
                    continue;
                }
                if (!directive.getHashes().contains(parsedIntegritySource.get())) {
                    bypassDueToIntegrityMatch = false;
                    break;
                }
                atLeastOneValidIntegrity = true;
            }
            if (atLeastOneValidIntegrity && bypassDueToIntegrityMatch) {
                return true;
            }
        }
        if (directive.strictDynamic()) {
            // if not the parameter is not supplied, we have to assume the worst case
            return !parserInserted.orElse(true);
        }
        return scriptUrl.filter(urlWithScheme ->
                doesUrlMatchSourceListInOrigin(urlWithScheme, directive, origin)).isPresent();
    }

    /**
     * Determines whether this policy allows an inline {@code <script>} element.
     *
     * @param nonce the nonce attribute value of the script element, if any
     * @param source the text content of the inline script, if known (used for hash matching)
     * @param parserInserted whether the script element is parser-inserted;
     *        {@link Optional#empty()} if unknown
     * @return {@code true} if this policy allows the inline script
     * @see <a href="https://w3c.github.io/webappsec-csp/#should-block-inline">
     *      should block inline check</a>
     */
    public boolean allowsInlineScript(final Optional<String> nonce,
            final Optional<String> source, final Optional<Boolean> parserInserted) {
        if (sandbox_ != null && !sandbox_.allowScripts()) {
            return false;
        }
        return doesElementMatchSourceListForTypeAndSource(InlineType.Script, nonce, source, parserInserted);
    }

    /**
     * Determines whether this policy allows a script provided as an inline event handler
     * attribute (e.g. {@code onclick}).
     *
     * @param source the text content of the event handler attribute, if known
     *        (used for hash matching with {@code 'unsafe-hashes'})
     * @return {@code true} if this policy allows the script attribute
     * @see <a href="https://w3c.github.io/webappsec-csp/#should-block-inline">
     *      should block inline check (script-src-attr)</a>
     */
    public boolean allowsScriptAsAttribute(final Optional<String> source) {
        if (sandbox_ != null && !sandbox_.allowScripts()) {
            return false;
        }
        return doesElementMatchSourceListForTypeAndSource(
                InlineType.ScriptAttribute, Optional.empty(), source, Optional.empty());
    }

    /**
     * Determines whether this policy allows the use of {@code eval()} and similar
     * string-to-code mechanisms.
     * <p>
     * The governing directive is {@code script-src} if present, otherwise {@code default-src}.
     * Returns {@code true} if no governing directive is present or if the governing directive
     * includes {@code 'unsafe-eval'}.
     * </p>
     *
     * @return {@code true} if this policy allows eval
     * @see <a href="https://w3c.github.io/webappsec-csp/#can-compile-strings">
     *      can compile strings check</a>
     */
    public boolean allowsEval() {
        // This is done in prose, not in a table
        final FetchDirectiveKind governingDirective =
                fetchDirectives_
                    .containsKey(FetchDirectiveKind.ScriptSrc)
                        ? FetchDirectiveKind.ScriptSrc : FetchDirectiveKind.DefaultSrc;
        final SourceExpressionDirective sourceList = fetchDirectives_.get(governingDirective);
        return sourceList == null || sourceList.unsafeEval();
    }

    /**
     * Determines whether this policy allows a navigation to the given URL.
     * <p>
     * This checks the {@code navigate-to} directive. If the directive is not present,
     * navigation is allowed. This does <em>not</em> handle {@code javascript:} URL
     * navigation; use {@link #allowsJavascriptUrlNavigation} for that.
     * </p>
     * <p>
     * It is nonsensical to provide {@code redirectedTo} if {@code redirected} is
     * {@code Optional.of(false)}.
     * </p>
     *
     * @param to the initial navigation target URL, if known
     * @param redirected whether the navigation is a redirect; {@link Optional#empty()} if unknown
     * @param redirectedTo the final URL after redirect, if known
     * @param origin the origin of the protected resource, if known
     * @return {@code true} if this policy allows the navigation
     * @see <a href="https://w3c.github.io/webappsec-csp/#navigate-to-pre-navigate">
     *      navigate-to pre-navigate check</a>
     */
    public boolean allowsNavigation(
            final Optional<? extends URLWithScheme> to,
            final Optional<Boolean> redirected,
            final Optional<? extends URLWithScheme> redirectedTo,
            final Optional<? extends URLWithScheme> origin) {
        if (navigateTo_ == null) {
            return true;
        }
        if (navigateTo_.unsafeAllowRedirects()) {
            // if unsafe-allow-redirects is present, check `to` in non-redirect or maybe-non-redirect cases
            if (!redirected.orElse(false)) {
                if (to.isEmpty()) {
                    return false;
                }
                if (!doesUrlMatchSourceListInOrigin(to.get(), navigateTo_, origin)) {
                    return false;
                }
            }
            // if unsafe-allow-redirects is present, check `redirectedTo` in redirect or maybe-redirect cases
            if (redirected.orElse(true)) {
                if (redirectedTo.isEmpty()) {
                    return false;
                }
                if (!doesUrlMatchSourceListInOrigin(redirectedTo.get(), navigateTo_, origin)) {
                    return false;
                }
            }
        }
        else {
            // if unsafe-allow-redirects is absent, always and only check `to`
            if (to.isEmpty()) {
                return false;
            }
            if (!doesUrlMatchSourceListInOrigin(to.get(), navigateTo_, origin)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Determines whether this policy allows a form submission to the given URL.
     * <p>
     * This checks the {@code form-action} directive first; if absent, falls back to
     * the {@code navigate-to} directive via {@link #allowsNavigation}. If the sandbox
     * directive is present and does not include {@code allow-forms}, form submission
     * is blocked.
     * </p>
     *
     * @param to the form action target URL, if known
     * @param redirected whether the form submission results in a redirect;
     *        {@link Optional#empty()} if unknown
     * @param redirectedTo the final URL after redirect, if known
     * @param origin the origin of the protected resource, if known
     * @return {@code true} if this policy allows the form action
     * @see <a href="https://w3c.github.io/webappsec-csp/#navigate-to-pre-navigate">
     *      navigate-to pre-navigate check</a>
     */
    public boolean allowsFormAction(
            final Optional<? extends URLWithScheme> to,
            final Optional<Boolean> redirected,
            final Optional<? extends URLWithScheme> redirectedTo,
            final Optional<? extends URLWithScheme> origin) {
        if (sandbox_ != null && !sandbox_.allowForms()) {
            return false;
        }
        if (formAction_ != null) {
            if (to.isEmpty()) {
                return false;
            }
            if (!doesUrlMatchSourceListInOrigin(to.get(), formAction_, origin)) {
                return false;
            }
            return true;
        }
        // this isn't implemented like other fallbacks because
        // it isn't one: form-action does not respect unsafe-allow-redirects
        return allowsNavigation(to, redirected, redirectedTo, origin);
    }

    /**
     * Determines whether this policy allows a {@code javascript:} URL navigation.
     * <p>
     * The hashes (for {@code 'unsafe-hashes'}) are expected to include the
     * {@code javascript:} prefix per the specification.
     * </p>
     *
     * @param source the JavaScript source code after the {@code javascript:} prefix, if known
     * @param origin the origin of the protected resource, if known
     * @return {@code true} if this policy allows the {@code javascript:} URL navigation
     */
    public boolean allowsJavascriptUrlNavigation(
            final Optional<String> source,
            final Optional<? extends URLWithScheme> origin) {
        return allowsNavigation(
                Optional.of(
                            new GUID("javascript", source.orElse(""))),
                Optional.of(false), Optional.empty(), origin)
                &&
                    doesElementMatchSourceListForTypeAndSource(
                                InlineType.Navigation, Optional.empty(),
                                            source.map(s -> "javascript:" + s), Optional.of(false));
    }

    /**
     * Determines whether this policy allows loading an external stylesheet.
     * <p>
     * The effective directive is {@code style-src-elem} per the
     * <a href="https://w3c.github.io/webappsec-csp/#effective-directive-for-a-request">
     * effective directive for a request</a> algorithm. Integrity is not checked for
     * stylesheets per <a href="https://github.com/w3c/webappsec-csp/issues/430">
     * w3c/webappsec-csp#430</a>.
     * </p>
     *
     * @param nonce the nonce attribute value of the link element, if any
     * @param styleUrl the URL of the external stylesheet, if known
     * @param origin the origin of the protected resource, if known
     * @return {@code true} if this policy allows the external style
     */
    public boolean allowsExternalStyle(
            final Optional<String> nonce,
            final Optional<? extends URLWithScheme> styleUrl,
            final Optional<? extends URLWithScheme> origin) {
        // Effective directive is "style-src-elem" per
        // https://w3c.github.io/webappsec-csp/#effective-directive-for-a-request
        final SourceExpressionDirective directive
                = getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.StyleSrcElem).orElse(null);
        if (directive == null) {
            return true;
        }
        if (nonce.isPresent()) {
            final String actualNonce = nonce.get();
            if (actualNonce.length() > 0
                    && directive.getNonces().stream().anyMatch(n -> n.base64ValuePart().equals(actualNonce))) {
                return true;
            }
        }
        // integrity is not used: https://github.com/w3c/webappsec-csp/issues/430
        return styleUrl.filter(urlWithScheme ->
                doesUrlMatchSourceListInOrigin(urlWithScheme, directive, origin)).isPresent();
    }

    /**
     * Determines whether this policy allows an inline {@code <style>} element.
     *
     * @param nonce the nonce attribute value of the style element, if any
     * @param source the text content of the inline style, if known (used for hash matching)
     * @return {@code true} if this policy allows the inline style
     */
    public boolean allowsInlineStyle(final Optional<String> nonce, final Optional<String> source) {
        return doesElementMatchSourceListForTypeAndSource(InlineType.Style, nonce, source, Optional.empty());
    }

    /**
     * Determines whether this policy allows an inline style attribute (e.g. {@code style="..."}).
     *
     * @param source the text content of the style attribute, if known
     *        (used for hash matching with {@code 'unsafe-hashes'})
     * @return {@code true} if this policy allows the style attribute
     */
    public boolean allowsStyleAsAttribute(final Optional<String> source) {
        return doesElementMatchSourceListForTypeAndSource(
                InlineType.StyleAttribute, Optional.empty(), source, Optional.empty());
    }

    /**
     * Determines whether this policy allows loading a frame (iframe/frame) from the given source.
     * <p>
     * Uses the {@code frame-src} effective directive with its fallback chain.
     * </p>
     *
     * @param source the URL of the framed resource, if known
     * @param origin the origin of the protected resource, if known
     * @return {@code true} if this policy allows the frame
     */
    public boolean allowsFrame(final Optional<? extends URLWithScheme> source,
                               final Optional<? extends URLWithScheme> origin) {
        final SourceExpressionDirective sourceList
            = getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.FrameSrc).orElse(null);
        if (sourceList == null) {
            return true;
        }
        return source.filter(urlWithScheme ->
                doesUrlMatchSourceListInOrigin(urlWithScheme, sourceList, origin)).isPresent();
    }

    /**
     * Determines whether this policy allows being framed by the given ancestor origin.
     * <p>
     * Checks the {@code frame-ancestors} directive. If not present, all ancestors are allowed.
     * </p>
     *
     * @param source the URL of the ancestor frame, if known
     * @param origin the origin of the protected resource, if known
     * @return {@code true} if this policy allows the frame ancestor
     * @see <a href="https://w3c.github.io/webappsec-csp/#directive-frame-ancestors">
     *      frame-ancestors directive</a>
     */
    public boolean allowsFrameAncestor(final Optional<? extends URLWithScheme> source,
                                       final Optional<? extends URLWithScheme> origin) {
        if (frameAncestors_ == null) {
            return true;
        }
        return source.filter(urlWithScheme ->
                        doesUrlMatchSourceListInOrigin(urlWithScheme, frameAncestors_, origin)).isPresent();
    }

    /**
     * Determines whether this policy allows a connection (e.g. {@code fetch()},
     * {@code XMLHttpRequest}, {@code WebSocket}) to the given source.
     * <p>
     * For {@code ws:} and {@code wss:} URLs (when using {@code new WebSocket}),
     * the scheme is mapped to {@code http:} / {@code https:} respectively for matching,
     * per the <a href="https://fetch.spec.whatwg.org/#concept-websocket-establish">
     * WebSocket establish algorithm</a>.
     * </p>
     *
     * @param source the URL to connect to, if known
     * @param origin the origin of the protected resource, if known
     * @return {@code true} if this policy allows the connection
     */
    public boolean allowsConnection(final Optional<? extends URLWithScheme> source,
                                    final Optional<? extends URLWithScheme> origin) {
        final SourceExpressionDirective sourceList
                = getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.ConnectSrc).orElse(null);
        if (sourceList == null) {
            return true;
        }
        if (source.isEmpty()) {
            return false;
        }
        // See https://fetch.spec.whatwg.org/#concept-websocket-establish
        // Also browsers don't implement this; see https://github.com/w3c/webappsec-csp/issues/429
        final URLWithScheme actualSource = source.get();
        final String scheme = actualSource.getScheme();
        URLWithScheme usedSource = actualSource;
        if (actualSource instanceof URI) {
            if ("ws".equals(scheme)) {
                usedSource = new URI("http", actualSource.getHost(), actualSource.getPort(), actualSource.getPath());
            }
            else if ("wss".equals(scheme)) {
                usedSource = new URI("https", actualSource.getHost(), actualSource.getPort(), actualSource.getPath());
            }
        }

        return doesUrlMatchSourceListInOrigin(usedSource, sourceList, origin);
    }

    /**
     * Determines whether this policy allows loading a font from the given source.
     *
     * @param source the URL of the font resource, if known
     * @param origin the origin of the protected resource, if known
     * @return {@code true} if this policy allows the font
     */
    public boolean allowsFont(final Optional<? extends URLWithScheme> source,
                              final Optional<? extends URLWithScheme> origin) {
        final SourceExpressionDirective sourceList
                = getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.FontSrc).orElse(null);
        if (sourceList == null) {
            return true;
        }
        return source.filter(urlWithScheme ->
                        doesUrlMatchSourceListInOrigin(urlWithScheme, sourceList, origin)).isPresent();
    }

    /**
     * Determines whether this policy allows loading an image from the given source.
     *
     * @param source the URL of the image resource, if known
     * @param origin the origin of the protected resource, if known
     * @return {@code true} if this policy allows the image
     */
    public boolean allowsImage(final Optional<? extends URLWithScheme> source,
                               final Optional<? extends URLWithScheme> origin) {
        final SourceExpressionDirective sourceList
                = getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.ImgSrc).orElse(null);
        if (sourceList == null) {
            return true;
        }
        return source.filter(urlWithScheme ->
                        doesUrlMatchSourceListInOrigin(urlWithScheme, sourceList, origin)).isPresent();
    }

    /**
     * Determines whether this policy allows loading an application manifest from the given source.
     *
     * @param source the URL of the manifest resource, if known
     * @param origin the origin of the protected resource, if known
     * @return {@code true} if this policy allows the manifest
     */
    public boolean allowsApplicationManifest(final Optional<? extends URLWithScheme> source,
                                             final Optional<? extends URLWithScheme> origin) {
        final SourceExpressionDirective sourceList
                = getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.ManifestSrc).orElse(null);
        if (sourceList == null) {
            return true;
        }
        return source.filter(urlWithScheme ->
                        doesUrlMatchSourceListInOrigin(urlWithScheme, sourceList, origin)).isPresent();
    }

    /**
     * Determines whether this policy allows loading media (audio/video) from the given source.
     *
     * @param source the URL of the media resource, if known
     * @param origin the origin of the protected resource, if known
     * @return {@code true} if this policy allows the media
     */
    public boolean allowsMedia(final Optional<? extends URLWithScheme> source,
                               final Optional<? extends URLWithScheme> origin) {
        final SourceExpressionDirective sourceList
                = getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.MediaSrc).orElse(null);
        if (sourceList == null) {
            return true;
        }
        return source.filter(urlWithScheme ->
                        doesUrlMatchSourceListInOrigin(urlWithScheme, sourceList, origin)).isPresent();
    }

    /**
     * Determines whether this policy allows loading an object/embed/applet from the given source.
     *
     * @param source the URL of the object resource, if known
     * @param origin the origin of the protected resource, if known
     * @return {@code true} if this policy allows the object
     */
    public boolean allowsObject(final Optional<? extends URLWithScheme> source,
                                final Optional<? extends URLWithScheme> origin) {
        final SourceExpressionDirective sourceList
                = getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.ObjectSrc).orElse(null);
        if (sourceList == null) {
            return true;
        }
        return source.filter(urlWithScheme ->
                        doesUrlMatchSourceListInOrigin(urlWithScheme, sourceList, origin)).isPresent();
    }

    /**
     * Determines whether this policy allows a prefetch from the given source.
     * <p>
     * Note: the {@code prefetch-src} directive is not properly spec'd.
     * See <a href="https://github.com/whatwg/fetch/issues/1008">whatwg/fetch#1008</a>.
     * </p>
     *
     * @param source the URL to prefetch, if known
     * @param origin the origin of the protected resource, if known
     * @return {@code true} if this policy allows the prefetch
     */
    public boolean allowsPrefetch(final Optional<? extends URLWithScheme> source,
                                  final Optional<? extends URLWithScheme> origin) {
        final SourceExpressionDirective sourceList
                = getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.PrefetchSrc).orElse(null);
        if (sourceList == null) {
            return true;
        }
        return source.filter(urlWithScheme ->
                        doesUrlMatchSourceListInOrigin(urlWithScheme, sourceList, origin)).isPresent();
    }

    /**
     * Determines whether this policy allows loading a worker (dedicated, shared, or service)
     * from the given source.
     *
     * @param source the URL of the worker script, if known
     * @param origin the origin of the protected resource, if known
     * @return {@code true} if this policy allows the worker
     */
    public boolean allowsWorker(final Optional<? extends URLWithScheme> source,
                                final Optional<? extends URLWithScheme> origin) {
        final SourceExpressionDirective sourceList
                = getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.WorkerSrc).orElse(null);
        if (sourceList == null) {
            return true;
        }
        return source.filter(urlWithScheme ->
                        doesUrlMatchSourceListInOrigin(urlWithScheme, sourceList, origin)).isPresent();
    }

    /**
     * Determines whether this policy allows a plugin of the given media type.
     * <p>
     * Checks the (deprecated) {@code plugin-types} directive. If not present,
     * all plugin types are allowed.
     * </p>
     *
     * @param mediaType the media type of the plugin, if known
     * @return {@code true} if this policy allows the plugin type
     */
    public boolean allowsPlugin(final Optional<? extends MediaType> mediaType) {
        if (pluginTypes_ == null) {
            return true;
        }
        return mediaType.filter(type -> pluginTypes_.getMediaTypes().contains(type)).isPresent();
    }

    /**
     * Returns the governing directive for the given effective fetch directive kind,
     * walking the fallback chain as defined in the specification.
     * <p>
     * For example, if {@code script-src-elem} is not present, this falls back to
     * {@code script-src}, then to {@code default-src}.
     * </p>
     *
     * @param kind the effective {@link FetchDirectiveKind} to resolve
     * @return an {@link Optional} containing the governing {@link SourceExpressionDirective},
     *         or empty if no directive in the fallback chain is present
     * @see <a href="https://w3c.github.io/webappsec-csp/#should-directive-execute">
     *      should a directive execute</a>
     */
    public Optional<SourceExpressionDirective> getGoverningDirectiveForEffectiveDirective(
                                                final FetchDirectiveKind kind) {
        for (final FetchDirectiveKind candidate : FetchDirectiveKind.getFetchDirectiveFallbackList(kind)) {
            final SourceExpressionDirective list = fetchDirectives_.get(candidate);
            if (list != null) {
                return Optional.of(list);
            }
        }
        return Optional.empty();
    }

    // https://w3c.github.io/webappsec-csp/#directive-inline-check
    // https://w3c.github.io/webappsec-csp/#should-block-inline specifies the first four values
    // https://w3c.github.io/webappsec-csp/#should-block-navigation-request
    // specifies "navigation", used for `javascript:` urls
    // https://w3c.github.io/webappsec-csp/#effective-directive-for-inline-check
    private enum InlineType {
        Script(FetchDirectiveKind.ScriptSrcElem),
        ScriptAttribute(FetchDirectiveKind.ScriptSrcAttr),
        Style(FetchDirectiveKind.StyleSrcElem),
        StyleAttribute(FetchDirectiveKind.StyleSrcAttr),
        Navigation(FetchDirectiveKind.ScriptSrcElem);

        private final FetchDirectiveKind effectiveDirective_;

        InlineType(final FetchDirectiveKind effectiveDirective) {
            effectiveDirective_ = effectiveDirective;
        }
    }

    // Note: this assumes the element is nonceable. See https://w3c.github.io/webappsec-csp/#is-element-nonceable
    // https://w3c.github.io/webappsec-csp/#match-element-to-source-list
    private boolean doesElementMatchSourceListForTypeAndSource(final InlineType type,
                        final Optional<String> nonce,
                        final Optional<String> source,
                        final Optional<Boolean> parserInserted) {
        final SourceExpressionDirective directive
                = getGoverningDirectiveForEffectiveDirective(type.effectiveDirective_).orElse(null);
        if (directive == null) {
            return true;
        }
        // https://w3c.github.io/webappsec-csp/#allow-all-inline
        final boolean allowAllInline
                    = directive.getNonces().isEmpty()
                        && directive.getHashes().isEmpty()
                        && !((type == InlineType.Script
                                    || type == InlineType.ScriptAttribute
                                    || type == InlineType.Navigation)
                        && directive.strictDynamic())
                        && directive.unsafeInline();
        if (allowAllInline) {
            return true;
        }
        if (nonce.isPresent()) {
            final String actualNonce = nonce.get();
            if (actualNonce.length() > 0
                    && directive.getNonces().stream().anyMatch(n -> n.base64ValuePart().equals(actualNonce))) {
                return true;
            }
        }
        if (source.isPresent()
                && !directive.getHashes().isEmpty()
                && (type == InlineType.Script || type == InlineType.Style || directive.unsafeHashes())) {
            final byte[] actualSource = source.get().getBytes(StandardCharsets.UTF_8);
            final Base64.Encoder base64encoder = Base64.getEncoder();
            String actualSha256 = null;
            String actualSha384 = null;
            String actualSha512 = null;
            try {
                for (final Hash hash : directive.getHashes()) {
                    switch (hash.getAlgorithm()) {
                        case SHA256:
                            if (actualSha256 == null) {
                                actualSha256 = base64encoder.encodeToString(
                                                    MessageDigest.getInstance("SHA-256").digest(actualSource));
                            }
                            if (actualSha256.equals(normalizeBase64Url(hash.getBase64ValuePart()))) {
                                return true;
                            }
                            break;
                        case SHA384:
                            if (actualSha384 == null) {
                                actualSha384 = base64encoder.encodeToString(
                                                    MessageDigest.getInstance("SHA-384").digest(actualSource));
                            }
                            if (actualSha384.equals(normalizeBase64Url(hash.getBase64ValuePart()))) {
                                return true;
                            }
                            break;
                        case SHA512:
                            if (actualSha512 == null) {
                                actualSha512 = base64encoder.encodeToString(
                                                    MessageDigest.getInstance("SHA-512").digest(actualSource));
                            }
                            if (actualSha512.equals(normalizeBase64Url(hash.getBase64ValuePart()))) {
                                return true;
                            }
                            break;
                        default:
                            throw new IllegalArgumentException("Unknown hash algorithm " + hash.getAlgorithm());
                    }
                }
            }
            catch (final NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }

        // This is not per spec, but matches implementations and the spec
        // author's intent: https://github.com/w3c/webappsec-csp/issues/426
        if (type == InlineType.Script && directive.strictDynamic() && !parserInserted.orElse(true)) {
            return true;
        }
        return false;
    }

    private static String normalizeBase64Url(final String input) {
        return input.replace('-', '+').replace('_', '/');
    }

    /**
     * Determines whether a URL matches a source list in the context of a given origin.
     * <p>
     * Implements the
     * <a href="https://w3c.github.io/webappsec-csp/#match-url-to-source-list">match a URL
     * to a source list</a> algorithm. This checks wildcards ({@code *}), scheme sources,
     * host sources, and the {@code 'self'} keyword against the provided URL.
     * </p>
     *
     * @param url the URL to check
     * @param list the host-source directive (source list) to match against
     * @param origin the origin of the protected resource, if known
     * @return {@code true} if the URL matches the source list
     */
    public static boolean doesUrlMatchSourceListInOrigin(final URLWithScheme url,
            final HostSourceDirective list,
            final Optional<? extends URLWithScheme> origin) {
        final String urlScheme = url.getScheme();
        if (list.star()) {
            // https://fetch.spec.whatwg.org/#network-scheme
            // Note that "ws" and "wss" are _not_ network schemes
            if (Objects.equals(urlScheme, "ftp")
                        || Objects.equals(urlScheme, "http")
                        || Objects.equals(urlScheme, "https")) {
                return true;
            }
            if (origin.isPresent() && Objects.equals(urlScheme, origin.get().getScheme())) {
                return true;
            }
        }
        for (final Scheme scheme : list.getSchemes()) {
            if (schemePartMatches(scheme.value(), urlScheme)) {
                return true;
            }
        }
        for (final Host expression : list.getHosts()) {
            final String scheme = expression.scheme();
            if (scheme != null) {
                if (!schemePartMatches(scheme, urlScheme)) {
                    continue;
                }
            }
            else {
                if (origin.isEmpty() || !schemePartMatches(origin.get().getScheme(), urlScheme)) {
                    continue;
                }
            }
            if (url.getHost() == null) {
                continue;
            }
            if (!hostPartMatches(expression.host(), url.getHost())) {
                continue;
            }
            // url.port is non-null whenever url.host is
            if (!portPartMatches(expression.port(), url.getPort(), urlScheme)) {
                continue;
            }
            if (!pathPartMatches(expression.path(), url.getPath())) {
                continue;
            }
            return true;
        }
        if (list.self()) {
            if (origin.isPresent()) {
                final URLWithScheme actualOrigin = origin.get();
                final String originScheme = actualOrigin.getScheme();
                if (
                        Objects.equals(actualOrigin.getHost(), url.getHost())
                        && (Objects.equals(actualOrigin.getPort(), url.getPort())
                                    || Objects.equals(actualOrigin.getPort(), URI.defaultPortForProtocol(originScheme))
                                    && Objects.equals(url.getPort(), URI.defaultPortForProtocol(urlScheme)))
                        && ("https".equals(urlScheme)
                                || "wss".equals(urlScheme)
                                || "http".equals(originScheme)
                                && ("http".equals(urlScheme) || "ws".equals(urlScheme)))
                ) {
                    return true;
                }
            }
        }
        return false;
    }

    // https://w3c.github.io/webappsec-csp/#scheme-part-match
    private static boolean schemePartMatches(final String a, final String b) {
        // Assumes inputs are already lowercased
        return a.equals(b)
                || "http".equals(a) && "https".equals(b)
                || "ws".equals(a) && ("wss".equals(b) || "http".equals(b) || "https".equals(b))
                || "wss".equals(a) && "https".equals(b);
    }

    // https://w3c.github.io/webappsec-csp/#host-part-match
    private static boolean hostPartMatches(final String a, final String b) {
        if (a.startsWith("*")) {
            final String remaining = a.substring(1);
            return b.toLowerCase(Locale.ROOT).endsWith(remaining.toLowerCase(Locale.ROOT));
        }

        if (!a.equalsIgnoreCase(b)) {
            return false;
        }

        final Matcher ipv4Matcher = Constants.IPv4address.matcher(a);
        final Matcher ipv6Matcher = Constants.IPv6addressWithOptionalBracket.matcher(a);
        final Matcher ipv6LoopbackMatcher = Constants.IPV6loopback.matcher(a);
        if ((ipv4Matcher.find() && !"127.0.0.1".equals(a)) || ipv6Matcher.find() || ipv6LoopbackMatcher.find()) {
            return false;
        }
        return true;
    }

    // https://w3c.github.io/webappsec-csp/#port-part-matches
    private static boolean portPartMatches(final int a, final int portB, final String schemeB) {
        if (a == Constants.EMPTY_PORT) {
            return portB == URI.defaultPortForProtocol(schemeB);
        }
        if (a == Constants.WILDCARD_PORT) {
            return true;
        }
        if (a == portB) {
            return true;
        }
        if (portB == Constants.EMPTY_PORT) {
            return a == URI.defaultPortForProtocol(schemeB);
        }
        return false;
    }

    // https://w3c.github.io/webappsec-csp/#path-part-match
    private static boolean pathPartMatches(String pathA, String pathB) {
        if (pathA == null) {
            pathA = "";
        }
        if (pathB == null) {
            pathB = "";
        }

        if (pathA.isEmpty()) {
            return true;
        }

        if ("/".equals(pathA) && pathB.isEmpty()) {
            return true;
        }

        final boolean exactMatch = !pathA.endsWith("/");

        final List<String> pathListA = Utils.strictlySplit(pathA, '/');
        final List<String> pathListB = Utils.strictlySplit(pathB, '/');

        if (pathListA.size() > pathListB.size()) {
            return false;
        }

        if (exactMatch && pathListA.size() != pathListB.size()) {
            return false;
        }

        if (!exactMatch) {
            pathListA.remove(pathListA.size() - 1);
        }

        final Iterator<String> it1 = pathListA.iterator();
        final Iterator<String> it2 = pathListB.iterator();

        while (it1.hasNext()) {
            final String a = Utils.decodeString(it1.next());
            final String b = Utils.decodeString(it2.next());
            if (!a.equals(b)) {
                return false;
            }
        }
        return true;
    }

    // Utilities and helper classes

    static void enforceAscii(final String s) {
        if (!StandardCharsets.US_ASCII.newEncoder().canEncode(s)) {
            throw new IllegalArgumentException("string is not ascii: \"" + s + "\"");
        }
    }

    private record NamedDirective(String name_, Directive directive_) {
    }

    /**
     * The severity level of a parsing error or warning.
     * <ul>
     *   <li>{@link #Info} — strictly informative</li>
     *   <li>{@link #Warning} — the input matches the grammar but is meaningless, duplicated,
     *       or otherwise problematic</li>
     *   <li>{@link #Error} — the input does not match the grammar</li>
     * </ul>
     */
    public enum Severity {
            /** Severity Info. */
            Info,
            /** Severity Warning. */
            Warning,
            /** Severity Error. */
            Error }

    /**
     * A callback interface for receiving errors and warnings encountered while
     * parsing a single serialized CSP.
     * <p>
     * A {@code valueIndex} of {@code -1} indicates that the error does not pertain
     * to a specific value within the directive.
     * </p>
     */
    @FunctionalInterface
    public interface PolicyErrorConsumer {
        /** PolicyErrorConsumer ignored. */
        PolicyErrorConsumer ignored = (severity, message, directiveIndex, valueIndex) -> { };

        /**
         * Called when a parsing error or warning is encountered.
         *
         * @param severity the severity of the issue
         * @param message a human-readable description of the issue
         * @param directiveIndex the zero-based index of the directive within the policy
         * @param valueIndex the zero-based index of the value within the directive,
         *        or {@code -1} if the issue does not pertain to a specific value
         */
        void add(Severity severity, String message, int directiveIndex, int valueIndex);
    }

    /**
     * A callback interface for receiving errors and warnings encountered while
     * parsing a serialized CSP list (comma-separated policies).
     * <p>
     * A {@code valueIndex} of {@code -1} indicates that the error does not pertain
     * to a specific value within the directive.
     * </p>
     */
    @FunctionalInterface
    public interface PolicyListErrorConsumer {
        /** PolicyListErrorConsumer ignored. */
        PolicyListErrorConsumer ignored = (severity, message, policyIndex, directiveIndex, valueIndex) -> { };

        /**
         * Called when a parsing error or warning is encountered.
         *
         * @param severity the severity of the issue
         * @param message a human-readable description of the issue
         * @param policyIndex the zero-based index of the policy within the comma-separated list
         * @param directiveIndex the zero-based index of the directive within that policy
         * @param valueIndex the zero-based index of the value within the directive,
         *        or {@code -1} if the issue does not pertain to a specific value
         */
        void add(Severity severity, String message, int policyIndex, int directiveIndex, int valueIndex);
    }
}
