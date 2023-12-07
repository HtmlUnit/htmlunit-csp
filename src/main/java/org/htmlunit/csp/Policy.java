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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.EnumMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.htmlunit.csp.directive.FrameAncestorsDirective;
import org.htmlunit.csp.directive.HostSourceDirective;
import org.htmlunit.csp.directive.PluginTypesDirective;
import org.htmlunit.csp.directive.ReportUriDirective;
import org.htmlunit.csp.directive.SandboxDirective;
import org.htmlunit.csp.directive.SourceExpressionDirective;
import org.htmlunit.csp.url.GUID;
import org.htmlunit.csp.url.URI;
import org.htmlunit.csp.url.URLWithScheme;
import org.htmlunit.csp.value.Hash;
import org.htmlunit.csp.value.Host;
import org.htmlunit.csp.value.MediaType;
import org.htmlunit.csp.value.RFC7230Token;
import org.htmlunit.csp.value.Scheme;

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

    private List<NamedDirective> directives_ = new ArrayList<>();

    private SourceExpressionDirective baseUri_;
    private boolean blockAllMixedContent_;
    private SourceExpressionDirective formAction_;
    private FrameAncestorsDirective frameAncestors_;
    private SourceExpressionDirective navigateTo_;
    private PluginTypesDirective pluginTypes_;
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

    // https://w3c.github.io/webappsec-csp/#parse-serialized-policy-list
    public static PolicyList parseSerializedCSPList(final String serialized,
                        final PolicyListErrorConsumer policyListErrorConsumer) {
        // "A serialized CSP list is an ASCII string"
        enforceAscii(serialized);

        final List<Policy> policies = new ArrayList<>();

        // java's lambdas are dumb
        final int[] index = {0};
        final PolicyErrorConsumer policyErrorConsumer =
                (Severity severity, String message, int directiveIndex, int valueIndex) -> {
                    policyListErrorConsumer.add(severity, message, index[0], directiveIndex, valueIndex);
                };

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

    // https://w3c.github.io/webappsec-csp/#parse-serialized-policy
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
                (Severity severity, String message, int valueIndex) -> {
                    policyErrorConsumer.add(severity, message, index[0], valueIndex);
                };

        final Policy policy = new Policy();

        // https://infra.spec.whatwg.org/#strictly-split
        for (final String token : serialized.split(";")) {
            final String strippedLeadingAndTrailingWhitespace = stripTrailingWhitespace(stripLeadingWhitespace(token));
            if (strippedLeadingAndTrailingWhitespace.isEmpty()) {
                ++index[0];
                continue;
            }
            final String directiveName =
                            collect(strippedLeadingAndTrailingWhitespace, "[^" + Constants.WHITESPACE_CHARS + "]+");

            // Note: we do not lowercase directive names or
            // skip duplicates during parsing, to allow round-tripping even invalid policies

            final String remainingToken = strippedLeadingAndTrailingWhitespace.substring(directiveName.length());

            final List<String> directiveValues = Utils.splitOnAsciiWhitespace(remainingToken);

            policy.add(directiveName, directiveValues, directiveErrorConsumer);

            ++index[0];
        }

        return policy;
    }

    // Manipulation APIs

    // We do not provide a generic method for updating an existing directive in-place.
    // Just remove the existing one and add it back.
    private Directive add(final String name, final List<String> values,
                            final Directive.DirectiveErrorConsumer directiveErrorConsumer) {
        enforceAscii(name);

        // the parser will never hit these errors by construction, but use of the manipulation APIs can
        if (Directive.containsNonDirectiveCharacter.test(name)) {
            throw new IllegalArgumentException("directive names must not contain whitespace, ',', or ';'");
        }
        if (name.isEmpty()) {
            throw new IllegalArgumentException("directive names must not be empty");
        }

        boolean wasDupe = false;
        final Directive newDirective;
        final String lowcaseDirectiveName = name.toLowerCase(Locale.ROOT);
        switch (lowcaseDirectiveName) {
            case "base-uri": {
                // https://w3c.github.io/webappsec-csp/#directive-base-uri
                final SourceExpressionDirective thisDirective
                        = new SourceExpressionDirective(values, directiveErrorConsumer);
                if (baseUri_ == null) {
                    baseUri_ = thisDirective;
                }
                else {
                    wasDupe = true;
                }
                newDirective = thisDirective;
                break;
            }
            case "block-all-mixed-content": {
                // https://www.w3.org/TR/mixed-content/#strict-opt-in
                if (!blockAllMixedContent_) {
                    if (!values.isEmpty()) {
                        directiveErrorConsumer.add(Severity.Error,
                                        "The block-all-mixed-content directive does not support values", 0);
                    }
                    blockAllMixedContent_ = true;
                }
                else {
                    wasDupe = true;
                }
                newDirective = new Directive(values);
                break;
            }
            case "form-action": {
                // https://w3c.github.io/webappsec-csp/#directive-form-action
                final SourceExpressionDirective thisDirective
                                = new SourceExpressionDirective(values, directiveErrorConsumer);
                if (formAction_ == null) {
                    formAction_ = thisDirective;
                }
                else {
                    wasDupe = true;
                }
                newDirective = thisDirective;
                break;
            }
            case "frame-ancestors": {
                // https://w3c.github.io/webappsec-csp/#directive-frame-ancestors
                // TODO contemplate warning for paths, which are always ignored: frame-ancestors only matches
                // against origins: https://w3c.github.io/webappsec-csp/#frame-ancestors-navigation-response
                final FrameAncestorsDirective thisDirective
                            = new FrameAncestorsDirective(values, directiveErrorConsumer);
                if (frameAncestors_ == null) {
                    frameAncestors_ = thisDirective;
                }
                else {
                    wasDupe = true;
                }
                newDirective = thisDirective;
                break;
            }
            case "navigate-to": {
                // https://w3c.github.io/webappsec-csp/#directive-navigate-to
                // For some ungodly reason "navigate-to" is a list of source expressions while "frame-ancestors" is not
                // There is no logic here
                final SourceExpressionDirective thisDirective
                            = new SourceExpressionDirective(values, directiveErrorConsumer);
                if (navigateTo_ == null) {
                    navigateTo_ = thisDirective;
                }
                else {
                    wasDupe = true;
                }
                newDirective = thisDirective;
                break;
            }
            case "plugin-types": {
                // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/plugin-types
                directiveErrorConsumer.add(Severity.Warning, "The plugin-types directive has been deprecated", -1);
                final PluginTypesDirective thisDirective = new PluginTypesDirective(values, directiveErrorConsumer);
                if (pluginTypes_ == null) {
                    pluginTypes_ = thisDirective;
                }
                else {
                    wasDupe = true;
                }
                newDirective = thisDirective;
                break;
            }
            case "report-to": {
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
            }
            case "report-uri": {
                // https://w3c.github.io/webappsec-csp/#directive-report-uri
                directiveErrorConsumer.add(Severity.Warning,
                        "The report-uri directive has been deprecated in favor of the new report-to directive", -1);

                final ReportUriDirective thisDirective = new ReportUriDirective(values, directiveErrorConsumer);
                if (reportUri_ == null) {
                    reportUri_ = thisDirective;
                }
                else {
                    wasDupe = true;
                }
                newDirective = thisDirective;
                break;
            }
            case "sandbox": {
                // https://w3c.github.io/webappsec-csp/#directive-sandbox
                final SandboxDirective thisDirective = new SandboxDirective(values, directiveErrorConsumer);
                if (sandbox_ == null) {
                    sandbox_ = thisDirective;
                }
                else {
                    wasDupe = true;
                }
                newDirective = thisDirective;
                break;
            }
            case "upgrade-insecure-requests": {
                // https://www.w3.org/TR/upgrade-insecure-requests/#delivery
                if (!upgradeInsecureRequests_) {
                    if (!values.isEmpty()) {
                        directiveErrorConsumer.add(Severity.Error,
                                "The upgrade-insecure-requests directive does not support values", 0);
                    }
                    upgradeInsecureRequests_ = true;
                }
                else {
                    wasDupe = true;
                }
                newDirective = new Directive(values);
                break;
            }
            default: {
                if (!Directive.IS_DIRECTIVE_NAME.test(name)) {
                    directiveErrorConsumer.add(Severity.Error,
                                    "Directive name " + name
                                        + " contains characters outside the range ALPHA / DIGIT / \"-\"", -1);
                    newDirective = new Directive(values);
                    break;
                }
                final FetchDirectiveKind fetchDirectiveKind = FetchDirectiveKind.fromString(lowcaseDirectiveName);
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
                directiveErrorConsumer.add(Severity.Warning, "Unrecognized directive " + lowcaseDirectiveName, -1);
                newDirective = new Directive(values);
                break;
            }
        }

        directives_.add(new NamedDirective(name, newDirective));
        if (wasDupe) {
            directiveErrorConsumer.add(Severity.Warning, "Duplicate directive " + lowcaseDirectiveName, -1);
        }
        return newDirective;
    }

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
                out.append(' ');
                out.append(value);
            }
        }
        return out.toString();
    }

    // Accessors

    public Optional<SourceExpressionDirective> baseUri() {
        return Optional.ofNullable(baseUri_);
    }

    public boolean blockAllMixedContent() {
        return blockAllMixedContent_;
    }

    public Optional<SourceExpressionDirective> formAction() {
        return Optional.ofNullable(formAction_);
    }

    public Optional<FrameAncestorsDirective> frameAncestors() {
        return Optional.ofNullable(frameAncestors_);
    }

    public Optional<SourceExpressionDirective> navigateTo() {
        return Optional.ofNullable(navigateTo_);
    }

    public Optional<PluginTypesDirective> pluginTypes() {
        return Optional.ofNullable(pluginTypes_);
    }

    public Optional<FetchDirectiveKind> prefetchSrc() {
        return Optional.ofNullable(prefetchSrc_);
    }

    public Optional<RFC7230Token> reportTo() {
        return Optional.ofNullable(reportTo_);
    }

    public Optional<ReportUriDirective> reportUri() {
        return Optional.ofNullable(reportUri_);
    }

    public Optional<SandboxDirective> sandbox() {
        return Optional.ofNullable(sandbox_);
    }

    public boolean upgradeInsecureRequests() {
        return upgradeInsecureRequests_;
    }

    public Optional<SourceExpressionDirective> getFetchDirective(final FetchDirectiveKind kind) {
        return Optional.ofNullable(fetchDirectives_.get(kind));
    }

    // High-level querying

    /*
    For each of these arguments, if the value provided is Optional.empty(), this method will return `true`
    only if there is no value for the Optional.of() case of that parameter which would cause it to return `false`.
    Take care with `integrity`; your script can be allowed by CSP but blocked by SRI if its integrity is wrong.
    See https://www.w3.org/TR/SRI/
    Also note that the notion of "the URL" is a little fuzzy because there can be redirects.
    https://w3c.github.io/webappsec-csp/#script-pre-request
    https://w3c.github.io/webappsec-csp/#script-post-request
     */
    public boolean allowsExternalScript(final Optional<String> nonce, final Optional<String> integrity,
            final Optional<URLWithScheme> scriptUrl, final Optional<Boolean> parserInserted,
            final Optional<URLWithScheme> origin) {
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
                    && directive.getNonces().stream().anyMatch(n -> n.getBase64ValuePart().equals(actualNonce))) {
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
                if (!parsedIntegritySource.isPresent()) {
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
        if (scriptUrl.isPresent()) {
            return doesUrlMatchSourceListInOrigin(scriptUrl.get(), directive, origin);
        }
        return false;
    }

    // https://w3c.github.io/webappsec-csp/#script-src-elem-inline
    public boolean allowsInlineScript(final Optional<String> nonce,
            final Optional<String> source, final Optional<Boolean> parserInserted) {
        if (sandbox_ != null && !sandbox_.allowScripts()) {
            return false;
        }
        return doesElementMatchSourceListForTypeAndSource(InlineType.Script, nonce, source, parserInserted);
    }

    // https://w3c.github.io/webappsec-csp/#script-src-attr-inline
    public boolean allowsScriptAsAttribute(final Optional<String> source) {
        if (sandbox_ != null && !sandbox_.allowScripts()) {
            return false;
        }
        return doesElementMatchSourceListForTypeAndSource(
                InlineType.ScriptAttribute, Optional.empty(), source, Optional.empty());
    }

    // https://w3c.github.io/webappsec-csp/#can-compile-strings
    public boolean allowsEval() {
        // This is done in prose, not in a table
        final FetchDirectiveKind governingDirective =
                fetchDirectives_
                    .containsKey(FetchDirectiveKind.ScriptSrc)
                        ? FetchDirectiveKind.ScriptSrc : FetchDirectiveKind.DefaultSrc;
        final SourceExpressionDirective sourceList = fetchDirectives_.get(governingDirective);
        return sourceList == null || sourceList.unsafeEval();
    }

    // https://w3c.github.io/webappsec-csp/#navigate-to-pre-navigate
    // https://w3c.github.io/webappsec-csp/#navigate-to-navigation-response
    // Strictly speaking this requires the _response_'s CSP as well, because of frame-ancestors.
    // But we are maybe not going to worry about that.
    // Note: it is nonsensical to provide redirectedTo if redirected is Optional.of(false)
    // Note: this also does not handle `javascript:` navigation; there's an explicit API for that
    public boolean allowsNavigation(final Optional<URLWithScheme> to, final Optional<Boolean> redirected,
            final Optional<URLWithScheme> redirectedTo, final Optional<URLWithScheme> origin) {
        if (navigateTo_ == null) {
            return true;
        }
        if (navigateTo_.unsafeAllowRedirects()) {
            // if unsafe-allow-redirects is present, check `to` in non-redirect or maybe-non-redirect cases
            if (!redirected.orElse(false)) {
                if (!to.isPresent()) {
                    return false;
                }
                if (!doesUrlMatchSourceListInOrigin(to.get(), navigateTo_, origin)) {
                    return false;
                }
            }
            // if unsafe-allow-redirects is present, check `redirectedTo` in redirect or maybe-redirect cases
            if (redirected.orElse(true)) {
                if (!redirectedTo.isPresent()) {
                    return false;
                }
                if (!doesUrlMatchSourceListInOrigin(redirectedTo.get(), navigateTo_, origin)) {
                    return false;
                }
            }
        }
        else {
            // if unsafe-allow-redirects is absent, always and only check `to`
            if (!to.isPresent()) {
                return false;
            }
            if (!doesUrlMatchSourceListInOrigin(to.get(), navigateTo_, origin)) {
                return false;
            }
        }
        return true;
    }

    // https://w3c.github.io/webappsec-csp/#navigate-to-pre-navigate
    // https://w3c.github.io/webappsec-csp/#navigate-to-navigation-response
    // Note: it is nonsensical to provide redirectedTo if redirected is Optional.of(false)
    public boolean allowsFormAction(final Optional<URLWithScheme> to, final Optional<Boolean> redirected,
            final Optional<URLWithScheme> redirectedTo, final Optional<URLWithScheme> origin) {
        if (sandbox_ != null && !sandbox_.allowForms()) {
            return false;
        }
        if (formAction_ != null) {
            if (!to.isPresent()) {
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

    // NB: the hashes (for unsafe-hashes) are supposed to include the javascript: part, per spec
    public boolean allowsJavascriptUrlNavigation(final Optional<String> source, final Optional<URLWithScheme> origin) {
        return allowsNavigation(
                Optional.of(
                            new GUID("javascript", source.orElse(""))),
                Optional.of(false), Optional.empty(), origin)
                &&
                    doesElementMatchSourceListForTypeAndSource(
                                InlineType.Navigation, Optional.empty(),
                                            source.map(s -> "javascript:" + s), Optional.of(false));
    }

    public boolean allowsExternalStyle(final Optional<String> nonce,
            final Optional<URLWithScheme> styleUrl, final Optional<URLWithScheme> origin) {
        // Effective directive is "script-src-elem" per
        // https://w3c.github.io/webappsec-csp/#effective-directive-for-a-request
        final SourceExpressionDirective directive
                = getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.StyleSrcElem).orElse(null);
        if (directive == null) {
            return true;
        }
        if (nonce.isPresent()) {
            final String actualNonce = nonce.get();
            if (actualNonce.length() > 0
                    && directive.getNonces().stream().anyMatch(n -> n.getBase64ValuePart().equals(actualNonce))) {
                return true;
            }
        }
        // integrity is not used: https://github.com/w3c/webappsec-csp/issues/430
        if (styleUrl.isPresent()) {
            return doesUrlMatchSourceListInOrigin(styleUrl.get(), directive, origin);
        }
        return false;
    }

    public boolean allowsInlineStyle(final Optional<String> nonce, final Optional<String> source) {
        return doesElementMatchSourceListForTypeAndSource(InlineType.Style, nonce, source, Optional.empty());
    }

    public boolean allowsStyleAsAttribute(final Optional<String> source) {
        return doesElementMatchSourceListForTypeAndSource(
                InlineType.StyleAttribute, Optional.empty(), source, Optional.empty());
    }

    public boolean allowsFrame(final Optional<URLWithScheme> source, final Optional<URLWithScheme> origin) {
        final SourceExpressionDirective sourceList
            = getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.FrameSrc).orElse(null);
        if (sourceList == null) {
            return true;
        }
        if (!source.isPresent()) {
            return false;
        }
        return doesUrlMatchSourceListInOrigin(source.get(), sourceList, origin);
    }

    public boolean allowsFrameAncestor(final Optional<URLWithScheme> source, final Optional<URLWithScheme> origin) {
        if (frameAncestors_ == null) {
            return true;
        }
        if (!source.isPresent()) {
            return false;
        }
        return doesUrlMatchSourceListInOrigin(source.get(), frameAncestors_, origin);
    }

    // This assumes that a `ws:` or `wss:` URL is being used with `new WebSocket` specifically
    public boolean allowsConnection(final Optional<URLWithScheme> source, final Optional<URLWithScheme> origin) {
        final SourceExpressionDirective sourceList
                = getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.ConnectSrc).orElse(null);
        if (sourceList == null) {
            return true;
        }
        if (!source.isPresent()) {
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

    public boolean allowsFont(final Optional<URLWithScheme> source, final Optional<URLWithScheme> origin) {
        final SourceExpressionDirective sourceList
                = getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.FontSrc).orElse(null);
        if (sourceList == null) {
            return true;
        }
        if (!source.isPresent()) {
            return false;
        }
        return doesUrlMatchSourceListInOrigin(source.get(), sourceList, origin);
    }

    public boolean allowsImage(final Optional<URLWithScheme> source, final Optional<URLWithScheme> origin) {
        final SourceExpressionDirective sourceList
                = getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.ImgSrc).orElse(null);
        if (sourceList == null) {
            return true;
        }
        if (!source.isPresent()) {
            return false;
        }
        return doesUrlMatchSourceListInOrigin(source.get(), sourceList, origin);
    }

    public boolean allowsApplicationManifest(final Optional<URLWithScheme> source,
                    final Optional<URLWithScheme> origin) {
        final SourceExpressionDirective sourceList
                = getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.ManifestSrc).orElse(null);
        if (sourceList == null) {
            return true;
        }
        if (!source.isPresent()) {
            return false;
        }
        return doesUrlMatchSourceListInOrigin(source.get(), sourceList, origin);
    }

    public boolean allowsMedia(final Optional<URLWithScheme> source, final Optional<URLWithScheme> origin) {
        final SourceExpressionDirective sourceList
                = getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.MediaSrc).orElse(null);
        if (sourceList == null) {
            return true;
        }
        if (!source.isPresent()) {
            return false;
        }
        return doesUrlMatchSourceListInOrigin(source.get(), sourceList, origin);
    }

    public boolean allowsObject(final Optional<URLWithScheme> source, final Optional<URLWithScheme> origin) {
        final SourceExpressionDirective sourceList
                = getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.ObjectSrc).orElse(null);
        if (sourceList == null) {
            return true;
        }
        if (!source.isPresent()) {
            return false;
        }
        return doesUrlMatchSourceListInOrigin(source.get(), sourceList, origin);
    }

    // Not actually spec'd properly; see https://github.com/whatwg/fetch/issues/1008
    public boolean allowsPrefetch(final Optional<URLWithScheme> source, final Optional<URLWithScheme> origin) {
        final SourceExpressionDirective sourceList
                = getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.PrefetchSrc).orElse(null);
        if (sourceList == null) {
            return true;
        }
        if (!source.isPresent()) {
            return false;
        }
        return doesUrlMatchSourceListInOrigin(source.get(), sourceList, origin);
    }

    public boolean allowsWorker(final Optional<URLWithScheme> source, final Optional<URLWithScheme> origin) {
        final SourceExpressionDirective sourceList
                = getGoverningDirectiveForEffectiveDirective(FetchDirectiveKind.WorkerSrc).orElse(null);
        if (sourceList == null) {
            return true;
        }
        if (!source.isPresent()) {
            return false;
        }
        return doesUrlMatchSourceListInOrigin(source.get(), sourceList, origin);
    }

    public boolean allowsPlugin(final Optional<MediaType> mediaType) {
        if (pluginTypes_ == null) {
            return true;
        }
        if (!mediaType.isPresent()) {
            return false;
        }
        return pluginTypes_.getMediaTypes().contains(mediaType.get());
    }

    // https://w3c.github.io/webappsec-csp/#should-directive-execute
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
                        final Optional<String> nonce, final Optional<String> source,
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
                    && directive.getNonces().stream().anyMatch(n -> n.getBase64ValuePart().equals(actualNonce))) {
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

    // https://w3c.github.io/webappsec-csp/#match-url-to-source-list
    public static boolean doesUrlMatchSourceListInOrigin(final URLWithScheme url,
            final HostSourceDirective list, final Optional<URLWithScheme> origin) {
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
            if (schemePartMatches(scheme.getValue(), urlScheme)) {
                return true;
            }
        }
        for (final Host expression : list.getHosts()) {
            final String scheme = expression.getScheme();
            if (scheme != null) {
                if (!schemePartMatches(scheme, urlScheme)) {
                    continue;
                }
            }
            else {
                if (!origin.isPresent() || !schemePartMatches(origin.get().getScheme(), urlScheme)) {
                    continue;
                }
            }
            if (url.getHost() == null) {
                continue;
            }
            if (!hostPartMatches(expression.getHost(), url.getHost())) {
                continue;
            }
            // url.port is non-null whenever url.host is
            if (!portPartMatches(expression.getPort(), url.getPort(), urlScheme)) {
                continue;
            }
            if (!pathPartMatches(expression.getPath(), url.getPath())) {
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
        // Assumes inputs are already lowcased
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

    private static String stripLeadingWhitespace(final String string) {
        return string.replaceFirst("^[" + Constants.WHITESPACE_CHARS + "]+", "");
    }

    private static String stripTrailingWhitespace(final String string) {
        return Constants.TRAILING_WHITESPACE_PATTERN.matcher(string).replaceAll("");
    }

    private static String collect(final String input, final String regex) {
        final Matcher matcher = Pattern.compile(regex).matcher(input);
        if (!matcher.find() || matcher.start() != 0) {
            return "";
        }
        return input.substring(0, matcher.end());
    }

    private static final class NamedDirective {
        private final String name_;
        private final Directive directive_;

        private NamedDirective(final String name, final Directive directive) {
            name_ = name;
            directive_ = directive;
        }
    }

    // Info: strictly informative
    // Warning: it matches the grammar, but is meaningless, duplicated, or otherwise problematic
    // Error: it does not match the grammar
    public enum Severity { Info, Warning, Error }

    @FunctionalInterface
    public interface PolicyErrorConsumer {
        void add(Severity severity, String message, int directiveIndex,
                int valueIndex); // valueIndex = -1 for errors not pertaining to a value

        PolicyErrorConsumer ignored = (severity, message, directiveIndex, valueIndex) -> { };
    }

    @FunctionalInterface
    public interface PolicyListErrorConsumer {
        void add(Severity severity, String message, int policyIndex, int directiveIndex,
                int valueIndex); // valueIndex = -1 for errors not pertaining to a value

        PolicyListErrorConsumer ignored = (severity, message, policyIndex, directiveIndex, valueIndex) -> { };
    }
}
