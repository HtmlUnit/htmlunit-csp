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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import org.htmlunit.csp.Policy;
import org.htmlunit.csp.value.Hash;
import org.htmlunit.csp.value.Nonce;

/**
 * Represents a CSP directive whose values form a
 * <a href="https://w3c.github.io/webappsec-csp/#grammardef-serialized-source-list">
 * source-expression list</a>.
 * <p>
 * In addition to the host-sources and scheme-sources inherited from
 * {@link HostSourceDirective}, a source-expression list may contain keyword
 * sources ({@code 'unsafe-inline'}, {@code 'unsafe-eval'}, {@code 'strict-dynamic'},
 * {@code 'unsafe-hashes'}, {@code 'report-sample'}, {@code 'unsafe-allow-redirects'},
 * {@code 'wasm-unsafe-eval'}), nonce-sources ({@code 'nonce-...'}) and hash-sources
 * ({@code 'sha256-...'}, {@code 'sha384-...'}, {@code 'sha512-...'}).
 * </p>
 * <p>
 * This class is used for most fetch directives ({@code script-src}, {@code style-src},
 * {@code default-src}, {@code img-src}, etc.) as well as {@code base-uri},
 * {@code form-action}, and {@code navigate-to}.
 * </p>
 */
public class SourceExpressionDirective extends HostSourceDirective {
    private static final String REPORT_SAMPLE = "'report-sample'";
    private static final String UNSAFE_INLINE = "'unsafe-inline'";
    private static final String STRICT_DYNAMIC = "'strict-dynamic'";
    private static final String UNSAFE_ALLOW_REDIRECTS = "'unsafe-allow-redirects'";
    private static final String UNSAFE_EVAL = "'unsafe-eval'";
    private static final String UNSAFE_HASHES = "'unsafe-hashes'";

    /**
     * <a href="https://developer.mozilla.org/en-US/docs/Web/
     * HTTP/Headers/Content-Security-Policy/script-src#unsafe_webassembly_execution">
     * Unsafe WebAssembly execution</a>
     */
    private static final String WASM_UNSAFE_EVAL = "'wasm-unsafe-eval'";

    private boolean unsafeInline_;
    private boolean unsafeEval_;
    private boolean strictDynamic_;
    private boolean unsafeHashes_;
    private boolean reportSample_;
    private boolean unsafeAllowRedirects_;
    private boolean unsafeWasm_;

    // In practice, these are probably small enough for Lists to be faster than LinkedHashSets
    private final List<Nonce> nonces_ = new ArrayList<>();
    private final List<Hash> hashes_ = new ArrayList<>();

    /**
     * Parses a source-expression directive from the given list of values.
     * <p>
     * Each token is classified as a keyword, nonce, hash, host-source, or scheme-source.
     * Errors and warnings (duplicates, unrecognised tokens, empty lists, etc.) are
     * reported through the supplied {@code errors} consumer.
     * </p>
     *
     * @param values the raw string values for this directive
     * @param errors consumer that receives parsing errors and warnings
     */
    public SourceExpressionDirective(final List<String> values, final DirectiveErrorConsumer errors) {
        super(values);

        int index = 0;
        for (final String token : values) {
            // The CSP grammar uses ABNF grammars, whose strings
            // are case-insensitive: https://tools.ietf.org/html/rfc5234
            // This needs to be ASCII-lowercase, so that `'strIct-dynamic'` still parses in Turkey
            final String lowercaseToken = token.toLowerCase(Locale.ROOT);
            switch (lowercaseToken) {
                case UNSAFE_INLINE:
                    if (unsafeInline_) {
                        errors.add(Policy.Severity.Warning, "Duplicate source-expression 'unsafe-inline'", index);
                    }
                    else {
                        unsafeInline_ = true;
                    }
                    break;
                case UNSAFE_EVAL:
                    if (unsafeEval_) {
                        errors.add(Policy.Severity.Warning, "Duplicate source-expression 'unsafe-eval'", index);
                    }
                    else {
                        unsafeEval_ = true;
                    }
                    break;
                case STRICT_DYNAMIC:
                    if (strictDynamic_) {
                        errors.add(Policy.Severity.Warning, "Duplicate source-expression 'strict-dynamic'", index);
                    }
                    else {
                        strictDynamic_ = true;
                    }
                    break;
                case UNSAFE_HASHES:
                    if (unsafeHashes_) {
                        errors.add(Policy.Severity.Warning, "Duplicate source-expression 'unsafe-hashes'", index);
                    }
                    else {
                        unsafeHashes_ = true;
                    }
                    break;
                case WASM_UNSAFE_EVAL:
                    if (unsafeWasm_) {
                        errors.add(Policy.Severity.Warning, "Duplicate source-expression " + WASM_UNSAFE_EVAL, index);
                    }
                    else {
                        unsafeWasm_ = true;
                    }
                    break;
                case REPORT_SAMPLE:
                    if (reportSample_) {
                        errors.add(Policy.Severity.Warning, "Duplicate source-expression 'report-sample'", index);
                    }
                    else {
                        reportSample_ = true;
                    }
                    break;
                case UNSAFE_ALLOW_REDIRECTS:
                    if (unsafeAllowRedirects_) {
                        errors.add(Policy.Severity.Warning,
                                "Duplicate source-expression 'unsafe-allow-redirects'", index);
                    }
                    else {
                        unsafeAllowRedirects_ = true;
                    }
                    break;
                case "'unsafe-redirect'":
                    errors.add(Policy.Severity.Error,
                                    "'unsafe-redirect' has been removed from CSP as of version 2.0", index);
                    break;
                case "'unsafe-hashed-attributes'":
                    errors.add(Policy.Severity.Error,
                            "'unsafe-hashed-attributes' was renamed to 'unsafe-hashes' in June 2018", index);
                    break;
                default:
                    if (lowercaseToken.startsWith("'nonce-")) {
                        // the above check is not strictly necessary, but allows us to
                        // give a better message for nonce-likes which don't match the base64 grammar
                        final Optional<Nonce> nonce = Nonce.parseNonce(token);
                        if (nonce.isPresent()) {
                            addNonce(nonce.get(), index, errors);
                        }
                        else {
                            errors.add(Policy.Severity.Error, "Unrecognised nonce " + token, index);
                        }
                        break;
                    }
                    else if (lowercaseToken.startsWith("'sha")) {
                        // the above check is not strictly necessary, but allows us to give
                        // a better message for hash-likes which don't match the base64 grammar
                        final Optional<Hash> hash = Hash.parseHash(token);
                        if (hash.isPresent()) {
                            addHash(hash.get(), index, errors);
                        }
                        else {
                            errors.add(Policy.Severity.Error,
                                    "'sha...' source-expression uses an unrecognized algorithm or "
                                    + "does not match the base64-value grammar (or is missing its trailing \"'\")",
                                    index);
                        }
                        break;
                    }
                    else {
                        addHostOrSchemeDuringConstruction(token, lowercaseToken, "source-expression", index, errors);
                    }
            }
            ++index;
        }

        if (getNone() != null && values.size() > 1) {
            errors.add(Policy.Severity.Error, "'none' must not be combined with any other source-expression", 1);
        }

        if (values.isEmpty()) {
            errors.add(Policy.Severity.Error, "Source-expression lists cannot be empty (use 'none' instead)", -1);
        }
    }

    private boolean addNonce(final Nonce nonce, final int index, final DirectiveErrorConsumer errors) {
        if (nonces_.contains(nonce)) {
            errors.add(Policy.Severity.Warning, "Duplicate nonce " + nonce.toString(), index);
            return false;
        }

        nonces_.add(nonce);
        return true;
    }

    private boolean addHash(final Hash hash, final int index, final DirectiveErrorConsumer errors) {
        if (hashes_.contains(hash)) {
            errors.add(Policy.Severity.Warning, "Duplicate hash " + hash.toString(), index);
            return false;
        }

        if (hash.getBase64ValuePart().length() != hash.getAlgorithm().getLength()) {
            errors.add(Policy.Severity.Warning,
                    "Wrong length for " + hash.getAlgorithm()
                    + ": expected " + hash.getAlgorithm().getLength()
                    + ", got " + hash.getBase64ValuePart().length(), index);
        }

        if (hash.getBase64ValuePart().contains("_") || hash.getBase64ValuePart().contains("-")) {
            errors.add(Policy.Severity.Warning, "'_' and '-' in hashes can never match actual elements", index);
        }

        hashes_.add(hash);
        return true;
    }

    // Accessors

    // TODO it would be nice to warn for adding things which are irrelevant
    // Though it would be better to just not provide those methods at all
    // But that kind of conflicts with the "only error on things which don't match the grammar" goal
    // See also https://github.com/w3c/webappsec-csp/issues/431

    /**
     * Returns whether the {@code 'unsafe-inline'} keyword is present.
     * <p>
     * When present (and not neutralised by nonces/hashes), inline scripts and styles
     * are permitted.
     * </p>
     *
     * @return {@code true} if {@code 'unsafe-inline'} is present
     */
    public boolean unsafeInline() {
        return unsafeInline_;
    }

    /**
     * Returns whether the {@code 'unsafe-eval'} keyword is present.
     * <p>
     * When present, {@code eval()} and similar string-to-code mechanisms are permitted.
     * </p>
     *
     * @return {@code true} if {@code 'unsafe-eval'} is present
     */
    public boolean unsafeEval() {
        return unsafeEval_;
    }

    /**
     * Returns whether the {@code 'strict-dynamic'} keyword is present.
     * <p>
     * When present, trust is propagated to scripts loaded by already-trusted scripts,
     * and host-/scheme-based allowlists are ignored.
     * </p>
     *
     * @return {@code true} if {@code 'strict-dynamic'} is present
     * @see <a href="https://w3c.github.io/webappsec-csp/#strict-dynamic-usage">
     *      strict-dynamic usage</a>
     */
    public boolean strictDynamic() {
        return strictDynamic_;
    }

    /**
     * Returns whether the {@code 'unsafe-hashes'} keyword is present.
     * <p>
     * When present, inline event handlers and {@code javascript:} URLs can be
     * allowed by matching their content against the hash-sources in this directive.
     * </p>
     *
     * @return {@code true} if {@code 'unsafe-hashes'} is present
     */
    public boolean unsafeHashes() {
        return unsafeHashes_;
    }

    /**
     * Returns whether the {@code 'report-sample'} keyword is present.
     * <p>
     * When present, violation reports include a sample of the violating code.
     * </p>
     *
     * @return {@code true} if {@code 'report-sample'} is present
     */
    public boolean reportSample() {
        return reportSample_;
    }

    /**
     * Returns whether the {@code 'unsafe-allow-redirects'} keyword is present.
     * <p>
     * When present in a {@code navigate-to} directive, navigation is checked both
     * before and after any redirect, rather than only before.
     * </p>
     *
     * @return {@code true} if {@code 'unsafe-allow-redirects'} is present
     */
    public boolean unsafeAllowRedirects() {
        return unsafeAllowRedirects_;
    }

    /**
     * Returns whether the {@code 'wasm-unsafe-eval'} keyword is present.
     * <p>
     * When present, WebAssembly compilation and instantiation are permitted
     * without requiring {@code 'unsafe-eval'}.
     * </p>
     *
     * @return {@code true} if {@code 'wasm-unsafe-eval'} is present
     * @see <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src#unsafe_webassembly_execution">
     *      wasm-unsafe-eval on MDN</a>
     */
    public boolean unsafeWasm() {
        return unsafeWasm_;
    }

    /**
     * Returns an unmodifiable list of nonce-sources parsed from this directive.
     *
     * @return the list of {@link Nonce} values
     */
    public List<Nonce> getNonces() {
        return Collections.unmodifiableList(nonces_);
    }

    /**
     * Returns an unmodifiable list of hash-sources parsed from this directive.
     *
     * @return the list of {@link Hash} values
     */
    public List<Hash> getHashes() {
        return Collections.unmodifiableList(hashes_);
    }
}
