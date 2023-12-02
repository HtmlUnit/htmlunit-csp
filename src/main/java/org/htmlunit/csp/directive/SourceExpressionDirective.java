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
package org.htmlunit.csp.directive;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import org.htmlunit.csp.Policy;
import org.htmlunit.csp.value.Hash;
import org.htmlunit.csp.value.Nonce;

public class SourceExpressionDirective extends HostSourceDirective {
    private static final String REPORT_SAMPLE = "'report-sample'";
    private static final String UNSAFE_INLINE = "'unsafe-inline'";
    private static final String STRICT_DYNAMIC = "'strict-dynamic'";
    private static final String UNSAFE_ALLOW_REDIRECTS = "'unsafe-allow-redirects'";
    private static final String UNSAFE_EVAL = "'unsafe-eval'";
    private static final String UNSAFE_HASHES = "'unsafe-hashes'";
    private boolean unsafeInline_;
    private boolean unsafeEval_;
    private boolean strictDynamic_;
    private boolean unsafeHashes_;
    private boolean reportSample_;
    private boolean unsafeAllowRedirects_;

    // In practice, these are probably small enough for Lists to be faster than LinkedHashSets
    private final List<Nonce> nonces_ = new ArrayList<>();
    private final List<Hash> hashes_ = new ArrayList<>();

    public SourceExpressionDirective(final List<String> values, final DirectiveErrorConsumer errors) {
        super(values);

        int index = 0;
        for (final String token : values) {
            // The CSP grammar uses ABNF grammars, whose strings
            // are case-insensitive: https://tools.ietf.org/html/rfc5234
            // This needs to be ASCII-lowercase, so that `'strIct-dynamic''` still parses in Turkey
            final String lowcaseToken = token.toLowerCase(Locale.ENGLISH);
            switch (lowcaseToken) {
                case UNSAFE_INLINE:
                    if (!unsafeInline_) {
                        unsafeInline_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning, "Duplicate source-expression 'unsafe-inline'", index);
                    }
                    break;
                case UNSAFE_EVAL:
                    if (!unsafeEval_) {
                        unsafeEval_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning, "Duplicate source-expression 'unsafe-eval'", index);
                    }
                    break;
                case STRICT_DYNAMIC:
                    if (!strictDynamic_) {
                        strictDynamic_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning, "Duplicate source-expression 'strict-dynamic'", index);
                    }
                    break;
                case UNSAFE_HASHES:
                    if (!unsafeHashes_) {
                        unsafeHashes_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning, "Duplicate source-expression 'unsafe-hashes'", index);
                    }
                    break;
                case REPORT_SAMPLE:
                    if (!reportSample_) {
                        reportSample_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning, "Duplicate source-expression 'report-sample'", index);
                    }
                    break;
                case UNSAFE_ALLOW_REDIRECTS:
                    if (!unsafeAllowRedirects_) {
                        unsafeAllowRedirects_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning,
                                    "Duplicate source-expression 'unsafe-allow-redirects'", index);
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
                    if (lowcaseToken.startsWith("'nonce-")) {
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
                    else if (lowcaseToken.startsWith("'sha")) {
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
                        addHostOrSchemeDuringConstruction(token, lowcaseToken, "source-expression", index, errors);
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
        else {
            nonces_.add(nonce);
            return true;
        }
    }

    private boolean addHash(final Hash hash, final int index, final DirectiveErrorConsumer errors) {
        if (hashes_.contains(hash)) {
            errors.add(Policy.Severity.Warning, "Duplicate hash " + hash.toString(), index);
            return false;
        }
        else {
            if (hash.getBase64ValuePart().length() != hash.getAlgorithm().getLength()) {
                errors.add(Policy.Severity.Warning,
                        "Wrong length for " + hash.getAlgorithm().toString()
                        + ": expected " + hash.getAlgorithm().getLength()
                        + ", got " + hash.getBase64ValuePart().length(), index);
            }

            if (hash.getBase64ValuePart().contains("_") || hash.getBase64ValuePart().contains("-")) {
                errors.add(Policy.Severity.Warning, "'_' and '-' in hashes can never match actual elements", index);
            }

            hashes_.add(hash);
            return true;
        }
    }

    // Accessors

    // TODO it would be nice to warn for adding things which are irrelevant
    // Though it would be better to just not provide those methods at all
    // But that kind of conflicts with the "only error on things which don't match the grammar" goal
    // See also https://github.com/w3c/webappsec-csp/issues/431

    public boolean unsafeInline() {
        return unsafeInline_;
    }

    public boolean unsafeEval() {
        return unsafeEval_;
    }

    public boolean strictDynamic() {
        return strictDynamic_;
    }

    public boolean unsafeHashes() {
        return unsafeHashes_;
    }

    public boolean reportSample() {
        return reportSample_;
    }

    public boolean unsafeAllowRedirects() {
        return unsafeAllowRedirects_;
    }

    public List<Nonce> getNonces() {
        return Collections.unmodifiableList(nonces_);
    }

    public List<Hash> getHashes() {
        return Collections.unmodifiableList(hashes_);
    }
}
