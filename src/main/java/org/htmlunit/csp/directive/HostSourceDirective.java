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
import java.util.Optional;

import org.htmlunit.csp.Constants;
import org.htmlunit.csp.Directive;
import org.htmlunit.csp.Policy;
import org.htmlunit.csp.value.Host;
import org.htmlunit.csp.value.Scheme;

/**
 * Abstract base class for directives whose values are host-source lists.
 * <p>
 * A host-source list can contain the keywords {@code 'none'}, {@code 'self'},
 * and {@code *}, as well as scheme-sources ({@code https:}) and host-sources
 * ({@code example.com}, {@code *.example.com:443/path}). This class is extended
 * by {@link SourceExpressionDirective} (which adds nonces, hashes, and other
 * source expressions) and by {@link FrameAncestorsDirective}.
 * </p>
 *
 * @see <a href="https://w3c.github.io/webappsec-csp/#framework-directive-source-list">
 *      CSP source list</a>
 */
public abstract class HostSourceDirective extends Directive {
    private static final String NONE_SRC = "'none'";
    private static final String SELF_SRC = "'self'";
    private final List<Scheme> schemes_ = new ArrayList<>();
    private final List<Host> hosts_ = new ArrayList<>();
    private boolean star_;
    private boolean self_;

    private String none_;

    /**
     * Constructs a host-source directive from the given raw values.
     *
     * @param values the raw string values for this directive
     */
    protected HostSourceDirective(final List<String> values) {
        super(values);
    }

    /**
     * Returns the original {@code 'none'} token if the directive was set to {@code 'none'},
     * or {@code null} if the directive is not {@code 'none'}.
     *
     * @return the {@code 'none'} token string, or {@code null}
     */
    public String getNone() {
        return none_;
    }

    @Override
    protected void addValue(final String value) {
        if (none_ != null) {
            // super, to not immediately add it back
            super.removeValueIgnoreCase(NONE_SRC);
            none_ = null;
        }
        super.addValue(value);
    }

    @Override
    protected void removeValueIgnoreCase(final String value) {
        super.removeValueIgnoreCase(value);
        if (getValues().isEmpty()) {
            getValues().add(NONE_SRC);
            none_ = NONE_SRC;
        }
    }

    void addHostOrSchemeDuringConstruction(final String token,
                final String lowercaseToken, final String kind, final int index,
                final DirectiveErrorConsumer errors) {
        switch (lowercaseToken) {
            case NONE_SRC -> {
                if (none_ == null) {
                    none_ = token;
                }
            }
            case "*" -> {
                // Technically this is just a specific kind of host-source, but it's worth handling explicitly
                if (star_) {
                    errors.add(Policy.Severity.Warning, "Duplicate " + kind + " *", index);
                }
                else {
                    star_ = true;
                }
            }
            case SELF_SRC -> {
                if (self_) {
                    errors.add(Policy.Severity.Warning, "Duplicate " + kind + " 'self'", index);
                }
                else {
                    self_ = true;
                }
            }
            default -> {
                final Optional<Scheme> asScheme = Scheme.parseScheme(token);
                if (asScheme.isPresent()) {
                    addScheme(asScheme.get(), index, errors);
                }
                else {
                    if (Constants.UNQUOTED_KEYWORD_PATTERN.matcher(token).find()) {
                        errors.add(Policy.Severity.Warning,
                                "This host name is unusual, and likely meant to be a keyword "
                                        + "that is missing the required quotes: '" + token + "'.", index);
                    }

                    final Optional<Host> asHost = Host.parseHost(token);
                    if (asHost.isPresent()) {
                        addHostSource(asHost.get(), index, errors);
                    }
                    else {
                        errors.add(Policy.Severity.Error, "Unrecognized " + kind + " " + token, index);
                    }
                }
            }
        }
    }

    private boolean addScheme(final Scheme scheme, final int index, final DirectiveErrorConsumer errors) {
        if (schemes_.contains(scheme)) {
            errors.add(Policy.Severity.Warning, "Duplicate scheme " + scheme, index);
            return false;
        }

        // TODO check if this subsumes or is subsumed by any existing scheme/host
        // NB we add it even if it subsumes or is subsumed by existing things,
        // since it's still valid and not a duplicate
        schemes_.add(scheme);
        return true;
    }

    private boolean addHostSource(final Host source, final int index, final DirectiveErrorConsumer errors) {
        if (hosts_.contains(source)) {
            errors.add(Policy.Severity.Warning, "Duplicate host " + source.toString(), index);
            return false;
        }

        // TODO check if this subsumes or is subsumed by any existing scheme/host
        hosts_.add(source);
        return true;
    }

    /**
     * Returns whether the wildcard ({@code *}) is present in this source list.
     * <p>
     * When {@code *} is present, any URL with a
     * <a href="https://fetch.spec.whatwg.org/#network-scheme">network scheme</a>
     * ({@code ftp}, {@code http}, {@code https}) is matched, as well as URLs whose
     * scheme matches the origin's scheme.
     * </p>
     *
     * @return {@code true} if the wildcard source is present
     */
    public boolean star() {
        return star_;
    }

    /**
     * Returns whether the {@code 'self'} keyword is present in this source list.
     * <p>
     * When {@code 'self'} is present, URLs that share the same origin as the
     * protected resource are matched.
     * </p>
     *
     * @return {@code true} if {@code 'self'} is present
     */
    public boolean self() {
        return self_;
    }

    /**
     * Returns an unmodifiable list of scheme-sources (e.g. {@code https:}, {@code data:})
     * present in this directive.
     *
     * @return the list of parsed {@link Scheme} values
     */
    public List<Scheme> getSchemes() {
        return Collections.unmodifiableList(schemes_);
    }

    /**
     * Returns an unmodifiable list of host-sources (e.g. {@code example.com},
     * {@code *.cdn.example.com:443/path}) present in this directive.
     *
     * @return the list of parsed {@link Host} values
     */
    public List<Host> getHosts() {
        return Collections.unmodifiableList(hosts_);
    }
}
