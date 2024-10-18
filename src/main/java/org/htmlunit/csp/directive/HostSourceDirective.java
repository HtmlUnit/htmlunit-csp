/*
 * Copyright (c) 2023-2024 Ronald Brill.
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
import java.util.Optional;

import org.htmlunit.csp.Constants;
import org.htmlunit.csp.Directive;
import org.htmlunit.csp.Policy;
import org.htmlunit.csp.value.Host;
import org.htmlunit.csp.value.Scheme;

public abstract class HostSourceDirective extends Directive {
    private static final String NONE_SRC = "'none'";
    private static final String SELF_SRC = "'self'";
    private final List<Scheme> schemes_ = new ArrayList<>();
    private final List<Host> hosts_ = new ArrayList<>();
    private boolean star_;
    private boolean self_;

    private String none_;

    protected HostSourceDirective(final List<String> values) {
        super(values);
    }

    public String getNone() {
        return none_;
    }

    @Override
    protected void addValue(final String value) {
        if (none_ != null) {
            super.removeValueIgnoreCase(NONE_SRC); // super so as to not immediately add it back
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
                final String lowcaseToken, final String kind, final int index,
                final DirectiveErrorConsumer errors) {
        if (lowcaseToken.equals(NONE_SRC)) {
            if (none_ == null) {
                none_ = token;
            }
        }
        else if ("*".equals(lowcaseToken)) {
            // Technically this is just a specific kind of host-source, but it's worth handling explicitly
            if (star_) {
                errors.add(Policy.Severity.Warning, "Duplicate " + kind + " *", index);
            }
            else {
                star_ = true;
            }
        }
        else if (lowcaseToken.equals(SELF_SRC)) {
            if (self_) {
                errors.add(Policy.Severity.Warning, "Duplicate " + kind + " 'self'", index);
            }
            else {
                self_ = true;
            }
        }
        else {
            final Optional<Scheme> asScheme = Scheme.parseScheme(token);
            if (asScheme.isPresent()) {
                addScheme(asScheme.get(), index, errors);
            }
            else {
                if (Constants.UNQUOTED_KEYWORD_PATTERN.matcher(token).find()) {
                    errors.add(Policy.Severity.Warning,
                            "This host name is unusual, and likely meant to be a keyword "
                            + "that is missing the required quotes: \'" + token + "\'.", index);
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

    public boolean star() {
        return star_;
    }

    public boolean self() {
        return self_;
    }

    public List<Scheme> getSchemes() {
        return Collections.unmodifiableList(schemes_);
    }

    public List<Host> getHosts() {
        return Collections.unmodifiableList(hosts_);
    }
}
