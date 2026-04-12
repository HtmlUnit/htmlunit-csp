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

import java.util.List;
import java.util.Locale;

import org.htmlunit.csp.Directive;
import org.htmlunit.csp.Policy;

/**
 * Represents the {@code require-trusted-types-for} CSP directive.
 * <p>
 * This directive instructs the user agent to require Trusted Types for certain
 * DOM sinks. Currently the only defined keyword is {@code 'script'}, which
 * enforces Trusted Types for all script-related injection sinks.
 * </p>
 *
 * @author Michael Smith
 * @see <a href="https://w3c.github.io/trusted-types/dist/spec/#require-trusted-types-for-csp-directive">
 *      require-trusted-types-for directive</a>
 */
public class RequireTrustedTypesForDirective extends Directive {
    // https://w3c.github.io/trusted-types/dist/spec/#require-trusted-types-for-csp-directive
    // Currently only 'script' is defined
    private static final String SCRIPT = "'script'";

    private boolean script_;

    /**
     * Parses a {@code require-trusted-types-for} directive from the given list of values.
     * <p>
     * The only currently recognised keyword is {@code 'script'} (case-insensitive).
     * An empty directive, duplicate keywords, and unrecognised tokens are reported
     * through the supplied {@code errors} consumer.
     * </p>
     *
     * @param values the raw string values for this directive
     * @param errors consumer that receives parsing errors and warnings
     */
    public RequireTrustedTypesForDirective(final List<String> values, final DirectiveErrorConsumer errors) {
        super(values);

        if (values.isEmpty()) {
            errors.add(Policy.Severity.Error, "The require-trusted-types-for directive requires a value", -1);
            return;
        }

        int index = 0;
        for (final String token : values) {
            // ABNF strings are case-insensitive
            final String lowerCaseToken = token.toLowerCase(Locale.ROOT);
            if ("'script'".equals(lowerCaseToken)) {
                if (script_) {
                    errors.add(Policy.Severity.Warning, "Duplicate keyword 'script'", index);
                }
                else {
                    script_ = true;
                }
            }
            else {
                if (token.startsWith("'") && token.endsWith("'")) {
                    errors.add(Policy.Severity.Error,
                            "Unrecognized require-trusted-types-for keyword " + token, index);
                }
                else {
                    errors.add(Policy.Severity.Error,
                            "Unrecognized require-trusted-types-for value " + token
                                    + " - keywords must be wrapped in single quotes", index);
                }
            }
            ++index;
        }
    }

    /**
     * Returns whether the {@code 'script'} keyword is present.
     * <p>
     * When {@code true}, Trusted Types are required for all script-related
     * DOM injection sinks.
     * </p>
     *
     * @return {@code true} if the {@code 'script'} keyword is present
     */
    public boolean script() {
        return script_;
    }

    /**
     * Sets whether the {@code 'script'} keyword is present.
     * <p>
     * Setting to {@code true} adds {@code 'script'} to the directive values;
     * setting to {@code false} removes it.
     * </p>
     *
     * @param script {@code true} to add {@code 'script'}, {@code false} to remove it
     */
    public void setScript(final boolean script) {
        if (script_ == script) {
            return;
        }
        if (script) {
            addValue(SCRIPT);
        }
        else {
            removeValueIgnoreCase(SCRIPT);
        }
        script_ = script;
    }
}
