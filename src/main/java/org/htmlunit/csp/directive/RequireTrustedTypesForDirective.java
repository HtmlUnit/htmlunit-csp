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

import org.htmlunit.csp.Directive;
import org.htmlunit.csp.Policy;

import java.util.List;
import java.util.Locale;

/**
 * @author Michael Smith
 */
public class RequireTrustedTypesForDirective extends Directive {
    // https://w3c.github.io/trusted-types/dist/spec/#require-trusted-types-for-csp-directive
    // Currently only 'script' is defined
    private static final String SCRIPT = "'script'";

    private boolean script_;

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

    public boolean script() {
        return script_;
    }

    public void setScript_(final boolean script) {
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
