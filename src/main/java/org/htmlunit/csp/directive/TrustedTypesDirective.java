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

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Directive implementation for `trusted-types`.
 */
public class TrustedTypesDirective extends Directive {

    private boolean allowDuplicates_;
    private boolean allowAnyPolicyName_;
    private Set<String> allowedPolicyNames_ = new HashSet<>();

    public TrustedTypesDirective(final List<String> values, final DirectiveErrorConsumer errors) {
        super(values);
        boolean hasNone = values.stream().anyMatch(x -> x.toLowerCase(Locale.ROOT).equals("'none'"));

        if (hasNone && values.size() > 1) {
            errors.add(Policy.Severity.Error,
                    "Specifying trusted-types 'none' along with other values is invalid", -1);
        }

        for (int i = 0; i < values.size(); i++) {
            String value = values.get(i);
            final String lowercaseValue = value.toLowerCase(Locale.ROOT);

            if ("*".equals(value)) {
                allowAnyPolicyName_ = true;
                continue;
            } else if (value.isBlank()) {
                errors.add(Policy.Severity.Error, "Empty or whitespace-only policy name is not allowed.", i);
                continue;
            }

            // Check for quoted keywords
            if (value.startsWith("'") && value.endsWith("'") && value.length() > 2) { // Minimum "'x'"
                String inner = lowercaseValue.substring(1, value.length() - 1);
                if (inner.equals("allow-duplicates")) {
                    allowDuplicates_ = true;
                } else if (inner.equals("none")) {
                    // 'none' is ignored here, nNo action needed
                } else {
                    errors.add(Policy.Severity.Error, "Unknown keyword in trusted-types: " + value, i);
                }
                continue;
            }

            // Validate and add policy name (unquoted)
            if (isValidPolicyName(value)) {
                if (!allowedPolicyNames_.add(value)) { // False when attempting to add duplicate
                    // The spec treats the policy name as a JavaScript DOMString identifier, and comparisons are done as exact string matches.
                    // There is no case normalization step.
                    // https://www.w3.org/TR/trusted-types/#should-trusted-type-policy-creation-be-blocked-by-content-security-policy
                    // https://www.w3.org/TR/trusted-types/#create-a-trusted-type-policy
                    // Case-sensitive storage
                    errors.add(Policy.Severity.Warning, "Second attempt to add trusted-types policy: " + value, i);
                };
            } else {
                errors.add(Policy.Severity.Error, "Invalid policy name in trusted-types: " + value
                        + " (must be alphanumeric or -#=_/@.%)", i);
            }
        }
    }

    private static boolean isValidPolicyName(String name) {
        if (name.isEmpty()) {
            return false;
        }
        for (char c : name.toCharArray()) {
            if (!Character.isLetterOrDigit(c) && "-#=_/@.%".indexOf(c) == -1) {
                return false;
            }
        }
        return true;
    }

    public boolean isAllowDuplicates() {
        return allowDuplicates_;
    }

    public boolean isAllowAnyPolicyName() {
        return allowAnyPolicyName_;
    }

    public Set<String> getAllowedPolicyNames() {
        return Collections.unmodifiableSet(allowedPolicyNames_);
    }
}