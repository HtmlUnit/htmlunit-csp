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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * @author Michael Smith
 */
public class TrustedTypesDirective extends Directive {
    // https://w3c.github.io/trusted-types/dist/spec/#trusted-types-csp-directive
    // tt-policy-name = 1*( ALPHA / DIGIT / "-" / "#" / "=" / "_" / "/" / "@" / "." / "%" )
    private static final Pattern TT_POLICY_NAME_PATTERN = Pattern.compile("^[A-Za-z0-9\\-#=_/@.%]+$");

    private boolean none_ = false;
    private boolean allowDuplicates_ = false;
    private boolean star_ = false;
    private final List<String> policyNames_ = new ArrayList<>();

    public TrustedTypesDirective(final List<String> values, final DirectiveErrorConsumer errors) {
        super(values);

        int index = 0;
        for (final String token : values) {
            // Keywords are case-insensitive per ABNF spec (RFC 5234 §2.3).
            // Note: Chromium incorrectly treats 'allow-duplicates' as case-sensitive,
            // while WebKit correctly treats it as case-insensitive. We follow the spec.
            // See https://issues.chromium.org/issues/472892238
            final String lowcaseToken = token.toLowerCase(Locale.ROOT);
            switch (lowcaseToken) {
                case "'none'":
                    if (!none_) {
                        none_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning, "Duplicate keyword 'none'", index);
                    }
                    break;
                case "'allow-duplicates'":
                    if (!allowDuplicates_) {
                        allowDuplicates_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning, "Duplicate keyword 'allow-duplicates'", index);
                    }
                    break;
                case "*":
                    if (!star_) {
                        star_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning, "Duplicate wildcard *", index);
                    }
                    break;
                default:
                    if (token.startsWith("'") && token.endsWith("'")) {
                        errors.add(Policy.Severity.Error, "Unrecognized trusted-types keyword " + token, index);
                    }
                    else if (TT_POLICY_NAME_PATTERN.matcher(token).matches()) {
                        // Policy names are case-sensitive per browser behavior
                        if (policyNames_.contains(token)) {
                            errors.add(Policy.Severity.Warning, "Duplicate policy name " + token, index);
                        }
                        else {
                            policyNames_.add(token);
                        }
                    }
                    else {
                        errors.add(Policy.Severity.Error, "Invalid trusted-types policy name " + token, index);
                    }
            }
            ++index;
        }

        // 'none' must not be combined with other values
        if (none_ && (star_ || allowDuplicates_ || !policyNames_.isEmpty())) {
            errors.add(Policy.Severity.Error,
                    "'none' must not be combined with any other trusted-types expression", -1);
        }
    }

    public boolean none() {
        return none_;
    }

    public void setNone(final boolean none) {
        if (none_ == none) {
            return;
        }
        if (none) {
            addValue("'none'");
        }
        else {
            removeValueIgnoreCase("'none'");
        }
        none_ = none;
    }

    public boolean allowDuplicates() {
        return allowDuplicates_;
    }

    public void setAllowDuplicates_(final boolean allowDuplicates) {
        if (allowDuplicates_ == allowDuplicates) {
            return;
        }
        if (allowDuplicates) {
            addValue("'allow-duplicates'");
        }
        else {
            removeValueIgnoreCase("'allow-duplicates'");
        }
        allowDuplicates_ = allowDuplicates;
    }

    public boolean star() {
        return star_;
    }

    public void setStar_(final boolean star) {
        if (star_ == star) {
            return;
        }
        if (star) {
            addValue("*");
        }
        else {
            removeValueIgnoreCase("*");
        }
        star_ = star;
    }

    public List<String> getPolicyNames_() {
        return Collections.unmodifiableList(policyNames_);
    }
}
