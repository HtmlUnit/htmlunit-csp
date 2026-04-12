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
import java.util.regex.Pattern;

import org.htmlunit.csp.Directive;
import org.htmlunit.csp.Policy;

/**
 * Represents the {@code trusted-types} CSP directive.
 * <p>
 * The {@code trusted-types} directive restricts the creation of Trusted Type
 * policies, which are used to guard DOM XSS sink functions. It can specify
 * an explicit allow-list of policy names, the keyword {@code 'none'} to forbid
 * all policies, the keyword {@code 'allow-duplicates'} to permit policies
 * with the same name to be created more than once, and the wildcard {@code *}
 * to allow any policy name.
 * </p>
 *
 * @author Michael Smith
 * @see <a href="https://w3c.github.io/trusted-types/dist/spec/#trusted-types-csp-directive">
 *      trusted-types directive</a>
 */
public class TrustedTypesDirective extends Directive {
    // https://w3c.github.io/trusted-types/dist/spec/#trusted-types-csp-directive
    // tt-policy-name = 1*( ALPHA / DIGIT / "-" / "#" / "=" / "_" / "/" / "@" / "." / "%" )
    private static final Pattern TT_POLICY_NAME_PATTERN = Pattern.compile("^[A-Za-z0-9\\-#=_/@.%]+$");

    private boolean none_;
    private boolean allowDuplicates_;
    private boolean star_;
    private final List<String> policyNames_ = new ArrayList<>();

    /**
     * Parses a {@code trusted-types} directive from the given list of values.
     * <p>
     * Recognised tokens include the keywords {@code 'none'}, {@code 'allow-duplicates'},
     * the wildcard {@code *}, and policy names matching the
     * {@code tt-policy-name} grammar. Errors and warnings (duplicates, invalid names,
     * conflicting combinations) are reported through the supplied {@code errors} consumer.
     * </p>
     *
     * @param values the raw string values for this directive
     * @param errors consumer that receives parsing errors and warnings
     */
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
                    if (none_) {
                        errors.add(Policy.Severity.Warning, "Duplicate keyword 'none'", index);
                    }
                    else {
                        none_ = true;
                    }
                    break;
                case "'allow-duplicates'":
                    if (allowDuplicates_) {
                        errors.add(Policy.Severity.Warning, "Duplicate keyword 'allow-duplicates'", index);
                    }
                    else {
                        allowDuplicates_ = true;
                    }
                    break;
                case "*":
                    if (star_) {
                        errors.add(Policy.Severity.Warning, "Duplicate wildcard *", index);
                    }
                    else {
                        star_ = true;
                        errors.add(Policy.Severity.Warning,
                                "Wildcard policy names (*) permit any policy name, which may reduce security", index);
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

        // Empty directive validation - if no values were provided, warn
        if (values.isEmpty()) {
            errors.add(Policy.Severity.Warning,
                    "Empty trusted-types directive allows all policy names (use '*' or 'none' to be explicit)", -1);
        }

        // 'none' must not be combined with other values
        if (none_ && (star_ || allowDuplicates_ || !policyNames_.isEmpty())) {
            errors.add(Policy.Severity.Error,
                    "'none' must not be combined with any other trusted-types expression", -1);
        }

        // Wildcard makes specific policy names redundant
        if (star_ && !policyNames_.isEmpty()) {
            errors.add(Policy.Severity.Warning,
                    "Wildcard (*) permits any policy name, making specific policy names redundant", -1);
        }

        // 'allow-duplicates' is redundant with wildcard (wildcard already allows everything)
        if (star_ && allowDuplicates_) {
            errors.add(Policy.Severity.Warning,
                    "'allow-duplicates' is redundant when wildcard (*) is present", -1);
        }

        // 'allow-duplicates' without policy names or wildcard has no effect
        if (allowDuplicates_ && !star_ && policyNames_.isEmpty()) {
            errors.add(Policy.Severity.Warning,
                    "'allow-duplicates' has no effect without policy names or wildcard", -1);
        }
    }

    /**
     * Returns whether the {@code 'none'} keyword is present.
     * <p>
     * When {@code 'none'} is present, no Trusted Type policies may be created.
     * </p>
     *
     * @return {@code true} if {@code 'none'} is present
     */
    public boolean none() {
        return none_;
    }

    /**
     * Sets whether the {@code 'none'} keyword is present.
     * <p>
     * Setting to {@code true} adds {@code 'none'} to the directive values;
     * setting to {@code false} removes it.
     * </p>
     *
     * @param none {@code true} to add {@code 'none'}, {@code false} to remove it
     */
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

    /**
     * Returns whether the {@code 'allow-duplicates'} keyword is present.
     * <p>
     * When present, Trusted Type policies with the same name may be created
     * more than once.
     * </p>
     *
     * @return {@code true} if {@code 'allow-duplicates'} is present
     */
    public boolean allowDuplicates() {
        return allowDuplicates_;
    }

    /**
     * Sets whether the {@code 'allow-duplicates'} keyword is present.
     * <p>
     * Setting to {@code true} adds {@code 'allow-duplicates'} to the directive values;
     * setting to {@code false} removes it.
     * </p>
     *
     * @param allowDuplicates {@code true} to add, {@code false} to remove
     */
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

    /**
     * Returns whether the wildcard ({@code *}) is present.
     * <p>
     * When present, any Trusted Type policy name is permitted.
     * </p>
     *
     * @return {@code true} if the wildcard is present
     */
    public boolean star() {
        return star_;
    }

    /**
     * Indicates if wildcard policy names are permitted.
     * When true, any policy name is allowed, which may reduce security.
     *
     * @return true if wildcard policy names (*) are permitted, false otherwise
     */
    public boolean allowsWildcardPolicyNames() {
        return star_;
    }

    /**
     * Sets whether the wildcard ({@code *}) is present.
     * <p>
     * Setting to {@code true} adds {@code *} to the directive values;
     * setting to {@code false} removes it.
     * </p>
     *
     * @param star {@code true} to add, {@code false} to remove
     */
    public void setStar(final boolean star) {
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

    /**
     * Returns an unmodifiable list of the explicitly named Trusted Type policy names
     * (excluding keywords and wildcard).
     * <p>
     * Policy names are case-sensitive and match the {@code tt-policy-name} grammar.
     * </p>
     *
     * @return the list of policy name strings
     */
    public List<String> getPolicyNames() {
        return Collections.unmodifiableList(policyNames_);
    }
}
