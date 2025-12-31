/*
 * Copyright (c) 2023-2025 Ronald Brill.
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
package org.htmlunit.csp;

import java.util.Locale;

public abstract class TestBase {
    /**
     * Policy.PolicyListErrorConsumer that throws.
     */
    public static final Policy.PolicyListErrorConsumer ThrowIfPolicyListError
                    = (severity, message, policyIndex, directiveIndex, valueIndex) -> {
                        throw new RuntimeException(
                                new PolicyListError(severity, message, policyIndex, directiveIndex, valueIndex).toString());
                    };

    /**
     * Policy.PolicyListErrorConsumer that throws.
     */
    public static final Policy.PolicyErrorConsumer ThrowIfPolicyError
                    = (severity, message, directiveIndex, valueIndex) -> {
                        throw new RuntimeException(new PolicyError(severity, message, directiveIndex, valueIndex).toString());
                    };

    /**
     * Policy.PolicyListErrorConsumer that throws.
     */
    public static final Directive.DirectiveErrorConsumer ThrowIfDirectiveError
                    = (severity, message, valueIndex) -> {
                        throw new RuntimeException(
                                new DirectiveError(severity, message, valueIndex).toString());
                    };

    static void inTurkey(final Runnable r) {
        final Locale current = Locale.getDefault();
        try {
            // In Turkey, "I" lowercases to "ı". This test enforces that we're doing ASCII-case-insensitive comparisons, rather than locale-specific comparisons.
            Locale.setDefault(new Locale("tr", "TR"));
            r.run();
        }
        finally {
            Locale.setDefault(current);
        }
    }

    protected static PolicyListError e(final Policy.Severity severity, final String message,
            final int policyIndex, final int directiveIndex, final int valueIndex) {
        return new PolicyListError(severity, message, policyIndex, directiveIndex, valueIndex);
    }

    protected static PolicyError e(final Policy.Severity severity, final String message,
            final int directiveIndex, final int valueIndex) {
        return new PolicyError(severity, message, directiveIndex, valueIndex);
    }

    protected static DirectiveError e(final Policy.Severity severity, final String message, final int valueIndex) {
        return new DirectiveError(severity, message, valueIndex);
    }

    record PolicyListError(Policy.Severity severity_, String message_, int policyIndex_, int directiveIndex_,
                           int valueIndex_) {

        @Override
            public String toString() {
                return "(" + severity_.name() + ") " + message_ + " at policy " + policyIndex_ + " at directive " + directiveIndex_ + " at value " + valueIndex_;
            }

            @Override
            public boolean equals(final Object o) {
                if (this == o) {
                    return true;
                }
                if (o == null || getClass() != o.getClass()) {
                    return false;
                }
                final PolicyListError that = (PolicyListError) o;
                return policyIndex_ == that.policyIndex_
                        && directiveIndex_ == that.directiveIndex_
                        && valueIndex_ == that.valueIndex_
                        && severity_ == that.severity_
                        && message_.equals(that.message_);
            }

    }

    record PolicyError(Policy.Severity severity_, String message_, int directiveIndex_, int valueIndex_) {

        @Override
            public String toString() {
                return "(" + severity_.name() + ") " + message_ + " at directive " + directiveIndex_ + " at value " + valueIndex_;
            }

            @Override
            public boolean equals(final Object o) {
                if (this == o) {
                    return true;
                }
                if (o == null || getClass() != o.getClass()) {
                    return false;
                }
                final PolicyError that = (PolicyError) o;
                return directiveIndex_ == that.directiveIndex_
                        && valueIndex_ == that.valueIndex_
                        && severity_ == that.severity_
                        && message_.equals(that.message_);
            }

    }

    record DirectiveError(Policy.Severity severity_, String message_, int valueIndex_) {

        @Override
            public String toString() {
                return "(" + severity_.name() + ") " + message_ + " at value " + valueIndex_;
            }

            @Override
            public boolean equals(final Object o) {
                if (this == o) {
                    return true;
                }
                if (o == null || getClass() != o.getClass()) {
                    return false;
                }
                final DirectiveError that = (DirectiveError) o;
                return valueIndex_ == that.valueIndex_
                        && severity_ == that.severity_
                        && message_.equals(that.message_);
            }

    }
}
