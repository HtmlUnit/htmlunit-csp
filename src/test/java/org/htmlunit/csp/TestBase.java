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
package org.htmlunit.csp;

import java.util.Locale;
import java.util.Objects;

public class TestBase {
    final Policy.PolicyListErrorConsumer throwIfPolicyListError = (severity, message, policyIndex, directiveIndex, valueIndex) -> {
        throw new RuntimeException(new PolicyListError(severity, message, policyIndex, directiveIndex, valueIndex).toString());
    };

    final Policy.PolicyErrorConsumer throwIfPolicyError = (severity, message, directiveIndex, valueIndex) -> {
        throw new RuntimeException(new PolicyError(severity, message, directiveIndex, valueIndex).toString());
    };

    final Directive.DirectiveErrorConsumer throwIfDirectiveError = (severity, message, valueIndex) -> {
        throw new RuntimeException(new DirectiveError(severity, message, valueIndex).toString());
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

    static class PolicyListError {
        private final Policy.Severity severity_;
        private final String message_;
        private final int policyIndex_;
        private final int directiveIndex_;
        private final int valueIndex_;

        PolicyListError(final Policy.Severity severity, final String message, final int policyIndex,
                final int directiveIndex, final int valueIndex) {
            this.severity_ = severity;
            this.message_ = message;
            this.policyIndex_ = policyIndex;
            this.directiveIndex_ = directiveIndex;
            this.valueIndex_ = valueIndex;
        }

        @Override
        public String toString() {
            return "(" + this.severity_.name() + ") " + this.message_ + " at policy " + this.policyIndex_ + " at directive " + this.directiveIndex_ + " at value " + this.valueIndex_;
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

        @Override
        public int hashCode() {
            return Objects.hash(severity_, message_, policyIndex_, directiveIndex_, valueIndex_);
        }
    }

    static class PolicyError {
        private final Policy.Severity severity_;
        private final String message_;
        private final int directiveIndex_;
        private final int valueIndex_;

        PolicyError(final Policy.Severity severity, final String message,
                final int directiveIndex, final int valueIndex) {
            this.severity_ = severity;
            this.message_ = message;
            this.directiveIndex_ = directiveIndex;
            this.valueIndex_ = valueIndex;
        }

        @Override
        public String toString() {
            return "(" + this.severity_.name() + ") " + this.message_ + " at directive " + this.directiveIndex_ + " at value " + this.valueIndex_;
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

        @Override
        public int hashCode() {
            return Objects.hash(severity_, message_, directiveIndex_, valueIndex_);
        }
    }

    static class DirectiveError {
        private final Policy.Severity severity_;
        private final String message_;
        private final int valueIndex_;

        DirectiveError(final Policy.Severity severity, final String message, final int valueIndex) {
            this.severity_ = severity;
            this.message_ = message;
            this.valueIndex_ = valueIndex;
        }

        @Override
        public String toString() {
            return "(" + this.severity_.name() + ") " + this.message_ + " at value " + this.valueIndex_;
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

        @Override
        public int hashCode() {
            return Objects.hash(severity_, message_, valueIndex_);
        }
    }
}
