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
package org.htmlunit.csp;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents a list of Content Security Policies parsed from a comma-separated
 * serialized CSP list.
 * <p>
 * A serialized CSP list (e.g. the value of a {@code Content-Security-Policy}
 * HTTP header) may contain multiple policies separated by commas. Each policy
 * is parsed independently, and a resource is blocked if <em>any</em> policy
 * in the list blocks it.
 * </p>
 * <p>
 * Instances are created by
 * {@link Policy#parseSerializedCSPList(String, Policy.PolicyListErrorConsumer)}.
 * Empty policies (those with no directives) are omitted during parsing.
 * </p>
 *
 * @see Policy#parseSerializedCSPList(String, Policy.PolicyListErrorConsumer)
 */
public class PolicyList {
    private final List<Policy> policies_;

    /**
     * Ctor.
     *
     * @param policies the list of parsed {@link Policy} instances (empty policies excluded)
     */
    public PolicyList(final List<Policy> policies) {
        policies_ = policies;
    }

    /**
     * Returns a copy of the policies associated with this object.
     * <p>
     * The returned list is a defensive copy, so modifications to it do not
     * affect the internal collection of policies.
     * </p>
     *
     * @return a new {@code List} containing all policies
     */
    public List<Policy> getPolicies() {
        return new ArrayList<Policy>(policies_);
    }

    /**
     * Serializes this policy list back to its string representation.
     * <p>
     * Individual policies are separated by {@code ", "}. Each policy is
     * serialized using {@link Policy#toString()}.
     * </p>
     *
     * @return the comma-separated serialized CSP list string
     */
    @Override
    public String toString() {
        final StringBuilder out = new StringBuilder();
        boolean first = true;
        for (final Policy policy : policies_) {
            if (!first) {
                out.append(", "); // The whitespace is not strictly necessary but is probably valuable
            }
            first = false;
            out.append(policy.toString());
        }
        return out.toString();
    }
}
