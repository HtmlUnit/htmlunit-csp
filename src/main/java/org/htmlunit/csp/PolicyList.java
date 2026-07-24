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

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;

import org.htmlunit.csp.Policy.PolicyListErrorConsumer;
import org.htmlunit.csp.url.URLWithScheme;
import org.htmlunit.csp.value.MediaType;

/**
 * Represents a list of Content Security Policies parsed from a comma-separated
 * serialized CSP list, or combined from multiple header / meta deliveries.
 * <p>
 * A serialized CSP list (e.g. the value of a {@code Content-Security-Policy}
 * HTTP header) may contain multiple policies separated by commas. Each policy
 * is parsed independently, and a resource is blocked if <em>any</em> policy
 * in the list blocks it — equivalently, {@code allows*} methods return
 * {@code true} only when <em>every</em> member policy allows the resource.
 * See
 * <a href="https://w3c.github.io/webappsec-csp/#multiple-policies">CSP3
 * multiple policies</a>.
 * </p>
 * <p>
 * Implements {@link CspQueries}: each query method AND-delegates to member
 * {@link Policy} instances (short-circuit on the first deny). An empty list
 * is unrestricted (all {@code allows*} return {@code true}).
 * </p>
 * <p>
 * Instances are created by
 * {@link Policy#parseSerializedCSPList(String, PolicyListErrorConsumer)}
 * or {@link #ofSerialized(List, PolicyListErrorConsumer)}.
 * Empty policies (those with no directives) are omitted during parsing.
 * </p>
 *
 * @author Ronald Brill
 * @see CspQueries
 * @see Policy#parseSerializedCSPList(String, PolicyListErrorConsumer)
 */
public class PolicyList implements CspQueries {
    private final List<Policy> policies_;

    /**
     * Ctor.
     *
     * @param policies the list of parsed {@link Policy} instances (empty policies excluded)
     * @throws NullPointerException if {@code policies} is {@code null} or contains {@code null}
     */
    public PolicyList(final List<Policy> policies) {
        policies_ = List.copyOf(policies);
    }

    /**
     * Parses and combines multiple serialized CSP strings into one policy list.
     * <p>
     * Each element may itself be a comma-separated CSP list (as with a single
     * header field value). Values are joined with {@code ","} and parsed via
     * {@link Policy#parseSerializedCSPList} (always as header delivery —
     * {@code deliveredViaMeta = false}). For meta policies, parse with
     * {@link Policy#parseSerializedCSP(String, Policy.PolicyErrorConsumer, boolean)}
     * and pass the results to {@link PolicyList#PolicyList(List)}. Report-Only policies
     * should be kept in a separate {@link PolicyList}.
     * </p>
     *
     * @param serializedPoliciesOrLists header field values (not meta {@code content}
     *        strings that need {@code deliveredViaMeta = true})
     * @param policyListErrorConsumer consumer for parse errors/warnings
     * @return the combined {@link PolicyList}
     * @throws NullPointerException if {@code serializedPoliciesOrLists} or
     *         {@code policyListErrorConsumer} is {@code null}, or if any element
     *         of {@code serializedPoliciesOrLists} is {@code null}
     * @since 5.4.0
     */
    public static PolicyList ofSerialized(final List<String> serializedPoliciesOrLists,
            final PolicyListErrorConsumer policyListErrorConsumer) {
        Objects.requireNonNull(serializedPoliciesOrLists, "serializedPoliciesOrLists");
        Objects.requireNonNull(policyListErrorConsumer, "policyListErrorConsumer");
        return Policy.parseSerializedCSPList(
                String.join(",", serializedPoliciesOrLists), policyListErrorConsumer);
    }

    /**
     * Returns the member policies (unmodifiable).
     *
     * @return an unmodifiable list of all policies
     */
    public List<Policy> getPolicies() {
        return policies_;
    }

    /**
     * Serializes this policy list back to its string representation.
     * <p>
     * Individual policies are separated by {@code ", "}. Each policy is
     * serialized using {@link Policy#toString()}. This is <em>not</em> an
     * intersected / merged policy.
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

    /**
     * Returns {@code true} only if every policy in the list satisfies {@code check}.
     * Stops at the first {@code false} (short-circuit). An empty list returns {@code true}.
     */
    private boolean allAllow(final Predicate<Policy> check) {
        for (final Policy policy : policies_) {
            if (!check.test(policy)) {
                return false;
            }
        }
        return true;
    }

    // High-level querying: AND across all member policies

    @Override
    public boolean allowsExternalScript(
            final Optional<String> nonce,
            final Optional<String> integrity,
            final Optional<? extends URLWithScheme> scriptUrl,
            final Optional<Boolean> parserInserted,
            final Optional<? extends URLWithScheme> origin) {
        return allAllow(p ->
                p.allowsExternalScript(nonce, integrity, scriptUrl, parserInserted, origin));
    }

    @Override
    public boolean allowsInlineScript(final Optional<String> nonce,
            final Optional<String> source, final Optional<Boolean> parserInserted) {
        return allAllow(p -> p.allowsInlineScript(nonce, source, parserInserted));
    }

    @Override
    public boolean allowsScriptAsAttribute(final Optional<String> source) {
        return allAllow(p -> p.allowsScriptAsAttribute(source));
    }

    @Override
    public boolean allowsEval() {
        return allAllow(Policy::allowsEval);
    }

    @Override
    public boolean allowsNavigation(
            final Optional<? extends URLWithScheme> to,
            final Optional<Boolean> redirected,
            final Optional<? extends URLWithScheme> redirectedTo,
            final Optional<? extends URLWithScheme> origin) {
        return allAllow(p -> p.allowsNavigation(to, redirected, redirectedTo, origin));
    }

    @Override
    public boolean allowsFormAction(
            final Optional<? extends URLWithScheme> to,
            final Optional<Boolean> redirected,
            final Optional<? extends URLWithScheme> redirectedTo,
            final Optional<? extends URLWithScheme> origin) {
        return allAllow(p -> p.allowsFormAction(to, redirected, redirectedTo, origin));
    }

    @Override
    public boolean allowsJavascriptUrlNavigation(
            final Optional<String> source,
            final Optional<? extends URLWithScheme> origin) {
        return allAllow(p -> p.allowsJavascriptUrlNavigation(source, origin));
    }

    @Override
    public boolean allowsExternalStyle(
            final Optional<String> nonce,
            final Optional<? extends URLWithScheme> styleUrl,
            final Optional<? extends URLWithScheme> origin) {
        return allAllow(p -> p.allowsExternalStyle(nonce, styleUrl, origin));
    }

    @Override
    public boolean allowsInlineStyle(final Optional<String> nonce, final Optional<String> source) {
        return allAllow(p -> p.allowsInlineStyle(nonce, source));
    }

    @Override
    public boolean allowsStyleAsAttribute(final Optional<String> source) {
        return allAllow(p -> p.allowsStyleAsAttribute(source));
    }

    @Override
    public boolean allowsFrame(final Optional<? extends URLWithScheme> source,
                               final Optional<? extends URLWithScheme> origin) {
        return allAllow(p -> p.allowsFrame(source, origin));
    }

    @Override
    public boolean allowsFrameAncestor(final Optional<? extends URLWithScheme> source,
                                       final Optional<? extends URLWithScheme> origin) {
        return allAllow(p -> p.allowsFrameAncestor(source, origin));
    }

    @Override
    public boolean allowsConnection(final Optional<? extends URLWithScheme> source,
                                    final Optional<? extends URLWithScheme> origin) {
        return allAllow(p -> p.allowsConnection(source, origin));
    }

    @Override
    public boolean allowsFont(final Optional<? extends URLWithScheme> source,
                              final Optional<? extends URLWithScheme> origin) {
        return allAllow(p -> p.allowsFont(source, origin));
    }

    @Override
    public boolean allowsImage(final Optional<? extends URLWithScheme> source,
                               final Optional<? extends URLWithScheme> origin) {
        return allAllow(p -> p.allowsImage(source, origin));
    }

    @Override
    public boolean allowsApplicationManifest(final Optional<? extends URLWithScheme> source,
                                             final Optional<? extends URLWithScheme> origin) {
        return allAllow(p -> p.allowsApplicationManifest(source, origin));
    }

    @Override
    public boolean allowsMedia(final Optional<? extends URLWithScheme> source,
                               final Optional<? extends URLWithScheme> origin) {
        return allAllow(p -> p.allowsMedia(source, origin));
    }

    @Override
    public boolean allowsObject(final Optional<? extends URLWithScheme> source,
                                final Optional<? extends URLWithScheme> origin) {
        return allAllow(p -> p.allowsObject(source, origin));
    }

    @Override
    public boolean allowsPrefetch(final Optional<? extends URLWithScheme> source,
                                  final Optional<? extends URLWithScheme> origin) {
        return allAllow(p -> p.allowsPrefetch(source, origin));
    }

    @Override
    public boolean allowsWorker(final Optional<? extends URLWithScheme> source,
                                final Optional<? extends URLWithScheme> origin) {
        return allAllow(p -> p.allowsWorker(source, origin));
    }

    @Override
    public boolean allowsPlugin(final Optional<? extends MediaType> mediaType) {
        return allAllow(p -> p.allowsPlugin(mediaType));
    }
}
