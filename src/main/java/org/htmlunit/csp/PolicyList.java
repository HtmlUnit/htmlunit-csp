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
 * Instances are created by
 * {@link Policy#parseSerializedCSPList(String, PolicyListErrorConsumer)}
 * or {@link #ofSerialized(List, PolicyListErrorConsumer)}.
 * Empty policies (those with no directives) are omitted during parsing.
 * An empty list (no policies) is treated as unrestricted: all {@code allows*}
 * methods return {@code true}.
 * </p>
 *
 * @author Ronald Brill
 * @see Policy#parseSerializedCSPList(String, PolicyListErrorConsumer)
 */
public class PolicyList {
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

    // High-level querying: AND across all member policies

    /**
     * Whether every member policy allows the external script.
     * @param nonce script nonce, if any
     * @param integrity SRI metadata, if any
     * @param scriptUrl script URL, if known
     * @param parserInserted whether the script is parser-inserted
     * @param origin protected-resource origin, if known
     * @return {@code true} if every member allows
     * @see Policy#allowsExternalScript
     * @since 5.4.0
     */
    public boolean allowsExternalScript(
            final Optional<String> nonce,
            final Optional<String> integrity,
            final Optional<? extends URLWithScheme> scriptUrl,
            final Optional<Boolean> parserInserted,
            final Optional<? extends URLWithScheme> origin) {
        return policies_.stream().allMatch(p ->
                p.allowsExternalScript(nonce, integrity, scriptUrl, parserInserted, origin));
    }

    /**
     * Whether every member policy allows the inline script.
     * @param nonce script nonce, if any
     * @param source inline script text, if known
     * @param parserInserted whether the script is parser-inserted
     * @return {@code true} if every member allows
     * @see Policy#allowsInlineScript
     * @since 5.4.0
     */
    public boolean allowsInlineScript(final Optional<String> nonce,
            final Optional<String> source, final Optional<Boolean> parserInserted) {
        return policies_.stream().allMatch(p -> p.allowsInlineScript(nonce, source, parserInserted));
    }

    /**
     * Whether every member policy allows the script event-handler attribute.
     * @param source attribute text, if known
     * @return {@code true} if every member allows
     * @see Policy#allowsScriptAsAttribute
     * @since 5.4.0
     */
    public boolean allowsScriptAsAttribute(final Optional<String> source) {
        return policies_.stream().allMatch(p -> p.allowsScriptAsAttribute(source));
    }

    /**
     * Whether every member policy allows eval.
     * @return {@code true} if every member allows
     * @see Policy#allowsEval
     * @since 5.4.0
     */
    public boolean allowsEval() {
        return policies_.stream().allMatch(Policy::allowsEval);
    }

    /**
     * Whether every member policy allows the navigation.
     * @param to navigation target URL, if known
     * @param redirected whether the navigation is a redirect
     * @param redirectedTo final URL after redirect, if known
     * @param origin protected-resource origin, if known
     * @return {@code true} if every member allows
     * @see Policy#allowsNavigation
     * @since 5.4.0
     */
    public boolean allowsNavigation(
            final Optional<? extends URLWithScheme> to,
            final Optional<Boolean> redirected,
            final Optional<? extends URLWithScheme> redirectedTo,
            final Optional<? extends URLWithScheme> origin) {
        return policies_.stream().allMatch(p -> p.allowsNavigation(to, redirected, redirectedTo, origin));
    }

    /**
     * Whether every member policy allows the form action.
     * @param to form action URL, if known
     * @param redirected whether the submission redirects
     * @param redirectedTo final URL after redirect, if known
     * @param origin protected-resource origin, if known
     * @return {@code true} if every member allows
     * @see Policy#allowsFormAction
     * @since 5.4.0
     */
    public boolean allowsFormAction(
            final Optional<? extends URLWithScheme> to,
            final Optional<Boolean> redirected,
            final Optional<? extends URLWithScheme> redirectedTo,
            final Optional<? extends URLWithScheme> origin) {
        return policies_.stream().allMatch(p -> p.allowsFormAction(to, redirected, redirectedTo, origin));
    }

    /**
     * Whether every member policy allows the {@code javascript:} URL navigation.
     * @param source JavaScript after the {@code javascript:} prefix, if known
     * @param origin protected-resource origin, if known
     * @return {@code true} if every member allows
     * @see Policy#allowsJavascriptUrlNavigation
     * @since 5.4.0
     */
    public boolean allowsJavascriptUrlNavigation(
            final Optional<String> source,
            final Optional<? extends URLWithScheme> origin) {
        return policies_.stream().allMatch(p -> p.allowsJavascriptUrlNavigation(source, origin));
    }

    /**
     * Whether every member policy allows the external stylesheet.
     * @param nonce link nonce, if any
     * @param styleUrl stylesheet URL, if known
     * @param origin protected-resource origin, if known
     * @return {@code true} if every member allows
     * @see Policy#allowsExternalStyle
     * @since 5.4.0
     */
    public boolean allowsExternalStyle(
            final Optional<String> nonce,
            final Optional<? extends URLWithScheme> styleUrl,
            final Optional<? extends URLWithScheme> origin) {
        return policies_.stream().allMatch(p -> p.allowsExternalStyle(nonce, styleUrl, origin));
    }

    /**
     * Whether every member policy allows the inline style.
     * @param nonce style nonce, if any
     * @param source inline style text, if known
     * @return {@code true} if every member allows
     * @see Policy#allowsInlineStyle
     * @since 5.4.0
     */
    public boolean allowsInlineStyle(final Optional<String> nonce, final Optional<String> source) {
        return policies_.stream().allMatch(p -> p.allowsInlineStyle(nonce, source));
    }

    /**
     * Whether every member policy allows the style attribute.
     * @param source attribute text, if known
     * @return {@code true} if every member allows
     * @see Policy#allowsStyleAsAttribute
     * @since 5.4.0
     */
    public boolean allowsStyleAsAttribute(final Optional<String> source) {
        return policies_.stream().allMatch(p -> p.allowsStyleAsAttribute(source));
    }

    /**
     * Whether every member policy allows the frame.
     * @param source framed resource URL, if known
     * @param origin protected-resource origin, if known
     * @return {@code true} if every member allows
     * @see Policy#allowsFrame
     * @since 5.4.0
     */
    public boolean allowsFrame(final Optional<? extends URLWithScheme> source,
                               final Optional<? extends URLWithScheme> origin) {
        return policies_.stream().allMatch(p -> p.allowsFrame(source, origin));
    }

    /**
     * Whether every member policy allows the frame ancestor.
     * @param source ancestor frame URL, if known
     * @param origin protected-resource origin, if known
     * @return {@code true} if every member allows
     * @see Policy#allowsFrameAncestor
     * @since 5.4.0
     */
    public boolean allowsFrameAncestor(final Optional<? extends URLWithScheme> source,
                                       final Optional<? extends URLWithScheme> origin) {
        return policies_.stream().allMatch(p -> p.allowsFrameAncestor(source, origin));
    }

    /**
     * Whether every member policy allows the connection.
     * @param source connection URL, if known
     * @param origin protected-resource origin, if known
     * @return {@code true} if every member allows
     * @see Policy#allowsConnection
     * @since 5.4.0
     */
    public boolean allowsConnection(final Optional<? extends URLWithScheme> source,
                                    final Optional<? extends URLWithScheme> origin) {
        return policies_.stream().allMatch(p -> p.allowsConnection(source, origin));
    }

    /**
     * Whether every member policy allows the font.
     * @param source font URL, if known
     * @param origin protected-resource origin, if known
     * @return {@code true} if every member allows
     * @see Policy#allowsFont
     * @since 5.4.0
     */
    public boolean allowsFont(final Optional<? extends URLWithScheme> source,
                              final Optional<? extends URLWithScheme> origin) {
        return policies_.stream().allMatch(p -> p.allowsFont(source, origin));
    }

    /**
     * Whether every member policy allows the image.
     * @param source image URL, if known
     * @param origin protected-resource origin, if known
     * @return {@code true} if every member allows
     * @see Policy#allowsImage
     * @since 5.4.0
     */
    public boolean allowsImage(final Optional<? extends URLWithScheme> source,
                               final Optional<? extends URLWithScheme> origin) {
        return policies_.stream().allMatch(p -> p.allowsImage(source, origin));
    }

    /**
     * Whether every member policy allows the application manifest.
     * @param source manifest URL, if known
     * @param origin protected-resource origin, if known
     * @return {@code true} if every member allows
     * @see Policy#allowsApplicationManifest
     * @since 5.4.0
     */
    public boolean allowsApplicationManifest(final Optional<? extends URLWithScheme> source,
                                             final Optional<? extends URLWithScheme> origin) {
        return policies_.stream().allMatch(p -> p.allowsApplicationManifest(source, origin));
    }

    /**
     * Whether every member policy allows the media.
     * @param source media URL, if known
     * @param origin protected-resource origin, if known
     * @return {@code true} if every member allows
     * @see Policy#allowsMedia
     * @since 5.4.0
     */
    public boolean allowsMedia(final Optional<? extends URLWithScheme> source,
                               final Optional<? extends URLWithScheme> origin) {
        return policies_.stream().allMatch(p -> p.allowsMedia(source, origin));
    }

    /**
     * Whether every member policy allows the object.
     * @param source object URL, if known
     * @param origin protected-resource origin, if known
     * @return {@code true} if every member allows
     * @see Policy#allowsObject
     * @since 5.4.0
     */
    public boolean allowsObject(final Optional<? extends URLWithScheme> source,
                                final Optional<? extends URLWithScheme> origin) {
        return policies_.stream().allMatch(p -> p.allowsObject(source, origin));
    }

    /**
     * Whether every member policy allows the prefetch.
     * @param source prefetch URL, if known
     * @param origin protected-resource origin, if known
     * @return {@code true} if every member allows
     * @see Policy#allowsPrefetch
     * @since 5.4.0
     */
    public boolean allowsPrefetch(final Optional<? extends URLWithScheme> source,
                                  final Optional<? extends URLWithScheme> origin) {
        return policies_.stream().allMatch(p -> p.allowsPrefetch(source, origin));
    }

    /**
     * Whether every member policy allows the worker.
     * @param source worker URL, if known
     * @param origin protected-resource origin, if known
     * @return {@code true} if every member allows
     * @see Policy#allowsWorker
     * @since 5.4.0
     */
    public boolean allowsWorker(final Optional<? extends URLWithScheme> source,
                                final Optional<? extends URLWithScheme> origin) {
        return policies_.stream().allMatch(p -> p.allowsWorker(source, origin));
    }

    /**
     * Whether every member policy allows the plugin type.
     * @param mediaType plugin media type, if known
     * @return {@code true} if every member allows
     * @see Policy#allowsPlugin
     * @since 5.4.0
     */
    public boolean allowsPlugin(final Optional<? extends MediaType> mediaType) {
        return policies_.stream().allMatch(p -> p.allowsPlugin(mediaType));
    }
}
