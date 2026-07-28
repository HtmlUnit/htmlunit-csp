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

import java.util.Optional;

import org.htmlunit.csp.url.URLWithScheme;
import org.htmlunit.csp.value.MediaType;

/**
 * Enforcement query API shared by {@link Policy} and {@link PolicyList}.
 * <p>
 * For a single {@link Policy}, each method applies that policy's rules.
 * For a {@link PolicyList}, each method returns {@code true} only if every
 * member policy allows the resource (an empty list is unrestricted).
 * Semantics of individual checks are documented on {@link Policy}.
 * </p>
 *
 * @author Ronald Brill
 * @see Policy
 * @see PolicyList
 * @see CspQueriesInOrigin
 * @since 5.4.0
 */
public interface CspQueries {

    /**
     * Returns whether an external script is allowed.
     *
     * @param nonce script nonce, if any
     * @param integrity SRI metadata, if any
     * @param scriptUrl script URL, if known
     * @param parserInserted whether the script is parser-inserted
     * @param origin protected-resource origin, if known
     * @return {@code true} if allowed under this query target's rules
     * @see Policy#allowsExternalScript
     */
    boolean allowsExternalScript(
            Optional<String> nonce,
            Optional<String> integrity,
            Optional<? extends URLWithScheme> scriptUrl,
            Optional<Boolean> parserInserted,
            Optional<? extends URLWithScheme> origin);

    /**
     * Returns whether an inline script is allowed.
     *
     * @param nonce script nonce, if any
     * @param source inline script text, if known
     * @param parserInserted whether the script is parser-inserted
     * @return {@code true} if allowed under this query target's rules
     * @see Policy#allowsInlineScript
     */
    boolean allowsInlineScript(Optional<String> nonce,
            Optional<String> source, Optional<Boolean> parserInserted);

    /**
     * Returns whether a script event-handler attribute is allowed.
     *
     * @param source attribute text, if known
     * @return {@code true} if allowed under this query target's rules
     * @see Policy#allowsScriptAsAttribute
     */
    boolean allowsScriptAsAttribute(Optional<String> source);

    /**
     * Returns whether eval is allowed.
     *
     * @return {@code true} if allowed under this query target's rules
     * @see Policy#allowsEval
     */
    boolean allowsEval();

    /**
     * Returns whether navigation is allowed.
     *
     * @param to navigation target URL, if known
     * @param redirected whether the navigation is a redirect
     * @param redirectedTo final URL after redirect, if known
     * @param origin protected-resource origin, if known
     * @return {@code true} if allowed under this query target's rules
     * @see Policy#allowsNavigation
     */
    boolean allowsNavigation(
            Optional<? extends URLWithScheme> to,
            Optional<Boolean> redirected,
            Optional<? extends URLWithScheme> redirectedTo,
            Optional<? extends URLWithScheme> origin);

    /**
     * Returns whether a form action is allowed.
     *
     * @param to form action URL, if known
     * @param redirected whether the submission redirects
     * @param redirectedTo final URL after redirect, if known
     * @param origin protected-resource origin, if known
     * @return {@code true} if allowed under this query target's rules
     * @see Policy#allowsFormAction
     */
    boolean allowsFormAction(
            Optional<? extends URLWithScheme> to,
            Optional<Boolean> redirected,
            Optional<? extends URLWithScheme> redirectedTo,
            Optional<? extends URLWithScheme> origin);

    /**
     * Returns whether a {@code javascript:} URL navigation is allowed.
     *
     * @param source JavaScript after the {@code javascript:} prefix, if known
     * @param origin protected-resource origin, if known
     * @return {@code true} if allowed under this query target's rules
     * @see Policy#allowsJavascriptUrlNavigation
     */
    boolean allowsJavascriptUrlNavigation(
            Optional<String> source,
            Optional<? extends URLWithScheme> origin);

    /**
     * Returns whether an external stylesheet is allowed.
     *
     * @param nonce style nonce, if any
     * @param styleUrl stylesheet URL, if known
     * @param origin protected-resource origin, if known
     * @return {@code true} if allowed under this query target's rules
     * @see Policy#allowsExternalStyle
     */
    boolean allowsExternalStyle(
            Optional<String> nonce,
            Optional<? extends URLWithScheme> styleUrl,
            Optional<? extends URLWithScheme> origin);

    /**
     * Returns whether an inline style is allowed.
     *
     * @param nonce style nonce, if any
     * @param source inline style text, if known
     * @return {@code true} if allowed under this query target's rules
     * @see Policy#allowsInlineStyle
     */
    boolean allowsInlineStyle(Optional<String> nonce, Optional<String> source);

    /**
     * Returns whether a style attribute is allowed.
     *
     * @param source attribute text, if known
     * @return {@code true} if allowed under this query target's rules
     * @see Policy#allowsStyleAsAttribute
     */
    boolean allowsStyleAsAttribute(Optional<String> source);

    /**
     * Returns whether a frame is allowed.
     *
     * @param source framed resource URL, if known
     * @param origin protected-resource origin, if known
     * @return {@code true} if allowed under this query target's rules
     * @see Policy#allowsFrame
     */
    boolean allowsFrame(Optional<? extends URLWithScheme> source,
            Optional<? extends URLWithScheme> origin);

    /**
     * Returns whether a frame ancestor is allowed.
     *
     * @param source ancestor frame URL, if known
     * @param origin protected-resource origin, if known
     * @return {@code true} if allowed under this query target's rules
     * @see Policy#allowsFrameAncestor
     */
    boolean allowsFrameAncestor(Optional<? extends URLWithScheme> source,
            Optional<? extends URLWithScheme> origin);

    /**
     * Returns whether a connection is allowed.
     *
     * @param source connection URL, if known
     * @param origin protected-resource origin, if known
     * @return {@code true} if allowed under this query target's rules
     * @see Policy#allowsConnection
     */
    boolean allowsConnection(Optional<? extends URLWithScheme> source,
            Optional<? extends URLWithScheme> origin);

    /**
     * Returns whether a font is allowed.
     *
     * @param source font URL, if known
     * @param origin protected-resource origin, if known
     * @return {@code true} if allowed under this query target's rules
     * @see Policy#allowsFont
     */
    boolean allowsFont(Optional<? extends URLWithScheme> source,
            Optional<? extends URLWithScheme> origin);

    /**
     * Returns whether an image is allowed.
     *
     * @param source image URL, if known
     * @param origin protected-resource origin, if known
     * @return {@code true} if allowed under this query target's rules
     * @see Policy#allowsImage
     */
    boolean allowsImage(Optional<? extends URLWithScheme> source,
            Optional<? extends URLWithScheme> origin);

    /**
     * Returns whether an application manifest is allowed.
     *
     * @param source manifest URL, if known
     * @param origin protected-resource origin, if known
     * @return {@code true} if allowed under this query target's rules
     * @see Policy#allowsApplicationManifest
     */
    boolean allowsApplicationManifest(Optional<? extends URLWithScheme> source,
            Optional<? extends URLWithScheme> origin);

    /**
     * Returns whether media is allowed.
     *
     * @param source media URL, if known
     * @param origin protected-resource origin, if known
     * @return {@code true} if allowed under this query target's rules
     * @see Policy#allowsMedia
     */
    boolean allowsMedia(Optional<? extends URLWithScheme> source,
            Optional<? extends URLWithScheme> origin);

    /**
     * Returns whether an object is allowed.
     *
     * @param source object URL, if known
     * @param origin protected-resource origin, if known
     * @return {@code true} if allowed under this query target's rules
     * @see Policy#allowsObject
     */
    boolean allowsObject(Optional<? extends URLWithScheme> source,
            Optional<? extends URLWithScheme> origin);

    /**
     * Returns whether a prefetch is allowed.
     *
     * @param source prefetch URL, if known
     * @param origin protected-resource origin, if known
     * @return {@code true} if allowed under this query target's rules
     * @see Policy#allowsPrefetch
     */
    boolean allowsPrefetch(Optional<? extends URLWithScheme> source,
            Optional<? extends URLWithScheme> origin);

    /**
     * Returns whether a worker is allowed.
     *
     * @param source worker URL, if known
     * @param origin protected-resource origin, if known
     * @return {@code true} if allowed under this query target's rules
     * @see Policy#allowsWorker
     */
    boolean allowsWorker(Optional<? extends URLWithScheme> source,
            Optional<? extends URLWithScheme> origin);

    /**
     * Returns whether a plugin type is allowed.
     *
     * @param mediaType plugin media type, if known
     * @return {@code true} if allowed under this query target's rules
     * @see Policy#allowsPlugin
     */
    boolean allowsPlugin(Optional<? extends MediaType> mediaType);
}
