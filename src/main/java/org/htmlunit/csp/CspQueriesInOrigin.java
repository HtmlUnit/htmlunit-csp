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

import java.util.Objects;
import java.util.Optional;

import org.htmlunit.csp.url.URLWithScheme;

/**
 * Convenience wrapper that pairs a {@link CspQueries} target with an
 * {@link URLWithScheme origin}, supplying simplified query methods that
 * fill in the origin and leave unused parameters empty.
 * <p>
 * Use {@link PolicyInOrigin} or {@link PolicyListInOrigin} when a typed
 * accessor for the underlying {@link Policy} / {@link PolicyList} is needed.
 * </p>
 *
 * @author Ronald Brill
 * @see CspQueries
 * @see PolicyInOrigin
 * @see PolicyListInOrigin
 * @since 5.4.0
 */
public class CspQueriesInOrigin {
    private final CspQueries queries_;
    private final URLWithScheme origin_;

    /**
     * Ctor.
     *
     * @param queries the query target ({@link Policy} or {@link PolicyList})
     * @param origin the origin of the protected resource
     * @throws NullPointerException if {@code queries} or {@code origin} is {@code null}
     */
    public CspQueriesInOrigin(final CspQueries queries, final URLWithScheme origin) {
        queries_ = Objects.requireNonNull(queries, "queries");
        origin_ = Objects.requireNonNull(origin, "origin");
    }

    /**
     * Returns the underlying query target.
     *
     * @return the {@link CspQueries} associated with this wrapper
     */
    public CspQueries getQueries() {
        return queries_;
    }

    /**
     * Returns the underlying origin.
     *
     * @return the origin of the protected resource
     */
    public URLWithScheme getOrigin() {
        return origin_;
    }

    /**
     * Returns whether an external script from the given URL is allowed.
     *
     * @param url the URL of the external script
     * @return {@code true} if allowed under this query target's rules
     * @see CspQueries#allowsExternalScript
     */
    public boolean allowsScriptFromSource(final URLWithScheme url) {
        return queries_.allowsExternalScript(Optional.empty(),
                Optional.empty(), Optional.of(url), Optional.empty(), Optional.of(origin_));
    }

    /**
     * Returns whether an external stylesheet from the given URL is allowed.
     *
     * @param url the URL of the external stylesheet
     * @return {@code true} if allowed under this query target's rules
     * @see CspQueries#allowsExternalStyle
     */
    public boolean allowsStyleFromSource(final URLWithScheme url) {
        return queries_.allowsExternalStyle(Optional.empty(), Optional.of(url), Optional.of(origin_));
    }

    /**
     * Returns whether an image from the given URL is allowed.
     *
     * @param url the URL of the image resource
     * @return {@code true} if allowed under this query target's rules
     * @see CspQueries#allowsImage
     */
    public boolean allowsImageFromSource(final URLWithScheme url) {
        return queries_.allowsImage(Optional.of(url), Optional.of(origin_));
    }

    /**
     * Returns whether a frame from the given URL is allowed.
     *
     * @param url the URL of the framed resource
     * @return {@code true} if allowed under this query target's rules
     * @see CspQueries#allowsFrame
     */
    public boolean allowsFrameFromSource(final URLWithScheme url) {
        return queries_.allowsFrame(Optional.of(url), Optional.of(origin_));
    }

    /**
     * Returns whether a worker from the given URL is allowed.
     *
     * @param url the URL of the worker script
     * @return {@code true} if allowed under this query target's rules
     * @see CspQueries#allowsWorker
     */
    public boolean allowsWorkerFromSource(final URLWithScheme url) {
        return queries_.allowsWorker(Optional.of(url), Optional.of(origin_));
    }

    /**
     * Returns whether a font from the given URL is allowed.
     *
     * @param url the URL of the font resource
     * @return {@code true} if allowed under this query target's rules
     * @see CspQueries#allowsFont
     */
    public boolean allowsFontFromSource(final URLWithScheme url) {
        return queries_.allowsFont(Optional.of(url), Optional.of(origin_));
    }

    /**
     * Returns whether an object from the given URL is allowed.
     *
     * @param url the URL of the object resource
     * @return {@code true} if allowed under this query target's rules
     * @see CspQueries#allowsObject
     */
    public boolean allowsObjectFromSource(final URLWithScheme url) {
        return queries_.allowsObject(Optional.of(url), Optional.of(origin_));
    }

    /**
     * Returns whether media from the given URL is allowed.
     *
     * @param url the URL of the media resource
     * @return {@code true} if allowed under this query target's rules
     * @see CspQueries#allowsMedia
     */
    public boolean allowsMediaFromSource(final URLWithScheme url) {
        return queries_.allowsMedia(Optional.of(url), Optional.of(origin_));
    }

    /**
     * Returns whether an application manifest from the given URL is allowed.
     *
     * @param url the URL of the manifest resource
     * @return {@code true} if allowed under this query target's rules
     * @see CspQueries#allowsApplicationManifest
     */
    public boolean allowsManifestFromSource(final URLWithScheme url) {
        return queries_.allowsApplicationManifest(Optional.of(url), Optional.of(origin_));
    }

    /**
     * Returns whether a prefetch from the given URL is allowed.
     *
     * @param url the URL to prefetch
     * @return {@code true} if allowed under this query target's rules
     * @see CspQueries#allowsPrefetch
     */
    public boolean allowsPrefetchFromSource(final URLWithScheme url) {
        return queries_.allowsPrefetch(Optional.of(url), Optional.of(origin_));
    }

    /**
     * Returns whether unsafe inline script is allowed.
     *
     * @return {@code true} if allowed under this query target's rules
     * @see CspQueries#allowsInlineScript
     */
    public boolean allowsUnsafeInlineScript() {
        return queries_.allowsInlineScript(Optional.empty(), Optional.empty(), Optional.empty());
    }

    /**
     * Returns whether unsafe inline style is allowed.
     *
     * @return {@code true} if allowed under this query target's rules
     * @see CspQueries#allowsInlineStyle
     */
    public boolean allowsUnsafeInlineStyle() {
        return queries_.allowsInlineStyle(Optional.empty(), Optional.empty());
    }

    /**
     * Returns whether eval is allowed.
     *
     * @return {@code true} if allowed under this query target's rules
     * @see CspQueries#allowsEval
     */
    public boolean allowsEval() {
        return queries_.allowsEval();
    }

    /**
     * Returns whether a connection to the given URL is allowed.
     *
     * @param url the URL to connect to
     * @return {@code true} if allowed under this query target's rules
     * @see CspQueries#allowsConnection
     */
    public boolean allowsConnection(final URLWithScheme url) {
        return queries_.allowsConnection(Optional.of(url), Optional.of(origin_));
    }

    /**
     * Returns whether navigation to the given URL is allowed.
     *
     * @param url the navigation target URL
     * @return {@code true} if allowed under this query target's rules
     * @see CspQueries#allowsNavigation
     */
    public boolean allowsNavigation(final URLWithScheme url) {
        return queries_.allowsNavigation(Optional.of(url),
                Optional.empty(), Optional.empty(), Optional.of(origin_));
    }

    /**
     * Returns whether the given frame ancestor is allowed.
     *
     * @param url the URL of the ancestor frame
     * @return {@code true} if allowed under this query target's rules
     * @see CspQueries#allowsFrameAncestor
     */
    public boolean allowsFrameAncestor(final URLWithScheme url) {
        return queries_.allowsFrameAncestor(Optional.of(url), Optional.of(origin_));
    }

    /**
     * Returns whether a form action to the given URL is allowed.
     *
     * @param url the form action target URL
     * @return {@code true} if allowed under this query target's rules
     * @see CspQueries#allowsFormAction
     */
    public boolean allowsFormAction(final URLWithScheme url) {
        return queries_.allowsFormAction(Optional.of(url),
                Optional.empty(), Optional.empty(), Optional.of(origin_));
    }
}
