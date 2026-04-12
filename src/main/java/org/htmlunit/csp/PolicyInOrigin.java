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

/**
 * A convenience wrapper that pairs a {@link Policy} with its
 * {@link URLWithScheme origin}, providing simplified query methods that
 * automatically supply the origin to the underlying policy checks.
 * <p>
 * Each {@code allows*} method delegates to the corresponding method on
 * {@link Policy}, filling in {@code Optional.of(origin_)} for the origin
 * parameter and {@code Optional.empty()} for any parameters that are not
 * applicable to the simplified query (such as nonce, integrity, or
 * redirect information).
 * </p>
 *
 * @param policy_ the Content Security Policy to query against
 * @param origin_ the origin of the protected resource
 */
public record PolicyInOrigin(Policy policy_, URLWithScheme origin_) {

    /**
     * Returns the underlying {@link Policy}.
     *
     * @return the policy associated with this origin-bound wrapper
     */
    public Policy getPolicy() {
        return policy_;
    }

    // Low-level querying

    /**
     * Determines whether the policy allows loading an external script from the given URL.
     * <p>
     * Delegates to {@link Policy#allowsExternalScript} with no nonce, no integrity,
     * unknown parser-inserted status, and this wrapper's origin.
     * </p>
     *
     * @param url the URL of the external script
     * @return {@code true} if the policy allows the script from the given source
     */
    public boolean allowsScriptFromSource(final URLWithScheme url) {
        return policy_.allowsExternalScript(Optional.empty(),
                Optional.empty(), Optional.of(url), Optional.empty(), Optional.of(origin_));
    }

    /**
     * Determines whether the policy allows loading an external stylesheet from the given URL.
     * <p>
     * Delegates to {@link Policy#allowsExternalStyle} with no nonce and this wrapper's origin.
     * </p>
     *
     * @param url the URL of the external stylesheet
     * @return {@code true} if the policy allows the style from the given source
     */
    public boolean allowsStyleFromSource(final URLWithScheme url) {
        return policy_.allowsExternalStyle(Optional.empty(), Optional.of(url), Optional.of(origin_));
    }

    /**
     * Determines whether the policy allows loading an image from the given URL.
     * <p>
     * Delegates to {@link Policy#allowsImage} with this wrapper's origin.
     * </p>
     *
     * @param url the URL of the image resource
     * @return {@code true} if the policy allows the image from the given source
     */
    public boolean allowsImageFromSource(final URLWithScheme url) {
        return policy_.allowsImage(Optional.of(url), Optional.of(origin_));
    }

    /**
     * Determines whether the policy allows loading a frame from the given URL.
     * <p>
     * Delegates to {@link Policy#allowsFrame} with this wrapper's origin.
     * </p>
     *
     * @param url the URL of the framed resource
     * @return {@code true} if the policy allows the frame from the given source
     */
    public boolean allowsFrameFromSource(final URLWithScheme url) {
        return policy_.allowsFrame(Optional.of(url), Optional.of(origin_));
    }

    /**
     * Determines whether the policy allows loading a worker from the given URL.
     * <p>
     * Delegates to {@link Policy#allowsWorker} with this wrapper's origin.
     * </p>
     *
     * @param url the URL of the worker script
     * @return {@code true} if the policy allows the worker from the given source
     */
    public boolean allowsWorkerFromSource(final URLWithScheme url) {
        return policy_.allowsWorker(Optional.of(url), Optional.of(origin_));
    }

    /**
     * Determines whether the policy allows loading a font from the given URL.
     * <p>
     * Delegates to {@link Policy#allowsFont} with this wrapper's origin.
     * </p>
     *
     * @param url the URL of the font resource
     * @return {@code true} if the policy allows the font from the given source
     */
    public boolean allowsFontFromSource(final URLWithScheme url) {
        return policy_.allowsFont(Optional.of(url), Optional.of(origin_));
    }

    /**
     * Determines whether the policy allows loading an object/embed/applet from the given URL.
     * <p>
     * Delegates to {@link Policy#allowsObject} with this wrapper's origin.
     * </p>
     *
     * @param url the URL of the object resource
     * @return {@code true} if the policy allows the object from the given source
     */
    public boolean allowsObjectFromSource(final URLWithScheme url) {
        return policy_.allowsObject(Optional.of(url), Optional.of(origin_));
    }

    /**
     * Determines whether the policy allows loading media (audio/video) from the given URL.
     * <p>
     * Delegates to {@link Policy#allowsMedia} with this wrapper's origin.
     * </p>
     *
     * @param url the URL of the media resource
     * @return {@code true} if the policy allows the media from the given source
     */
    public boolean allowsMediaFromSource(final URLWithScheme url) {
        return policy_.allowsMedia(Optional.of(url), Optional.of(origin_));
    }

    /**
     * Determines whether the policy allows loading an application manifest from the given URL.
     * <p>
     * Delegates to {@link Policy#allowsApplicationManifest} with this wrapper's origin.
     * </p>
     *
     * @param url the URL of the manifest resource
     * @return {@code true} if the policy allows the manifest from the given source
     */
    public boolean allowsManifestFromSource(final URLWithScheme url) {
        return policy_.allowsApplicationManifest(Optional.of(url), Optional.of(origin_));
    }

    /**
     * Determines whether the policy allows a prefetch from the given URL.
     * <p>
     * Delegates to {@link Policy#allowsPrefetch} with this wrapper's origin.
     * </p>
     *
     * @param url the URL to prefetch
     * @return {@code true} if the policy allows the prefetch from the given source
     */
    public boolean allowsPrefetchFromSource(final URLWithScheme url) {
        return policy_.allowsPrefetch(Optional.of(url), Optional.of(origin_));
    }

    /**
     * Determines whether the policy allows any inline script without a nonce or hash.
     * <p>
     * Delegates to {@link Policy#allowsInlineScript} with no nonce, no source text,
     * and unknown parser-inserted status. This effectively checks whether
     * {@code 'unsafe-inline'} is active for scripts.
     * </p>
     *
     * @return {@code true} if the policy allows inline scripts without specific credentials
     */
    public boolean allowsUnsafeInlineScript() {
        return policy_.allowsInlineScript(Optional.empty(), Optional.empty(), Optional.empty());
    }

    /**
     * Determines whether the policy allows any inline style without a nonce or hash.
     * <p>
     * Delegates to {@link Policy#allowsInlineStyle} with no nonce and no source text.
     * This effectively checks whether {@code 'unsafe-inline'} is active for styles.
     * </p>
     *
     * @return {@code true} if the policy allows inline styles without specific credentials
     */
    public boolean allowsUnsafeInlineStyle() {
        return policy_.allowsInlineStyle(Optional.empty(), Optional.empty());
    }

    /**
     * Determines whether the policy allows a connection (e.g. {@code fetch()},
     * {@code XMLHttpRequest}, {@code WebSocket}) to the given URL.
     * <p>
     * Delegates to {@link Policy#allowsConnection} with this wrapper's origin.
     * </p>
     *
     * @param url the URL to connect to
     * @return {@code true} if the policy allows the connection to the given source
     */
    public boolean allowsConnection(final URLWithScheme url) {
        return policy_.allowsConnection(Optional.of(url), Optional.of(origin_));
    }

    /**
     * Determines whether the policy allows navigation to the given URL.
     * <p>
     * Delegates to {@link Policy#allowsNavigation} with unknown redirect status,
     * no redirect target, and this wrapper's origin.
     * </p>
     *
     * @param url the navigation target URL
     * @return {@code true} if the policy allows navigation to the given URL
     */
    public boolean allowsNavigation(final URLWithScheme url) {
        return policy_.allowsNavigation(Optional.of(url),
                Optional.empty(), Optional.empty(), Optional.of(origin_));
    }

    /**
     * Determines whether the policy allows being framed by the given ancestor URL.
     * <p>
     * Delegates to {@link Policy#allowsFrameAncestor} with this wrapper's origin.
     * </p>
     *
     * @param url the URL of the ancestor frame
     * @return {@code true} if the policy allows the frame ancestor
     */
    public boolean allowsFrameAncestor(final URLWithScheme url) {
        return policy_.allowsFrameAncestor(Optional.of(url), Optional.of(origin_));
    }

    /**
     * Determines whether the policy allows a form submission to the given URL.
     * <p>
     * Delegates to {@link Policy#allowsFormAction} with unknown redirect status,
     * no redirect target, and this wrapper's origin.
     * </p>
     *
     * @param url the form action target URL
     * @return {@code true} if the policy allows the form action to the given URL
     */
    public boolean allowsFormAction(final URLWithScheme url) {
        return policy_.allowsFormAction(Optional.of(url),
                Optional.empty(), Optional.empty(), Optional.of(origin_));
    }
}
