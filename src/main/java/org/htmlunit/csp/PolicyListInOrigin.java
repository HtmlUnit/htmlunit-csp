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
 * A convenience wrapper that pairs a {@link PolicyList} with its
 * {@link URLWithScheme origin}, providing simplified query methods that
 * automatically supply the origin to the underlying list checks.
 * <p>
 * Each {@code allows*} method delegates to the corresponding method on
 * {@link PolicyList}, which returns {@code true} only when every member
 * {@link Policy} allows the resource.
 * </p>
 *
 * @author Ronald Brill
 * @see PolicyInOrigin
 * @see PolicyList
 * @since 5.4.0
 */
public class PolicyListInOrigin {
    private final PolicyList policyList_;
    private final URLWithScheme origin_;

    /**
     * Ctor.
     *
     * @param policyList the Content Security Policy list to query against
     * @param origin the origin of the protected resource
     */
    public PolicyListInOrigin(final PolicyList policyList, final URLWithScheme origin) {
        policyList_ = policyList;
        origin_ = origin;
    }

    /**
     * Returns the underlying {@link PolicyList}.
     *
     * @return the policy list associated with this origin-bound wrapper
     */
    public PolicyList getPolicyList() {
        return policyList_;
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
     * Determines whether every policy allows loading an external script from the given URL.
     *
     * @param url the URL of the external script
     * @return {@code true} if every member policy allows the script from the given source
     */
    public boolean allowsScriptFromSource(final URLWithScheme url) {
        return policyList_.allowsExternalScript(Optional.empty(),
                Optional.empty(), Optional.of(url), Optional.empty(), Optional.of(origin_));
    }

    /**
     * Determines whether every policy allows loading an external stylesheet from the given URL.
     *
     * @param url the URL of the external stylesheet
     * @return {@code true} if every member policy allows the style from the given source
     */
    public boolean allowsStyleFromSource(final URLWithScheme url) {
        return policyList_.allowsExternalStyle(Optional.empty(), Optional.of(url), Optional.of(origin_));
    }

    /**
     * Determines whether every policy allows loading an image from the given URL.
     *
     * @param url the URL of the image resource
     * @return {@code true} if every member policy allows the image from the given source
     */
    public boolean allowsImageFromSource(final URLWithScheme url) {
        return policyList_.allowsImage(Optional.of(url), Optional.of(origin_));
    }

    /**
     * Determines whether every policy allows loading a frame from the given URL.
     *
     * @param url the URL of the framed resource
     * @return {@code true} if every member policy allows the frame from the given source
     */
    public boolean allowsFrameFromSource(final URLWithScheme url) {
        return policyList_.allowsFrame(Optional.of(url), Optional.of(origin_));
    }

    /**
     * Determines whether every policy allows loading a worker from the given URL.
     *
     * @param url the URL of the worker script
     * @return {@code true} if every member policy allows the worker from the given source
     */
    public boolean allowsWorkerFromSource(final URLWithScheme url) {
        return policyList_.allowsWorker(Optional.of(url), Optional.of(origin_));
    }

    /**
     * Determines whether every policy allows loading a font from the given URL.
     *
     * @param url the URL of the font resource
     * @return {@code true} if every member policy allows the font from the given source
     */
    public boolean allowsFontFromSource(final URLWithScheme url) {
        return policyList_.allowsFont(Optional.of(url), Optional.of(origin_));
    }

    /**
     * Determines whether every policy allows loading an object/embed/applet from the given URL.
     *
     * @param url the URL of the object resource
     * @return {@code true} if every member policy allows the object from the given source
     */
    public boolean allowsObjectFromSource(final URLWithScheme url) {
        return policyList_.allowsObject(Optional.of(url), Optional.of(origin_));
    }

    /**
     * Determines whether every policy allows loading media (audio/video) from the given URL.
     *
     * @param url the URL of the media resource
     * @return {@code true} if every member policy allows the media from the given source
     */
    public boolean allowsMediaFromSource(final URLWithScheme url) {
        return policyList_.allowsMedia(Optional.of(url), Optional.of(origin_));
    }

    /**
     * Determines whether every policy allows loading an application manifest from the given URL.
     *
     * @param url the URL of the manifest resource
     * @return {@code true} if every member policy allows the manifest from the given source
     */
    public boolean allowsManifestFromSource(final URLWithScheme url) {
        return policyList_.allowsApplicationManifest(Optional.of(url), Optional.of(origin_));
    }

    /**
     * Determines whether every policy allows a prefetch from the given URL.
     *
     * @param url the URL to prefetch
     * @return {@code true} if every member policy allows the prefetch from the given source
     */
    public boolean allowsPrefetchFromSource(final URLWithScheme url) {
        return policyList_.allowsPrefetch(Optional.of(url), Optional.of(origin_));
    }

    /**
     * Determines whether every policy allows any inline script without a nonce or hash.
     *
     * @return {@code true} if every member policy allows inline scripts without specific credentials
     */
    public boolean allowsUnsafeInlineScript() {
        return policyList_.allowsInlineScript(Optional.empty(), Optional.empty(), Optional.empty());
    }

    /**
     * Determines whether every policy allows any inline style without a nonce or hash.
     *
     * @return {@code true} if every member policy allows inline styles without specific credentials
     */
    public boolean allowsUnsafeInlineStyle() {
        return policyList_.allowsInlineStyle(Optional.empty(), Optional.empty());
    }

    /**
     * Determines whether every policy allows a connection to the given URL.
     *
     * @param url the URL to connect to
     * @return {@code true} if every member policy allows the connection to the given source
     */
    public boolean allowsConnection(final URLWithScheme url) {
        return policyList_.allowsConnection(Optional.of(url), Optional.of(origin_));
    }

    /**
     * Determines whether every policy allows navigation to the given URL.
     *
     * @param url the navigation target URL
     * @return {@code true} if every member policy allows navigation to the given URL
     */
    public boolean allowsNavigation(final URLWithScheme url) {
        return policyList_.allowsNavigation(Optional.of(url),
                Optional.empty(), Optional.empty(), Optional.of(origin_));
    }

    /**
     * Determines whether every policy allows being framed by the given ancestor URL.
     *
     * @param url the URL of the ancestor frame
     * @return {@code true} if every member policy allows the frame ancestor
     */
    public boolean allowsFrameAncestor(final URLWithScheme url) {
        return policyList_.allowsFrameAncestor(Optional.of(url), Optional.of(origin_));
    }

    /**
     * Determines whether every policy allows a form submission to the given URL.
     *
     * @param url the form action target URL
     * @return {@code true} if every member policy allows the form action to the given URL
     */
    public boolean allowsFormAction(final URLWithScheme url) {
        return policyList_.allowsFormAction(Optional.of(url),
                Optional.empty(), Optional.empty(), Optional.of(origin_));
    }

    /**
     * Determines whether every policy allows eval.
     *
     * @return {@code true} if every member policy allows eval
     */
    public boolean allowsEval() {
        return policyList_.allowsEval();
    }
}
