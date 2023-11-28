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

import java.util.Optional;

import org.htmlunit.csp.url.URLWithScheme;

public class PolicyInOrigin {
    private final Policy policy_;
    private final URLWithScheme origin_;

    public PolicyInOrigin(final Policy policy, final URLWithScheme origin) {
        this.policy_ = policy;
        this.origin_ = origin;
    }

    public Policy getPolicy() {
        return policy_;
    }

    // Low-level querying

    public boolean allowsScriptFromSource(final URLWithScheme url) {
        return this.policy_.allowsExternalScript(Optional.empty(),
                Optional.empty(), Optional.of(url), Optional.empty(), Optional.of(this.origin_));
    }

    public boolean allowsStyleFromSource(final URLWithScheme url) {
        return this.policy_.allowsExternalStyle(Optional.empty(), Optional.of(url), Optional.of(this.origin_));
    }

    public boolean allowsImageFromSource(final URLWithScheme url) {
        return this.policy_.allowsImage(Optional.of(url), Optional.of(this.origin_));
    }

    public boolean allowsFrameFromSource(final URLWithScheme url) {
        return this.policy_.allowsFrame(Optional.of(url), Optional.of(this.origin_));
    }

    public boolean allowsWorkerFromSource(final URLWithScheme url) {
        return this.policy_.allowsWorker(Optional.of(url), Optional.of(this.origin_));
    }

    public boolean allowsFontFromSource(final URLWithScheme url) {
        return this.policy_.allowsFont(Optional.of(url), Optional.of(this.origin_));
    }

    public boolean allowsObjectFromSource(final URLWithScheme url) {
        return this.policy_.allowsObject(Optional.of(url), Optional.of(this.origin_));
    }

    public boolean allowsMediaFromSource(final URLWithScheme url) {
        return this.policy_.allowsMedia(Optional.of(url), Optional.of(this.origin_));
    }

    public boolean allowsManifestFromSource(final URLWithScheme url) {
        return this.policy_.allowsApplicationManifest(Optional.of(url), Optional.of(this.origin_));
    }

    public boolean allowsPrefetchFromSource(final URLWithScheme url) {
        return this.policy_.allowsPrefetch(Optional.of(url), Optional.of(this.origin_));
    }

    public boolean allowsUnsafeInlineScript() {
        return this.policy_.allowsInlineScript(Optional.empty(), Optional.empty(), Optional.empty());
    }

    public boolean allowsUnsafeInlineStyle() {
        return this.policy_.allowsInlineStyle(Optional.empty(), Optional.empty());
    }

    public boolean allowsConnection(final URLWithScheme url) {
        return this.policy_.allowsConnection(Optional.of(url), Optional.of(this.origin_));
    }

    public boolean allowsNavigation(final URLWithScheme url) {
        return this.policy_.allowsNavigation(Optional.of(url),
                            Optional.empty(), Optional.empty(), Optional.of(this.origin_));
    }

    public boolean allowsFrameAncestor(final URLWithScheme url) {
        return this.policy_.allowsFrameAncestor(Optional.of(url), Optional.of(this.origin_));
    }

    public boolean allowsFormAction(final URLWithScheme url) {
        return this.policy_.allowsFormAction(Optional.of(url),
                            Optional.empty(), Optional.empty(), Optional.of(this.origin_));
    }
}
