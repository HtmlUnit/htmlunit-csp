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
package org.htmlunit.csp.directive;

import java.util.List;
import java.util.Locale;

import org.htmlunit.csp.Directive;
import org.htmlunit.csp.Policy;

public class SandboxDirective extends Directive {
    private static final String ALLOW_DOWNLOADS = "allow-downloads";
    private boolean allowDownloads_ = false;
    private boolean allowForms_ = false;
    private boolean allowModals_ = false;
    private boolean allowOrientationLock_ = false;
    private boolean allowPointerLock_ = false;
    private boolean allowPopups_ = false;
    private boolean allowPopupsToEscapeSandbox_ = false;
    private boolean allowPresentation_ = false;
    private boolean allowSameOrigin_ = false;
    private boolean allowScripts_ = false;
    private boolean allowStorageAccessByUserActivation_ = false;
    private boolean allowTopNavigation_ = false;
    private boolean allowTopNavigationByUserActivation_ = false;

    public SandboxDirective(final List<String> values, final DirectiveErrorConsumer errors) {
        super(values);

        int index = 0;
        for (final String token : values) {
            // HTML attribute keywords are ascii-case-insensitive:
            // https://html.spec.whatwg.org/multipage/common-microsyntaxes.html#keywords-and-enumerated-attributes
            final String lowcaseToken = token.toLowerCase(Locale.ENGLISH);
            switch (lowcaseToken) {
                case ALLOW_DOWNLOADS:
                    if (!this.allowDownloads_) {
                        this.allowDownloads_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-downloads", index);
                    }
                    break;
                case "allow-forms":
                    if (!this.allowForms_) {
                        this.allowForms_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-forms", index);
                    }
                    break;
                case "allow-modals":
                    if (!this.allowModals_) {
                        this.allowModals_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-modals", index);
                    }
                    break;
                case "allow-orientation-lock":
                    if (!this.allowOrientationLock_) {
                        this.allowOrientationLock_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-orientation-lock", index);
                    }
                    break;
                case "allow-pointer-lock":
                    if (!this.allowPointerLock_) {
                        this.allowPointerLock_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-pointer-lock", index);
                    }
                    break;
                case "allow-popups":
                    if (!this.allowPopups_) {
                        this.allowPopups_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-popups", index);
                    }
                    break;
                case "allow-popups-to-escape-sandbox":
                    if (!this.allowPopupsToEscapeSandbox_) {
                        this.allowPopupsToEscapeSandbox_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning,
                                "Duplicate sandbox keyword allow-popups-to-escape-sandbox", index);
                    }
                    break;
                case "allow-presentation":
                    if (!this.allowPresentation_) {
                        this.allowPresentation_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-presentation", index);
                    }
                    break;
                case "allow-same-origin":
                    if (!this.allowSameOrigin_) {
                        this.allowSameOrigin_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-same-origin", index);
                    }
                    break;
                case "allow-scripts":
                    if (!this.allowScripts_) {
                        this.allowScripts_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-scripts", index);
                    }
                    break;
                case "allow-storage-access-by-user-activation":
                    if (!this.allowStorageAccessByUserActivation_) {
                        this.allowStorageAccessByUserActivation_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning,
                                "Duplicate sandbox keyword allow-storage-access-by-user-activation", index);
                    }
                    break;
                case "allow-top-navigation":
                    if (!this.allowTopNavigation_) {
                        this.allowTopNavigation_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-top-navigation", index);
                    }
                    break;
                case "allow-top-navigation-by-user-activation":
                    if (!this.allowTopNavigationByUserActivation_) {
                        this.allowTopNavigationByUserActivation_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning,
                                "Duplicate sandbox keyword allow-top-navigation-by-user-activation", index);
                    }
                    break;
                default:
                    if (token.startsWith("'")) {
                        errors.add(Policy.Severity.Error,
                                "Unrecognized sandbox keyword "
                                        + token + " - note that sandbox keywords do not have \"'\"s", index);
                    }
                    else {
                        errors.add(Policy.Severity.Error, "Unrecognized sandbox keyword " + token, index);
                    }
            }
            ++index;
        }
    }

    public boolean allowDownloads() {
        return this.allowDownloads_;
    }

    public boolean allowForms() {
        return this.allowForms_;
    }

    public boolean allowModals() {
        return this.allowModals_;
    }

    public boolean allowOrientationLock() {
        return this.allowOrientationLock_;
    }

    public boolean allowPointerLock() {
        return this.allowPointerLock_;
    }

    public boolean allowPopups() {
        return this.allowPopups_;
    }

    public boolean allowPopupsToEscapeSandbox() {
        return this.allowPopupsToEscapeSandbox_;
    }

    public boolean allowPresentation() {
        return this.allowPresentation_;
    }

    public boolean allowSameOrigin() {
        return this.allowSameOrigin_;
    }

    public boolean allowScripts() {
        return this.allowScripts_;
    }

    public boolean allowStorageAccessByUserActivation() {
        return this.allowStorageAccessByUserActivation_;
    }

    public boolean allowTopNavigation() {
        return this.allowTopNavigation_;
    }

    public boolean allowTopNavigationByUserActivation() {
        return this.allowTopNavigationByUserActivation_;
    }
}
