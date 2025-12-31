/*
 * Copyright (c) 2023-2025 Ronald Brill.
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
package org.htmlunit.csp.directive;

import java.util.List;
import java.util.Locale;

import org.htmlunit.csp.Directive;
import org.htmlunit.csp.Policy;

public class SandboxDirective extends Directive {
    private static final String ALLOW_DOWNLOADS = "allow-downloads";
    private boolean allowDownloads_;
    private boolean allowForms_;
    private boolean allowModals_;
    private boolean allowOrientationLock_;
    private boolean allowPointerLock_;
    private boolean allowPopups_;
    private boolean allowPopupsToEscapeSandbox_;
    private boolean allowPresentation_;
    private boolean allowSameOrigin_;
    private boolean allowScripts_;
    private boolean allowStorageAccessByUserActivation_;
    private boolean allowTopNavigation_;
    private boolean allowTopNavigationByUserActivation_;

    public SandboxDirective(final List<String> values, final DirectiveErrorConsumer errors) {
        super(values);

        int index = 0;
        for (final String token : values) {
            // HTML attribute keywords are ascii-case-insensitive:
            // https://html.spec.whatwg.org/multipage/common-microsyntaxes.html#keywords-and-enumerated-attributes
            final String lowercaseToken = token.toLowerCase(Locale.ROOT);
            switch (lowercaseToken) {
                case ALLOW_DOWNLOADS:
                    if (allowDownloads_) {
                        errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-downloads", index);
                    }
                    else {
                        allowDownloads_ = true;
                    }
                    break;
                case "allow-forms":
                    if (allowForms_) {
                        errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-forms", index);
                    }
                    else {
                        allowForms_ = true;
                    }
                    break;
                case "allow-modals":
                    if (allowModals_) {
                        errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-modals", index);
                    }
                    else {
                        allowModals_ = true;
                    }
                    break;
                case "allow-orientation-lock":
                    if (allowOrientationLock_) {
                        errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-orientation-lock", index);
                    }
                    else {
                        allowOrientationLock_ = true;
                    }
                    break;
                case "allow-pointer-lock":
                    if (allowPointerLock_) {
                        errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-pointer-lock", index);
                    }
                    else {
                        allowPointerLock_ = true;
                    }
                    break;
                case "allow-popups":
                    if (allowPopups_) {
                        errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-popups", index);
                    }
                    else {
                        allowPopups_ = true;
                    }
                    break;
                case "allow-popups-to-escape-sandbox":
                    if (allowPopupsToEscapeSandbox_) {
                        errors.add(Policy.Severity.Warning,
                                "Duplicate sandbox keyword allow-popups-to-escape-sandbox", index);
                    }
                    else {
                        allowPopupsToEscapeSandbox_ = true;
                    }
                    break;
                case "allow-presentation":
                    if (allowPresentation_) {
                        errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-presentation", index);
                    }
                    else {
                        allowPresentation_ = true;
                    }
                    break;
                case "allow-same-origin":
                    if (allowSameOrigin_) {
                        errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-same-origin", index);
                    }
                    else {
                        allowSameOrigin_ = true;
                    }
                    break;
                case "allow-scripts":
                    if (allowScripts_) {
                        errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-scripts", index);
                    }
                    else {
                        allowScripts_ = true;
                    }
                    break;
                case "allow-storage-access-by-user-activation":
                    if (allowStorageAccessByUserActivation_) {
                        errors.add(Policy.Severity.Warning,
                                "Duplicate sandbox keyword allow-storage-access-by-user-activation", index);
                    }
                    else {
                        allowStorageAccessByUserActivation_ = true;
                    }
                    break;
                case "allow-top-navigation":
                    if (allowTopNavigation_) {
                        errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-top-navigation", index);
                    }
                    else {
                        allowTopNavigation_ = true;
                    }
                    break;
                case "allow-top-navigation-by-user-activation":
                    if (allowTopNavigationByUserActivation_) {
                        errors.add(Policy.Severity.Warning,
                                "Duplicate sandbox keyword allow-top-navigation-by-user-activation", index);
                    }
                    else {
                        allowTopNavigationByUserActivation_ = true;
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
        return allowDownloads_;
    }

    public boolean allowForms() {
        return allowForms_;
    }

    public boolean allowModals() {
        return allowModals_;
    }

    public boolean allowOrientationLock() {
        return allowOrientationLock_;
    }

    public boolean allowPointerLock() {
        return allowPointerLock_;
    }

    public boolean allowPopups() {
        return allowPopups_;
    }

    public boolean allowPopupsToEscapeSandbox() {
        return allowPopupsToEscapeSandbox_;
    }

    public boolean allowPresentation() {
        return allowPresentation_;
    }

    public boolean allowSameOrigin() {
        return allowSameOrigin_;
    }

    public boolean allowScripts() {
        return allowScripts_;
    }

    public boolean allowStorageAccessByUserActivation() {
        return allowStorageAccessByUserActivation_;
    }

    public boolean allowTopNavigation() {
        return allowTopNavigation_;
    }

    public boolean allowTopNavigationByUserActivation() {
        return allowTopNavigationByUserActivation_;
    }
}
