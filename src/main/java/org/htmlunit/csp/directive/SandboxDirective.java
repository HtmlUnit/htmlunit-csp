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
            final String lowcaseToken = token.toLowerCase(Locale.ROOT);
            switch (lowcaseToken) {
                case ALLOW_DOWNLOADS:
                    if (!allowDownloads_) {
                        allowDownloads_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-downloads", index);
                    }
                    break;
                case "allow-forms":
                    if (!allowForms_) {
                        allowForms_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-forms", index);
                    }
                    break;
                case "allow-modals":
                    if (!allowModals_) {
                        allowModals_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-modals", index);
                    }
                    break;
                case "allow-orientation-lock":
                    if (!allowOrientationLock_) {
                        allowOrientationLock_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-orientation-lock", index);
                    }
                    break;
                case "allow-pointer-lock":
                    if (!allowPointerLock_) {
                        allowPointerLock_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-pointer-lock", index);
                    }
                    break;
                case "allow-popups":
                    if (!allowPopups_) {
                        allowPopups_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-popups", index);
                    }
                    break;
                case "allow-popups-to-escape-sandbox":
                    if (!allowPopupsToEscapeSandbox_) {
                        allowPopupsToEscapeSandbox_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning,
                                "Duplicate sandbox keyword allow-popups-to-escape-sandbox", index);
                    }
                    break;
                case "allow-presentation":
                    if (!allowPresentation_) {
                        allowPresentation_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-presentation", index);
                    }
                    break;
                case "allow-same-origin":
                    if (!allowSameOrigin_) {
                        allowSameOrigin_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-same-origin", index);
                    }
                    break;
                case "allow-scripts":
                    if (!allowScripts_) {
                        allowScripts_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-scripts", index);
                    }
                    break;
                case "allow-storage-access-by-user-activation":
                    if (!allowStorageAccessByUserActivation_) {
                        allowStorageAccessByUserActivation_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning,
                                "Duplicate sandbox keyword allow-storage-access-by-user-activation", index);
                    }
                    break;
                case "allow-top-navigation":
                    if (!allowTopNavigation_) {
                        allowTopNavigation_ = true;
                    }
                    else {
                        errors.add(Policy.Severity.Warning, "Duplicate sandbox keyword allow-top-navigation", index);
                    }
                    break;
                case "allow-top-navigation-by-user-activation":
                    if (!allowTopNavigationByUserActivation_) {
                        allowTopNavigationByUserActivation_ = true;
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
