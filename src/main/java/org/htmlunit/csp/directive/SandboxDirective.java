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
package org.htmlunit.csp.directive;

import java.util.List;
import java.util.Locale;

import org.htmlunit.csp.Directive;
import org.htmlunit.csp.Policy;

/**
 * Represents the {@code sandbox} CSP directive.
 * <p>
 * The {@code sandbox} directive applies restrictions to the protected resource
 * similar to the {@code <iframe sandbox>} attribute. When present with no keywords,
 * the strictest sandbox is applied. Individual restrictions can be lifted by
 * including the corresponding {@code allow-*} keyword.
 * </p>
 *
 * @see <a href="https://w3c.github.io/webappsec-csp/#directive-sandbox">
 *      sandbox directive</a>
 * @see <a href="https://html.spec.whatwg.org/multipage/iframe-embed-object.html#attr-iframe-sandbox">
 *      HTML sandbox attribute</a>
 */
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

    /**
     * Parses a {@code sandbox} directive from the given list of keyword values.
     * <p>
     * Each token is matched case-insensitively against the known sandbox keywords.
     * Duplicates and unrecognised keywords are reported through the supplied
     * {@code errors} consumer.
     * </p>
     *
     * @param values the raw string values (sandbox keywords) for this directive
     * @param errors consumer that receives parsing errors and warnings
     */
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

    /**
     * Returns whether the {@code allow-downloads} sandbox keyword is present.
     *
     * @return {@code true} if downloads are allowed
     */
    public boolean allowDownloads() {
        return allowDownloads_;
    }

    /**
     * Returns whether the {@code allow-forms} sandbox keyword is present.
     *
     * @return {@code true} if form submission is allowed
     */
    public boolean allowForms() {
        return allowForms_;
    }

    /**
     * Returns whether the {@code allow-modals} sandbox keyword is present.
     *
     * @return {@code true} if modal dialogs (e.g. {@code alert()}) are allowed
     */
    public boolean allowModals() {
        return allowModals_;
    }

    /**
     * Returns whether the {@code allow-orientation-lock} sandbox keyword is present.
     *
     * @return {@code true} if screen orientation locking is allowed
     */
    public boolean allowOrientationLock() {
        return allowOrientationLock_;
    }

    /**
     * Returns whether the {@code allow-pointer-lock} sandbox keyword is present.
     *
     * @return {@code true} if the Pointer Lock API is allowed
     */
    public boolean allowPointerLock() {
        return allowPointerLock_;
    }

    /**
     * Returns whether the {@code allow-popups} sandbox keyword is present.
     *
     * @return {@code true} if popups (e.g. {@code window.open()}, {@code target="_blank"}) are allowed
     */
    public boolean allowPopups() {
        return allowPopups_;
    }

    /**
     * Returns whether the {@code allow-popups-to-escape-sandbox} sandbox keyword is present.
     *
     * @return {@code true} if popups are allowed to open without inheriting the sandbox
     */
    public boolean allowPopupsToEscapeSandbox() {
        return allowPopupsToEscapeSandbox_;
    }

    /**
     * Returns whether the {@code allow-presentation} sandbox keyword is present.
     *
     * @return {@code true} if the Presentation API is allowed
     */
    public boolean allowPresentation() {
        return allowPresentation_;
    }

    /**
     * Returns whether the {@code allow-same-origin} sandbox keyword is present.
     *
     * @return {@code true} if the content is treated as being from its normal origin
     */
    public boolean allowSameOrigin() {
        return allowSameOrigin_;
    }

    /**
     * Returns whether the {@code allow-scripts} sandbox keyword is present.
     *
     * @return {@code true} if script execution is allowed
     */
    public boolean allowScripts() {
        return allowScripts_;
    }

    /**
     * Returns whether the {@code allow-storage-access-by-user-activation} sandbox keyword is present.
     *
     * @return {@code true} if the Storage Access API is allowed with user activation
     */
    public boolean allowStorageAccessByUserActivation() {
        return allowStorageAccessByUserActivation_;
    }

    /**
     * Returns whether the {@code allow-top-navigation} sandbox keyword is present.
     *
     * @return {@code true} if navigation of the top-level browsing context is allowed
     */
    public boolean allowTopNavigation() {
        return allowTopNavigation_;
    }

    /**
     * Returns whether the {@code allow-top-navigation-by-user-activation} sandbox keyword is present.
     *
     * @return {@code true} if top-level navigation is allowed only with user activation
     */
    public boolean allowTopNavigationByUserActivation() {
        return allowTopNavigationByUserActivation_;
    }
}
