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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.htmlunit.csp.Directive;
import org.htmlunit.csp.Policy;

/**
 * Represents the (deprecated) {@code report-uri} CSP directive.
 * <p>
 * The {@code report-uri} directive specifies one or more URIs to which the
 * user agent sends violation reports. It has been deprecated in favour of the
 * {@code report-to} directive.
 * </p>
 * <p>
 * Duplicate URIs are permitted because they have actual semantic meaning:
 * the report will be sent to the same endpoint multiple times (once per
 * occurrence), per specification.
 * </p>
 *
 * @see <a href="https://w3c.github.io/webappsec-csp/#directive-report-uri">
 *      report-uri directive</a>
 */
public class ReportUriDirective extends Directive {
    private final List<String> uris_ = new ArrayList<>();

    /**
     * Parses a {@code report-uri} directive from the given list of URI values.
     * <p>
     * At least one URI is required. Duplicate URIs produce an informational
     * message (not an error) since they are semantically valid.
     * </p>
     *
     * @param values the raw string values (URIs) for this directive
     * @param errors consumer that receives parsing errors and warnings
     */
    public ReportUriDirective(final List<String> values, final DirectiveErrorConsumer errors) {
        super(values);
        int index = 0;
        for (final String value : values) {
            addUri(value, index, errors);
            index++;
        }

        if (getValues().isEmpty()) {
            errors.add(Policy.Severity.Error, "The report-uri value requires at least one value", -1);
        }
    }

    private void addUri(final String uri, final int index, final DirectiveErrorConsumer errors) {
        // TODO actual parsing per https://tools.ietf.org/html/rfc3986#section-4.1
        // It's awful, though: 'urn:example:animal:ferret:nose' is a valid URI
        if (uris_.contains(uri)) {
            // NB: we don't prevent you from having duplicates, because that
            // has actual semantic meaning - it will get each report twice (per spec)
            errors.add(Policy.Severity.Info,
                    "Duplicate report-to URI; are you sure you intend to get multiple copies of each report?",
                    index);
        }
        uris_.add(uri);
    }

    /**
     * Returns an unmodifiable list of the report URIs specified in this directive.
     * <p>
     * The list may contain duplicates, which have semantic meaning (the report
     * is sent once per URI occurrence).
     * </p>
     *
     * @return the list of report URI strings
     */
    public List<String> getUris() {
        return Collections.unmodifiableList(uris_);
    }
}
