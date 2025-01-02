/*
 * Copyright (c) 2023-2025 Ronald Brill.
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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.htmlunit.csp.Directive;
import org.htmlunit.csp.Policy;

public class ReportUriDirective extends Directive {
    private final List<String> uris_ = new ArrayList<>();

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

    public List<String> getUris() {
        return Collections.unmodifiableList(uris_);
    }
}
