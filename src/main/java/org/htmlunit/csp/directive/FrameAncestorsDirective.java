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

import org.htmlunit.csp.Policy;

public class FrameAncestorsDirective extends HostSourceDirective {
    public FrameAncestorsDirective(final List<String> values, final DirectiveErrorConsumer errors) {
        super(values);

        int index = 0;
        for (final String token : values) {
            final String lowcaseToken = token.toLowerCase(Locale.ROOT);
            addHostOrSchemeDuringConstruction(token, lowcaseToken, "ancestor-source", index, errors);
            index++;
        }

        if (getNone() != null && values.size() > 1) {
            errors.add(Policy.Severity.Error, "'none' must not be combined with any other ancestor-source", index);
        }

        if (values.isEmpty()) {
            errors.add(Policy.Severity.Error, "Ancestor-source lists cannot be empty (use 'none' instead)", -1);
        }
    }
}
