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

import org.htmlunit.csp.Directive;
import org.htmlunit.csp.Policy;
import java.util.List;

/**
 * Directive implementation for `require-trusted-types-for`.
 */
public class RequireTrustedTypesForDirective extends Directive {

    public RequireTrustedTypesForDirective(final List<String> values, final DirectiveErrorConsumer errors) {
        super(values);
        if (!values.isEmpty()) {
            for (int i = 0; i < values.size(); i++) {
                String value = values.get(i);
                if (!"script".equalsIgnoreCase(value)) {
                    errors.add(Policy.Severity.Error, "`require-trusted-types-for` only accepts 'script' as a value.", i);
                }
            }
        }
    }
}