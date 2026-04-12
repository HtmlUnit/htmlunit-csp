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

import org.htmlunit.csp.Policy;

/**
 * Represents the {@code frame-ancestors} CSP directive.
 * <p>
 * The {@code frame-ancestors} directive restricts which URLs can embed the
 * protected resource using {@code <frame>}, {@code <iframe>}, {@code <object>},
 * {@code <embed>}, or {@code <applet>}. Unlike other directives, it uses an
 * ancestor-source list (host-sources and scheme-sources only — no nonces or hashes)
 * and only matches against origins (paths are always ignored).
 * </p>
 *
 * @see <a href="https://w3c.github.io/webappsec-csp/#directive-frame-ancestors">
 *      frame-ancestors directive</a>
 */
public class FrameAncestorsDirective extends HostSourceDirective {

    /**
     * Parses a {@code frame-ancestors} directive from the given list of values.
     * <p>
     * Each token is classified as {@code 'none'}, {@code 'self'}, {@code *},
     * a scheme-source, or a host-source. Errors and warnings (duplicates,
     * unrecognised tokens, combining {@code 'none'} with other values, empty lists)
     * are reported through the supplied {@code errors} consumer.
     * </p>
     *
     * @param values the raw string values for this directive
     * @param errors consumer that receives parsing errors and warnings
     */
    public FrameAncestorsDirective(final List<String> values, final DirectiveErrorConsumer errors) {
        super(values);

        int index = 0;
        for (final String token : values) {
            final String lowercaseToken = token.toLowerCase(Locale.ROOT);
            addHostOrSchemeDuringConstruction(token, lowercaseToken, "ancestor-source", index, errors);
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
