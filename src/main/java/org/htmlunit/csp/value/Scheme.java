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
package org.htmlunit.csp.value;

import java.util.Locale;
import java.util.Optional;

import org.htmlunit.csp.Constants;

/**
 * Represents a CSP scheme-source value, e.g. {@code https:} or {@code data:}.
 * <p>
 * A scheme-source is a URI scheme followed by a colon. Per
 * <a href="https://tools.ietf.org/html/rfc3986#section-3.1">RFC 3986 §3.1</a>,
 * schemes are case-insensitive, so the value is stored in its canonical
 * lowercase form.
 * </p>
 *
 * @param value the scheme name in lowercase, without the trailing colon
 *        (e.g. {@code "https"}, {@code "data"})
 * @see <a href="https://w3c.github.io/webappsec-csp/#grammardef-scheme-source">
 *      scheme-source grammar</a>
 */
public record Scheme(String value) {

    /**
     * Parses a scheme-source from its CSP string representation.
     * <p>
     * The input must match the scheme grammar followed by a colon
     * (e.g. {@code "https:"}). The scheme is lowercased per RFC 3986.
     * </p>
     *
     * @param value the CSP scheme-source token (e.g. {@code "https:"} or {@code "data:"})
     * @return an {@link Optional} containing the parsed {@link Scheme},
     *         or empty if the value does not match the scheme-source grammar
     */
    public static Optional<Scheme> parseScheme(final String value) {
        if (value.matches("^" + Constants.SCHEME_PART + ":$")) {
            // https://tools.ietf.org/html/rfc3986#section-3.1
            // "Although schemes are case-insensitive, the canonical form is lowercase"
            return Optional.of(new Scheme(value.substring(0, value.length() - 1).toLowerCase(Locale.ROOT)));
        }
        return Optional.empty();
    }

    /**
     * Returns the CSP string representation of this scheme-source
     * (the lowercase scheme name followed by a colon, e.g. {@code "https:"}).
     *
     * @return the scheme-source string
     */
    @Override
    public String toString() {
        return value + ":";
    }
}
