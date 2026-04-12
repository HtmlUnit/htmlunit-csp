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

import java.util.Optional;
import java.util.regex.Matcher;

import org.htmlunit.csp.Constants;

/**
 * Represents an RFC 7230 token value, used as the value of the
 * {@code report-to} CSP directive.
 * <p>
 * An RFC 7230 token is a sequence of one or more characters from the
 * {@code tchar} set defined in
 * <a href="https://tools.ietf.org/html/rfc7230#section-3.2.6">RFC 7230 §3.2.6</a>.
 * The value is preserved as-is (case-sensitive).
 * </p>
 *
 * @param value the token string
 * @see <a href="https://tools.ietf.org/html/rfc7230#section-3.2.6">RFC 7230 §3.2.6</a>
 */
public record RFC7230Token(String value) {

    /**
     * Parses an RFC 7230 token from the given string.
     * <p>
     * The input must consist entirely of valid {@code tchar} characters
     * as defined in RFC 7230.
     * </p>
     *
     * @param value the string to parse
     * @return an {@link Optional} containing the parsed {@link RFC7230Token},
     *         or empty if the value does not match the RFC 7230 token grammar
     */
    public static Optional<RFC7230Token> parseRFC7230Token(final String value) {
        final Matcher matcher = Constants.rfc7230TokenPattern.matcher(value);
        if (matcher.find()) {
            return Optional.of(new RFC7230Token(value));
        }

        return Optional.empty();
    }

    /**
     * Returns the token value as-is.
     *
     * @return the RFC 7230 token string
     */
    @Override
    public String toString() {
        return value;
    }
}
