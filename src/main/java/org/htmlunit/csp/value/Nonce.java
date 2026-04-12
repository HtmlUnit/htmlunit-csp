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

import org.htmlunit.csp.Utils;

/**
 * Represents a CSP nonce-source value, e.g. {@code 'nonce-abc123...'}.
 * <p>
 * A nonce-source consists of the keyword prefix {@code nonce-} followed by a
 * Base64-encoded value, all enclosed in single quotes. The prefix is parsed
 * case-insensitively, but the Base64 nonce value itself is case-sensitive.
 * </p>
 *
 * @param base64ValuePart the Base64-encoded nonce value (case-sensitive)
 * @see <a href="https://w3c.github.io/webappsec-csp/#grammardef-nonce-source">
 *      nonce-source grammar</a>
 */
public record Nonce(String base64ValuePart) {

    /**
     * Parses a nonce-source from its CSP string representation.
     * <p>
     * The input must be a single-quoted string of the form {@code 'nonce-<base64>'}.
     * The prefix is matched case-insensitively; the Base64 portion is preserved as-is.
     * </p>
     *
     * @param value the CSP nonce-source token (e.g. {@code 'nonce-abc123...'})
     * @return an {@link Optional} containing the parsed {@link Nonce},
     *         or empty if the value does not match the nonce-source grammar
     */
    public static Optional<Nonce> parseNonce(final String value) {
        final String lowercaseValue = value.toLowerCase(Locale.ROOT);
        if (lowercaseValue.startsWith("'nonce-") && lowercaseValue.endsWith("'")) {
            final String nonce = value.substring(7, value.length() - 1);
            if (Utils.IS_BASE64_VALUE.test(nonce)) {
                // Note that nonces _are_ case-sensitive, even though the grammar is not
                return Optional.of(new Nonce(nonce));
            }
        }
        return Optional.empty();
    }

    /**
     * Returns the CSP string representation of this nonce-source,
     * e.g. {@code 'nonce-abc123...'}.
     *
     * @return the single-quoted nonce-source string
     */
    @Override
    public String toString() {
        return "'nonce-" + base64ValuePart + "'";
    }
}
