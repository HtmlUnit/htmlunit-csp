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
 * Represents a CSP hash-source value, e.g. {@code 'sha256-abc123...'}.
 * <p>
 * A hash-source pairs a hash {@link Algorithm} with a Base64-encoded digest value.
 * The algorithm prefix ({@code sha256}, {@code sha384}, {@code sha512}) is parsed
 * case-insensitively, but the Base64 digest itself is case-sensitive.
 * </p>
 *
 * @param algorithm the hash algorithm (SHA-256, SHA-384, or SHA-512)
 * @param base64ValuePart the Base64-encoded hash value (case-sensitive)
 * @see <a href="https://w3c.github.io/webappsec-csp/#grammardef-hash-source">
 *      hash-source grammar</a>
 */
public record Hash(Algorithm algorithm, String base64ValuePart) {

    /**
     * Returns the hash algorithm.
     *
     * @return the {@link Algorithm} for this hash-source
     */
    public Algorithm getAlgorithm() {
        return algorithm;
    }

    /**
     * Returns the Base64-encoded hash value.
     * <p>
     * This value is case-sensitive and may use standard Base64 or Base64url encoding.
     * </p>
     *
     * @return the Base64-encoded digest string
     */
    public String getBase64ValuePart() {
        return base64ValuePart;
    }

    /**
     * Parses a hash-source from its CSP string representation.
     * <p>
     * The input must be a single-quoted string of the form
     * {@code 'sha256-<base64>'}, {@code 'sha384-<base64>'}, or
     * {@code 'sha512-<base64>'}. The algorithm prefix is matched
     * case-insensitively; the Base64 portion is preserved as-is.
     * </p>
     *
     * @param value the CSP hash-source token (e.g. {@code 'sha256-abc123...'})
     * @return an {@link Optional} containing the parsed {@link Hash},
     *         or empty if the value does not match the hash-source grammar
     */
    public static Optional<Hash> parseHash(final String value) {
        final String lowercaseValue = value.toLowerCase(Locale.ROOT);
        final Algorithm algorithm;
        if (lowercaseValue.startsWith("'sha") && lowercaseValue.endsWith("'")) {
            switch (lowercaseValue.substring(4, 7)) {
                case "256":
                    algorithm = Algorithm.SHA256;
                    break;
                case "384":
                    algorithm = Algorithm.SHA384;
                    break;
                case "512":
                    algorithm = Algorithm.SHA512;
                    break;
                default:
                    return Optional.empty();
            }

            final String hash = value.substring(8, value.length() - 1);
            if (Utils.IS_BASE64_VALUE.test(hash)) {
                // Note that hashes _are_ case-sensitive, even though the grammar is not
                return Optional.of(new Hash(algorithm, hash));
            }
        }
        return Optional.empty();
    }

    /**
     * Returns the CSP string representation of this hash-source,
     * e.g. {@code 'sha256-abc123...'}.
     *
     * @return the single-quoted hash-source string
     */
    @Override
    public String toString() {
        return "'" + algorithm.toString() + "-" + base64ValuePart + "'";
    }

    /**
     * Enumerates the hash algorithms supported by CSP hash-sources.
     * <p>
     * Each constant carries the lowercase algorithm name used in the CSP grammar
     * and the expected Base64-encoded output length for validation purposes.
     * </p>
     */
    public enum Algorithm {
        /**
         * SHA-256 algorithm ({@code sha256}), producing a 44-character Base64 digest.
         */
        SHA256("sha256", 44),

        /**
         * SHA-384 algorithm ({@code sha384}), producing a 64-character Base64 digest.
         */
        SHA384("sha384", 64),

        /**
         * SHA-512 algorithm ({@code sha512}), producing an 88-character Base64 digest.
         */
        SHA512("sha512", 88);

        private final String value_;
        private final int length_;

        Algorithm(final String value, final int length) {
            value_ = value;
            length_ = length;
        }

        /**
         * Returns the expected length of the Base64-encoded digest for this algorithm.
         *
         * @return the expected Base64 string length
         */
        public int getLength() {
            return length_;
        }

        /**
         * Returns the lowercase algorithm name as used in the CSP grammar
         * (e.g. {@code "sha256"}).
         *
         * @return the algorithm name string
         */
        @Override
        public String toString() {
            return value_;
        }
    }
}
