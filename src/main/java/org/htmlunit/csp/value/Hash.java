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

public record Hash(Algorithm algorithm, String base64ValuePart) {

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    public String getBase64ValuePart() {
        return base64ValuePart;
    }

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

    @Override
    public String toString() {
        return "'" + algorithm.toString() + "-" + base64ValuePart + "'";
    }

    public enum Algorithm {
        /**
         * SHA256("sha256", 44).
         */
        SHA256("sha256", 44),

        /**
         * SHA384("sha384", 64).
         */
        SHA384("sha384", 64),

        /**
         * SHA512("sha512", 88).
         */
        SHA512("sha512", 88);

        private final String value_;
        private final int length_;

        Algorithm(final String value, final int length) {
            value_ = value;
            length_ = length;
        }

        public int getLength() {
            return length_;
        }

        @Override
        public String toString() {
            return value_;
        }
    }
}
