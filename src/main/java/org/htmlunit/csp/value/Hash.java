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
package org.htmlunit.csp.value;

import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

import org.htmlunit.csp.Utils;

public final class Hash {

    private final Algorithm algorithm_;
    private final String base64ValuePart_;

    private Hash(final Algorithm algorithm, final String base64ValuePart) {
        algorithm_ = algorithm;
        base64ValuePart_ = base64ValuePart;
    }

    public Algorithm getAlgorithm() {
        return algorithm_;
    }

    public String getBase64ValuePart() {
        return base64ValuePart_;
    }

    public static Optional<Hash> parseHash(final String value) {
        final String lowcaseValue = value.toLowerCase(Locale.ENGLISH);
        final Algorithm algorithm;
        if (lowcaseValue.startsWith("'sha") && lowcaseValue.endsWith("'")) {
            switch (lowcaseValue.substring(4, 7)) {
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
        return "'" + algorithm_.toString() + "-" + base64ValuePart_ + "'";
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final Hash hash = (Hash) o;
        return algorithm_ == hash.algorithm_ && base64ValuePart_.equals(hash.base64ValuePart_);
    }

    @Override
    public int hashCode() {
        return Objects.hash(algorithm_, base64ValuePart_);
    }

    public enum Algorithm {
        /** SHA256("sha256", 44). */
        SHA256("sha256", 44),

        /** SHA384("sha384", 64). */
        SHA384("sha384", 64),

        /** SHA512("sha512", 88). */
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
