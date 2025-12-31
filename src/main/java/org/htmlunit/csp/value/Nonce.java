/*
 * Copyright (c) 2023-2025 Ronald Brill.
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

public record Nonce(String base64ValuePart_) {

    public String getBase64ValuePart() {
        return base64ValuePart_;
    }

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

    @Override
    public String toString() {
        return "'nonce-" + base64ValuePart_ + "'";
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final Nonce nonce = (Nonce) o;
        return base64ValuePart_.equals(nonce.base64ValuePart_);
    }

}
