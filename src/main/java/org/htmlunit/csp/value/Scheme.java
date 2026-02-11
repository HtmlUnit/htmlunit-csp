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

public record Scheme(String value) {

    public static Optional<Scheme> parseScheme(final String value) {
        if (value.matches("^" + Constants.SCHEME_PART + ":$")) {
            // https://tools.ietf.org/html/rfc3986#section-3.1
            // "Although schemes are case-insensitive, the canonical form is lowercase"
            return Optional.of(new Scheme(value.substring(0, value.length() - 1).toLowerCase(Locale.ROOT)));
        }
        return Optional.empty();
    }

    @Override
    public String toString() {
        return value + ":";
    }
}
