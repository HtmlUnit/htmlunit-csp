/*
 * Copyright (c) 2023-2024 Ronald Brill.
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

import org.htmlunit.csp.Constants;

public final class Scheme {
    private final String value_;

    private Scheme(final String value) {
        value_ = value;
    }

    public static Optional<Scheme> parseScheme(final String value) {
        if (value.matches("^" + Constants.SCHEME_PART + ":$")) {
            // https://tools.ietf.org/html/rfc3986#section-3.1
            // "Although schemes are case-insensitive, the canonical form is lowercase"
            return Optional.of(new Scheme(value.substring(0, value.length() - 1).toLowerCase(Locale.ROOT)));
        }
        return Optional.empty();
    }

    public String getValue() {
        return value_;
    }

    @Override
    public String toString() {
        return value_ + ":";
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final Scheme scheme = (Scheme) o;
        return value_.equals(scheme.value_);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value_);
    }
}
