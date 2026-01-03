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

public record RFC7230Token(String value_) {

    public String getValue() {
        return value_;
    }

    public static Optional<RFC7230Token> parseRFC7230Token(final String value) {
        final Matcher matcher = Constants.rfc7230TokenPattern.matcher(value);
        if (matcher.find()) {
            return Optional.of(new RFC7230Token(value));
        }

        return Optional.empty();
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof RFC7230Token that)) {
            return false;
        }
        return value_.equals(that.value_);
    }

    @Override
    public String toString() {
        return value_;
    }
}
