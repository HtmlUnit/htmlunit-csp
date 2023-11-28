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

import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;

import org.htmlunit.csp.Constants;

public final class RFC7230Token {
    private final String value_;

    private RFC7230Token(final String value) {
        this.value_ = value;
    }

    public String getValue() {
        return value_;
    }

    public static Optional<RFC7230Token> parseRFC7230Token(final String value) {
        final Matcher matcher = Constants.rfc7230TokenPattern.matcher(value);
        if (matcher.find()) {
            return Optional.of(new RFC7230Token(value));
        }
        else {
            return Optional.empty();
        }
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof RFC7230Token)) {
            return false;
        }
        final RFC7230Token that = (RFC7230Token) o;
        return value_.equals(that.value_);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value_);
    }

    @Override
    public String toString() {
        return this.value_;
    }
}
