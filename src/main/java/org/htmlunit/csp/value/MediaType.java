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
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;

import org.htmlunit.csp.Constants;

public final class MediaType {
    private final String type_;
    private final String subtype_;

    private MediaType(final String type, final String subtype) {
        type_ = type;
        subtype_ = subtype;
    }

    public String getType() {
        return type_;
    }

    public String getSubtype() {
        return subtype_;
    }

    public static Optional<MediaType> parseMediaType(final String value) {
        final Matcher matcher = Constants.MEDIA_TYPE_PATTERN.matcher(value);
        if (matcher.find()) {
            // plugin type matching is ASCII case-insensitive
            // https://w3c.github.io/webappsec-csp/#plugin-types-post-request-check
            final String type = matcher.group("type").toLowerCase(Locale.ROOT);
            final String subtype = matcher.group("subtype").toLowerCase(Locale.ROOT);
            return Optional.of(new MediaType(type, subtype));
        }
        return Optional.empty();
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        final MediaType mediaType = (MediaType) o;
        return type_.equals(mediaType.type_) && subtype_.equals(mediaType.subtype_);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type_, subtype_);
    }

    @Override
    public String toString() {
        return type_ + "/" + subtype_;
    }
}
