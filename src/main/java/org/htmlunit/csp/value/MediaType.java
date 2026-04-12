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
import java.util.regex.Matcher;

import org.htmlunit.csp.Constants;

/**
 * Represents a media type (MIME type) value used by the (deprecated)
 * {@code plugin-types} CSP directive, e.g. {@code application/pdf}.
 * <p>
 * A media type consists of a type and a subtype separated by a forward slash.
 * Matching is ASCII case-insensitive per the
 * <a href="https://w3c.github.io/webappsec-csp/#plugin-types-post-request-check">
 * plugin-types post-request check</a>, so both parts are stored in lowercase.
 * </p>
 *
 * @param type the primary type in lowercase (e.g. {@code "application"})
 * @param subtype the subtype in lowercase (e.g. {@code "pdf"})
 */
public record MediaType(String type, String subtype) {

    /**
     * Parses a media type from its string representation.
     * <p>
     * The input must match the {@code type/subtype} grammar. Both parts
     * are lowercased for case-insensitive matching.
     * </p>
     *
     * @param value the media type string (e.g. {@code "application/pdf"})
     * @return an {@link Optional} containing the parsed {@link MediaType},
     *         or empty if the value does not match the media-type grammar
     */
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

    /**
     * Returns the media type in its canonical {@code type/subtype} form
     * (e.g. {@code "application/pdf"}).
     *
     * @return the media type string
     */
    @Override
    public String toString() {
        return type + "/" + subtype;
    }
}
