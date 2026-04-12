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
package org.htmlunit.csp.url;

import java.util.Optional;
import java.util.regex.Matcher;

import org.htmlunit.csp.Constants;

/**
 * Represents an opaque (non-hierarchical) URL that has a scheme and an opaque value
 * but no host or port, e.g. {@code data:text/html,...}, {@code blob:...}, or
 * {@code javascript:alert(1)}.
 * <p>
 * In the URL Standard these are URLs whose scheme is not a
 * <a href="https://url.spec.whatwg.org/#special-scheme">special scheme</a>.
 * The host and port are always {@code null}; the "path" holds the opaque data
 * after the scheme and colon.
 * </p>
 *
 * @see <a href="https://url.spec.whatwg.org/#example-url-components">
 *      URL Standard — URL components</a>
 */
public class GUID extends URLWithScheme {

    /**
     * Constructs a GUID (opaque URL) with the given scheme and opaque value.
     * <p>
     * The host is set to {@code null} and the port is set to {@code null}.
     * The opaque value is stored as the "path" component.
     * </p>
     *
     * @param scheme the URL scheme (e.g. {@code "javascript"}, {@code "data"},
     *        {@code "blob"}); will be lowercased
     * @param value the opaque data after the scheme colon
     *        (e.g. {@code "alert(1)"} for {@code javascript:alert(1)})
     */
    // See https://url.spec.whatwg.org/#example-url-components
    public GUID(final String scheme, final String value) {
        super(scheme, null, null, value);
    }

    /**
     * Parses an opaque URL from its string representation.
     * <p>
     * The input must begin with a valid scheme followed by a colon
     * (e.g. {@code "data:text/html,..."}). Everything after the colon
     * is stored as the opaque value.
     * </p>
     *
     * @param value the URL string to parse
     * @return an {@link Optional} containing the parsed {@link GUID},
     *         or empty if the value does not begin with a valid scheme
     */
    public static Optional<GUID> parseGUID(final String value) {
        final Matcher matcher = Constants.SCHEME_PATTERN.matcher(value);
        if (!matcher.find()) {
            return Optional.empty();
        }
        String scheme = matcher.group("scheme");
        scheme = scheme.substring(0, scheme.length() - 1);  // + 1 for the trailing ":"
        return Optional.of(new GUID(scheme, value.substring(scheme.length() + 1)));
    }
}
