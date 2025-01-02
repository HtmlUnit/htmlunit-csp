/*
 * Copyright (c) 2023-2025 Ronald Brill.
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
package org.htmlunit.csp.url;

import java.util.Optional;
import java.util.regex.Matcher;

import org.htmlunit.csp.Constants;

public class GUID extends URLWithScheme {
    // See https://url.spec.whatwg.org/#example-url-components
    public GUID(final String scheme, final String value) {
        super(scheme, null, null, value);
    }

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
