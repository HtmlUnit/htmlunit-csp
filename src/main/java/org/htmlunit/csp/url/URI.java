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
package org.htmlunit.csp.url;

import java.util.Locale;
import java.util.Optional;
import java.util.regex.Matcher;

import org.htmlunit.csp.Constants;

public class URI extends URLWithScheme {

    public URI(final String scheme, final String host, final int port, final String path) {
        super(scheme, host, port, path);
    }

    public static Optional<URI> parseURI(final String uri) {
        final Matcher matcher = Constants.HOST_SOURCE_PATTERN.matcher(uri);
        if (!matcher.find()) {
            return Optional.empty();
        }
        String scheme = matcher.group("scheme");
        if (scheme == null) {
            return Optional.empty();
        }
        scheme = scheme.substring(0, scheme.length() - 3);
        final String portString = matcher.group("port");
        final int port;
        if (portString == null) {
            port = URI.defaultPortForProtocol(scheme.toLowerCase(Locale.ROOT));
        }
        else {
            port = ":*".equals(portString) ? Constants.WILDCARD_PORT : Integer.parseInt(portString.substring(1));
        }
        final String host = matcher.group("host");
        String path = matcher.group("path");
        if (path == null) {
            path = "";
        }
        return Optional.of(new URI(scheme, host, port, path));
    }

    // http://www.w3.org/TR/url/#default-port
    public static int defaultPortForProtocol(final String scheme) {
        // NB this should just only be called with lowercased schemes
        return switch (scheme) {
            case "ftp" -> 21;
            case "file" -> Constants.EMPTY_PORT;
            case "gopher" -> 70;
            case "http" -> 80;
            case "https" -> 443;
            case "ws" -> 80;
            case "wss" -> 443;
            default -> Constants.EMPTY_PORT;
        };
    }
}
