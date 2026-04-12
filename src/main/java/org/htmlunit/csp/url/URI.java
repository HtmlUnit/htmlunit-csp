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

import java.util.Locale;
import java.util.Optional;
import java.util.regex.Matcher;

import org.htmlunit.csp.Constants;

/**
 * Represents a hierarchical URI with scheme, host, port, and path components.
 * <p>
 * This is the concrete {@link URLWithScheme} subclass used for standard URLs
 * such as {@code https://example.com:443/path}. For opaque/non-hierarchical URLs
 * (e.g. {@code data:} or {@code javascript:}), see {@link GUID}.
 * </p>
 * <p>
 * Instances can be created directly via the constructor or parsed from a string
 * using {@link #parseURI(String)}.
 * </p>
 */
public class URI extends URLWithScheme {

    /**
     * Constructs a hierarchical URI with the given components.
     *
     * @param scheme the URI scheme (e.g. {@code "https"}); will be lowercased
     * @param host the host name (e.g. {@code "example.com"}); will be lowercased
     * @param port the port number (use {@link #defaultPortForProtocol(String)} or
     *        {@link Constants#EMPTY_PORT} for unspecified ports)
     * @param path the path component (e.g. {@code "/scripts/app.js"});
     *        use an empty string if no path is present
     */
    public URI(final String scheme, final String host, final int port, final String path) {
        super(scheme, host, port, path);
    }

    /**
     * Parses a hierarchical URI from its string representation.
     * <p>
     * The input must contain a scheme (e.g. {@code "https://example.com/path"}).
     * If no port is specified, the {@linkplain #defaultPortForProtocol(String)
     * default port} for the scheme is used. If no path is specified, an empty
     * string is used. The host and scheme are lowercased.
     * </p>
     *
     * @param uri the URI string to parse
     * @return an {@link Optional} containing the parsed {@link URI},
     *         or empty if the string does not match the expected URI grammar
     *         or has no scheme
     */
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

    /**
     * Returns the default port number for the given protocol scheme.
     * <p>
     * Known default ports:
     * </p>
     * <table>
     *   <caption>Default ports by scheme</caption>
     *   <tr><th>Scheme</th><th>Port</th></tr>
     *   <tr><td>{@code ftp}</td><td>21</td></tr>
     *   <tr><td>{@code gopher}</td><td>70</td></tr>
     *   <tr><td>{@code http}, {@code ws}</td><td>80</td></tr>
     *   <tr><td>{@code https}, {@code wss}</td><td>443</td></tr>
     *   <tr><td>{@code file}</td><td>{@link Constants#EMPTY_PORT}</td></tr>
     * </table>
     * <p>
     * For unrecognised schemes, {@link Constants#EMPTY_PORT} is returned.
     * </p>
     *
     * @param scheme the protocol scheme in lowercase (e.g. {@code "https"})
     * @return the default port number, or {@link Constants#EMPTY_PORT} if the
     *         scheme has no default port
     * @see <a href="http://www.w3.org/TR/url/#default-port">URL Standard — default port</a>
     */
    // http://www.w3.org/TR/url/#default-port
    public static int defaultPortForProtocol(final String scheme) {
        // NB this should just only be called with lowercased schemes
        return switch (scheme) {
            case "ftp" -> 21;
            case "file" -> Constants.EMPTY_PORT;
            case "gopher" -> 70;
            case "http", "ws" -> 80;
            case "https", "wss" -> 443;
            default -> Constants.EMPTY_PORT;
        };
    }
}
