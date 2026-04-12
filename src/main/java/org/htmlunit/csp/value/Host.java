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
import org.htmlunit.csp.url.URI;

/**
 * Represents a CSP host-source value, e.g. {@code https://example.com:443/path}.
 * <p>
 * A host-source consists of an optional scheme, a required host name
 * (which may use a leading wildcard like {@code *.example.com}), an optional
 * port (which may be a wildcard {@code *}), and an optional path.
 * The host portion is always lowercased during parsing per the CSP specification.
 * </p>
 *
 * @param scheme the scheme part (e.g. {@code "https"}), or {@code null} if not specified
 * @param host the host part, lowercased (e.g. {@code "example.com"} or {@code "*.cdn.example.com"})
 * @param port the port number, {@link Constants#EMPTY_PORT} if not specified,
 *        or {@link Constants#WILDCARD_PORT} if {@code :*}
 * @param path the path part (e.g. {@code "/scripts/"}), or {@code null} if not specified
 * @see <a href="https://w3c.github.io/webappsec-csp/#grammardef-host-source">
 *      host-source grammar</a>
 */
public record Host(String scheme, String host, int port, String path) {

    /**
     * Parses a host-source from its CSP string representation.
     * <p>
     * The input is matched against the host-source grammar. The scheme, if present,
     * is lowercased. The host is always lowercased. The port may be a number, the
     * wildcard {@code *}, or absent. The path, if present, is preserved as-is.
     * </p>
     *
     * @param value the CSP host-source token (e.g. {@code "https://example.com:443/path"})
     * @return an {@link Optional} containing the parsed {@link Host},
     *         or empty if the value does not match the host-source grammar
     */
    public static Optional<Host> parseHost(final String value) {
        final Matcher matcher = Constants.HOST_SOURCE_PATTERN.matcher(value);
        if (matcher.find()) {
            String scheme = matcher.group("scheme");
            if (scheme != null) {
                scheme = scheme.substring(0, scheme.length() - 3).toLowerCase(Locale.ROOT);
            }
            final String portString = matcher.group("port");
            final int port;
            if (portString == null) {
                port = Constants.EMPTY_PORT;
            }
            else {
                port = ":*".equals(portString) ? Constants.WILDCARD_PORT : Integer.parseInt(portString.substring(1));
            }
            // Hosts are only consumed lowercase: https://w3c.github.io/webappsec-csp/#host-part-match
            // There is no possible NPE here; host is not optional
            final String host = matcher.group("host").toLowerCase(Locale.ROOT);
            final String path = matcher.group("path");

            // TODO contemplate warning for paths which contain `//`, `/../`, or `/./`,
            // since those will never match an actual request
            // TODO contemplate warning for ports which are implied by their scheme
            // TODO think about IDN and percent-encoding :((((
            // We really want paths to be minimally percent-encoded - all and only the things which need to be
            // (IDN isn't that bad because we restrict to ascii)
            return Optional.of(new Host(scheme, host, port, path));
        }

        return Optional.empty();
    }

    /**
     * Returns the CSP string representation of this host-source.
     * <p>
     * The scheme is included only if it was explicitly specified.
     * The port is omitted if it is the default port for the scheme or was not specified.
     * The path is included only if it was explicitly specified.
     * </p>
     *
     * @return the host-source string (e.g. {@code "https://example.com/path"})
     */
    @Override
    public String toString() {
        final boolean isDefaultPort =
                port == Constants.EMPTY_PORT || scheme != null && port == URI
                        .defaultPortForProtocol(scheme);
        return (scheme == null ? "" : scheme + "://")
                + host
                + (isDefaultPort ? "" : ":" + (port == Constants.WILDCARD_PORT ? "*" : port))
                + (path == null ? "" : path);
    }

}
