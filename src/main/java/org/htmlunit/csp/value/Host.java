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
import java.util.regex.Matcher;

import org.htmlunit.csp.Constants;
import org.htmlunit.csp.url.URI;

public final class Host {
    private final String scheme_;
    private final String host_;
    private final int port_;
    private final String path_;

    private Host(final String scheme, final String host, final int port, final String path) {
        scheme_ = scheme;
        host_ = host;
        port_ = port;
        path_ = path;
    }

    public String getScheme() {
        return scheme_;
    }

    public String getHost() {
        return host_;
    }

    public int getPort() {
        return port_;
    }

    public String getPath() {
        return path_;
    }

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

    @Override
    public String toString() {
        final boolean isDefaultPort =
                port_ == Constants.EMPTY_PORT || scheme_ != null && port_ == URI
                        .defaultPortForProtocol(scheme_);
        return (scheme_ == null ? "" : scheme_ + "://")
                + host_
                + (isDefaultPort ? "" : ":" + (port_ == Constants.WILDCARD_PORT ? "*" : port_))
                + (path_ == null ? "" : path_);
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        final Host that = (Host) o;
        return port_ == that.port_
                && Objects.equals(scheme_, that.scheme_)
                && Objects.equals(host_, that.host_)
                && Objects.equals(path_, that.path_);
    }

    @Override
    public int hashCode() {
        return Objects.hash(scheme_, host_, port_, path_);
    }
}
