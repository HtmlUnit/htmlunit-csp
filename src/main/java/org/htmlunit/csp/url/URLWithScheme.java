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
import java.util.Objects;

/**
 * Abstract base class representing a URL that has at least a scheme component.
 * <p>
 * This is the common supertype for both hierarchical URLs ({@link URI}) and
 * opaque/non-hierarchical URLs ({@link GUID}). The scheme and host are always
 * stored in lowercase per the relevant specifications. The port and path may
 * be {@code null} depending on the URL type.
 * </p>
 * <p>
 * Two {@code URLWithScheme} instances are considered equal if their scheme,
 * host, port, and path are all equal.
 * </p>
 */
public abstract class URLWithScheme {

    private final String scheme_;
    private final String host_;
    private final Integer port_;
    private final String path_;

    /**
     * Constructs a URL with the given components.
     * <p>
     * The scheme is lowercased. The host, if non-{@code null}, is also lowercased.
     * The port and path are stored as-is.
     * </p>
     *
     * @param scheme the URL scheme (e.g. {@code "https"}, {@code "javascript"});
     *        will be lowercased
     * @param host the host component, or {@code null} if not applicable;
     *        will be lowercased if non-{@code null}
     * @param port the port number, or {@code null} if not applicable
     * @param path the path component, or {@code null} if not applicable
     */
    protected URLWithScheme(final String scheme, final String host, final Integer port, final String path) {
        scheme_ = scheme.toLowerCase(Locale.ROOT);
        host_ = host == null ? null : host.toLowerCase(Locale.ROOT);
        port_ = port;
        path_ = path;
    }

    /**
     * Returns the scheme component of this URL, in lowercase.
     *
     * @return the scheme (e.g. {@code "https"}, {@code "data"}, {@code "javascript"})
     */
    public String getScheme() {
        return scheme_;
    }

    /**
     * Returns the host component of this URL, in lowercase.
     *
     * @return the host, or {@code null} if this URL has no host
     *         (e.g. for {@link GUID} URLs like {@code data:} or {@code javascript:})
     */
    public String getHost() {
        return host_;
    }

    /**
     * Returns the port component of this URL.
     *
     * @return the port number, or {@code null} if this URL has no port
     */
    public Integer getPort() {
        return port_;
    }

    /**
     * Returns the path component of this URL.
     * <p>
     * For {@link URI} instances this is the path portion of the hierarchical URL
     * (e.g. {@code "/scripts/app.js"}). For {@link GUID} instances this is the
     * opaque data after the scheme (e.g. the source code in a {@code javascript:} URL).
     * </p>
     *
     * @return the path, or {@code null} if not applicable
     */
    public String getPath() {
        return path_;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Two {@code URLWithScheme} instances are equal if their scheme, host, port,
     * and path are all equal.
     * </p>
     */
    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof URLWithScheme that)) {
            return false;
        }
        return scheme_.equals(that.scheme_)
                && Objects.equals(host_, that.host_)
                && Objects.equals(port_, that.port_)
                && path_.equals(that.path_);
    }

    /** {@inheritDoc} */
    @Override
    public int hashCode() {
        return Objects.hash(scheme_, host_, port_, path_);
    }
}
