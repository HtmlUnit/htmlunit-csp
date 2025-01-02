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

import java.util.Locale;
import java.util.Objects;

public abstract class URLWithScheme {

    private final String scheme_;
    private final String host_;
    private final Integer port_;
    private final String path_;

    protected URLWithScheme(final String scheme, final String host, final Integer port, final String path) {
        scheme_ = scheme.toLowerCase(Locale.ROOT);
        host_ = host == null ? host : host.toLowerCase(Locale.ROOT);
        port_ = port;
        path_ = path;
    }

    public String getScheme() {
        return scheme_;
    }

    public String getHost() {
        return host_;
    }

    public Integer getPort() {
        return port_;
    }

    public String getPath() {
        return path_;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof URLWithScheme)) {
            return false;
        }
        final URLWithScheme that = (URLWithScheme) o;
        return scheme_.equals(that.scheme_)
                && Objects.equals(host_, that.host_)
                && Objects.equals(port_, that.port_)
                && path_.equals(that.path_);
    }

    @Override
    public int hashCode() {
        return Objects.hash(scheme_, host_, port_, path_);
    }
}
