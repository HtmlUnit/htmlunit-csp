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
package org.htmlunit.csp;

import java.util.regex.Pattern;

public final class Constants {
    // https://tools.ietf.org/html/rfc3986#section-3.1
    /** SCHEME_PART = "[a-zA-Z][a-zA-Z0-9+\\-.]*". */
    public static final String SCHEME_PART = "[a-zA-Z][a-zA-Z0-9+\\-.]*";
    /** SCHEME_PATTERN. */
    public static final Pattern SCHEME_PATTERN = Pattern.compile("^(?<scheme>" + Constants.SCHEME_PART + ":)");

    // https://tools.ietf.org/html/rfc7230#section-3.2.6
    /** rfc7230TokenPattern. */
    public static final Pattern rfc7230TokenPattern = Pattern.compile("^[!#$%&'*+\\-.^_`|~0-9a-zA-Z]+$");

    // RFC 2045 appendix A: productions of type and subtype
    // https://tools.ietf.org/html/rfc2045#section-5.1
    /** MEDIA_TYPE_PATTERN. */
    public static final Pattern MEDIA_TYPE_PATTERN
                = Pattern.compile("^(?<type>[a-zA-Z0-9!#$%^&*\\-_+{}|'.`~]+)"
                        + "/(?<subtype>[a-zA-Z0-9!#$%^&*\\-_+{}|'.`~]+)$");
    /** UNQUOTED_KEYWORD_PATTERN. */
    public static final Pattern UNQUOTED_KEYWORD_PATTERN
                = Pattern.compile("^(?:self|unsafe-inline|unsafe-eval|unsafe-redirect"
                        + "|none|strict-dynamic|unsafe-hashes|report-sample|unsafe-allow-redirects|"
                        + "wasm-unsafe-eval)$");

    // port-part constants
    /** WILDCARD_PORT = -200. */
    public static final int WILDCARD_PORT = -200;
    /** EMPTY_PORT = -1. */
    public static final int EMPTY_PORT = -1;

    // https://w3c.github.io/webappsec-csp/#grammardef-host-part
    private static final String hostPart = "\\*|(?:\\*\\.)?[a-zA-Z0-9-]+(?:\\.[a-zA-Z0-9-]+)*";

    // https://w3c.github.io/webappsec-csp/#grammardef-port-part
    private static final String portPart = ":(?:[0-9]+|\\*)";
    private static final String unreserved = "[a-zA-Z0-9\\-._~]";
    private static final String pctEncoded = "%[a-fA-F0-9]{2}";
    private static final String subDelims = "[!$&'()*+,;=]";
    private static final String pchar = "(?:" + unreserved + "|" + pctEncoded + "|" + subDelims + "|[:@])";

    // https://w3c.github.io/webappsec-csp/#grammardef-path-part
    // XXX: divergence from spec; uses path-abempty from RFC3986 instead of path
    private static final String pathPart = "(?:/" + pchar + "*)+";

    private static final String queryFragmentPart = "(?:\\?[^#]*)?(?:#.*)?";

    /** hostSourcePattern. */
    public static final Pattern HOST_SOURCE_PATTERN = Pattern.compile(
            "^(?<scheme>" + SCHEME_PART + "://)?(?<host>" + hostPart + ")(?<port>" + portPart + ")?(?<path>" + pathPart
                    + ")?" + queryFragmentPart + "$");
    /** IPv4address. */
    public static final Pattern IPv4address = Pattern.compile(
            "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");
    /** IPV6loopback. */
    public static final Pattern IPV6loopback = Pattern.compile("^[0:]+:1$");
    private static final String IPv6address = "(?:(?:(?:[0-9A-Fa-f]{1,4}:){6}"
            + "|::(?:[0-9A-Fa-f]{1,4}:){5}"
            + "|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}"
            + "|(?:(?:[0-9A-Fa-f]{1,4}:){0,1}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}"
            + "|(?:(?:[0-9A-Fa-f]{1,4}:){0,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}"
            + "|(?:(?:[0-9A-Fa-f]{1,4}:){0,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:"
            + "|(?:(?:[0-9A-Fa-f]{1,4}:){0,4}[0-9A-Fa-f]{1,4})?::)(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}"
            + "|(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))"
            + "|(?:(?:[0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}"
            + "|(?:(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4})?::)";
    /** IPv6addressWithOptionalBracket. */
    public static final Pattern IPv6addressWithOptionalBracket =
            Pattern.compile("^(?:\\[" + IPv6address + "\\]|" + IPv6address + ")$");

    /** DIRECTIVE_NAME_PATTERN. */
    public static final Pattern DIRECTIVE_NAME_PATTERN = Pattern.compile("^[A-Za-z0-9\\-]+$");

    /** ASCII whitespace. */
    public static boolean isAsciiWhitespace(char c) {
        return ' ' == c || '\n' == c || '\r' == c || '\t' == c || '\f' == c;
    }

    private Constants() {
        // Utility class
    }
}
