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

/**
 * Shared constants used throughout the CSP parser.
 * <p>
 * This utility class provides regex patterns for matching CSP grammar
 * productions (schemes, hosts, ports, paths, media types, RFC 7230 tokens,
 * IP addresses, etc.) as well as sentinel values for ports and a helper
 * method for ASCII whitespace detection.
 * </p>
 */
public final class Constants {
    /**
     * Regex fragment matching a URI scheme per
     * <a href="https://tools.ietf.org/html/rfc3986#section-3.1">RFC 3986 §3.1</a>.
     * <p>
     * Pattern: {@code [a-zA-Z][a-zA-Z0-9+\-.]*}
     * </p>
     */
    public static final String SCHEME_PART = "[a-zA-Z][a-zA-Z0-9+\\-.]*";

    /**
     * Pattern that matches a URI scheme followed by a colon at the start of a string.
     * <p>
     * Named capture group: {@code scheme} (includes the trailing colon).
     * </p>
     */
    public static final Pattern SCHEME_PATTERN = Pattern.compile("^(?<scheme>" + Constants.SCHEME_PART + ":)");

    /**
     * Pattern matching an RFC 7230 token (one or more {@code tchar} characters).
     *
     * @see <a href="https://tools.ietf.org/html/rfc7230#section-3.2.6">RFC 7230 §3.2.6</a>
     */
    public static final Pattern rfc7230TokenPattern = Pattern.compile("^[!#$%&'*+\\-.^_`|~0-9a-zA-Z]+$");

    /**
     * Pattern matching a media type ({@code type/subtype}) per
     * <a href="https://tools.ietf.org/html/rfc2045#section-5.1">RFC 2045 §5.1</a>.
     * <p>
     * Named capture groups: {@code type} and {@code subtype}.
     * </p>
     */
    public static final Pattern MEDIA_TYPE_PATTERN
                = Pattern.compile("^(?<type>[a-zA-Z0-9!#$%^&*\\-_+{}|'.`~]+)"
                        + "/(?<subtype>[a-zA-Z0-9!#$%^&*\\-_+{}|'.`~]+)$");

    /**
     * Pattern matching CSP keyword-like tokens that are missing their required
     * single quotes (e.g. {@code self} instead of {@code 'self'}).
     * <p>
     * Used to produce helpful warnings when an unquoted keyword is encountered
     * in a source list.
     * </p>
     */
    public static final Pattern UNQUOTED_KEYWORD_PATTERN
                = Pattern.compile("^(?:self|unsafe-inline|unsafe-eval|unsafe-redirect"
                        + "|none|strict-dynamic|unsafe-hashes|report-sample|unsafe-allow-redirects|"
                        + "wasm-unsafe-eval)$");

    /**
     * Sentinel value representing a wildcard port ({@code :*}) in a host-source.
     * <p>Value: {@code -200}</p>
     */
    public static final int WILDCARD_PORT = -200;

    /**
     * Sentinel value representing an empty (unspecified) port in a host-source.
     * <p>Value: {@code -1}</p>
     */
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

    /**
     * Pattern matching a CSP host-source expression.
     * <p>
     * Captures the optional scheme ({@code scheme}), required host ({@code host}),
     * optional port ({@code port}), and optional path ({@code path}) components.
     * </p>
     *
     * @see <a href="https://w3c.github.io/webappsec-csp/#grammardef-host-source">
     *      host-source grammar</a>
     */
    public static final Pattern HOST_SOURCE_PATTERN = Pattern.compile(
            "^(?<scheme>" + SCHEME_PART + "://)?(?<host>" + hostPart + ")(?<port>" + portPart + ")?(?<path>" + pathPart
                    + ")?" + queryFragmentPart + "$");

    /**
     * Pattern matching an IPv4 address in dotted-decimal notation.
     * <p>
     * Each octet must be in the range 0–255.
     * </p>
     */
    public static final Pattern IPv4address = Pattern.compile(
            "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");

    /**
     * Pattern matching the IPv6 loopback address ({@code ::1}) in its various
     * zero-expanded forms (e.g. {@code 0:0:0:0:0:0:0:1}).
     */
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

    /**
     * Pattern matching an IPv6 address, with or without enclosing brackets.
     * <p>
     * Matches both {@code [::1]} and {@code ::1} forms.
     * </p>
     */
    public static final Pattern IPv6addressWithOptionalBracket =
            Pattern.compile("^(?:\\[" + IPv6address + "\\]|" + IPv6address + ")$");

    /**
     * Pattern matching a valid CSP directive name ({@code ALPHA / DIGIT / "-"}).
     */
    public static final Pattern DIRECTIVE_NAME_PATTERN = Pattern.compile("^[A-Za-z0-9\\-]+$");

    /**
     * Tests if a character is ASCII whitespace.
     * <p>
     * ASCII whitespace characters are: tab ({@code \t}), newline ({@code \n}),
     * form feed ({@code \f}), carriage return ({@code \r}), and space.
     * </p>
     *
     * @param c the character to test
     * @return {@code true} if the character is ASCII whitespace, {@code false} otherwise
     */
    public static boolean isAsciiWhitespace(final char c) {
        return ' ' == c || '\n' == c || '\r' == c || '\t' == c || '\f' == c;
    }

    private Constants() {
        // Utility class
    }
}
