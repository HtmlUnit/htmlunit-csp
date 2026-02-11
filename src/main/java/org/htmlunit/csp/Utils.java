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

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import java.util.regex.Pattern;

public final class Utils {
    /** IS_BASE64_VALUE. */
    public static final Predicate<String> IS_BASE64_VALUE
                            = Pattern.compile("[a-zA-Z0-9+/\\-_]+=?=?").asPredicate();

    // https://infra.spec.whatwg.org/#split-on-ascii-whitespace
    static List<String> splitOnAsciiWhitespace(final String input) {
        final ArrayList<String> result = new ArrayList<>();

        if (input == null || input.isEmpty()) {
            return result;
        }

        final int len = input.length();
        int tokenStart = -1;

        for (int i = 0; i < len; i++) {
            final char c = input.charAt(i);
            final boolean isWs = Constants.isAsciiWhitespace(c);

            if (!isWs && tokenStart == -1) {
                // Start of a new token
                tokenStart = i;
            }
            else if (isWs && tokenStart != -1) {
                // End of current token
                result.add(input.substring(tokenStart, i));
                tokenStart = -1;
            }
        }

        // Add final token if string doesn't end with whitespace
        if (tokenStart != -1) {
            result.add(input.substring(tokenStart, len));
        }

        return result;
    }

    // https://infra.spec.whatwg.org/#strictly-split
    static List<String> strictlySplit(final String s, final char delim) {
        int off = 0;
        int next;
        final ArrayList<String> list = new ArrayList<>();
        while ((next = s.indexOf(delim, off)) != -1) {
            list.add(s.substring(off, next));
            off = next + 1;
        }

        list.add(s.substring(off));
        return list;
    }

    static String decodeString(final String s) {
        return URLDecoder.decode(s, StandardCharsets.UTF_8);
    }

    /**
     * Trims leading and trailing ascii whitespace (\t, \n, \f, \r, and space) from the given string.
     *
     * @param str the string to trim (can be null)
     * @return trimmed string, or null if input is null, or empty string if all whitespace
     */
    public static String trimAsciiWhitespace(final String str) {
        if (str == null) {
            return null;
        }

        final int len = str.length();
        if (len == 0) {
            return str;
        }

        int start = 0;
        int end = len - 1;

        // first non-whitespace character
        while (start <= end && Constants.isAsciiWhitespace(str.charAt(start))) {
            start++;
        }

        // all whitespace
        if (start > end) {
            return "";
        }

        // last non-whitespace character
        while (end > start && Constants.isAsciiWhitespace(str.charAt(end))) {
            end--;
        }

        if (start == 0 && end == len - 1) {
            return str;
        }

        return str.substring(start, end + 1);
    }

    /**
     * Extracts the first contiguous sequence of non-ascii whitespace (\t, \n, \f, \r, and space) characters
     * from the beginning of the input string. If the string starts with whitespace or is empty, returns empty string.
     *
     * @param input the input string (can be null)
     * @return the first token, or empty string if input starts with whitespace, is null, or is empty
     */
    public static String extractLeadingToken(final String input) {
        if (input == null || input.isEmpty()) {
            return "";
        }

        // If starts with whitespace, return empty
        final char first = input.charAt(0);
        if (first == '\t' || first == '\n' || first == '\f' || first == '\r' || first == ' ') {
            return "";
        }

        // Find first whitespace character
        for (int i = 1; i < input.length(); i++) {
            final char c = input.charAt(i);
            if (Constants.isAsciiWhitespace(c)) {
                return input.substring(0, i);
            }
        }

        // No whitespace found, return entire string
        return input;
    }

    private Utils() {
        // Utility class
    }
}
