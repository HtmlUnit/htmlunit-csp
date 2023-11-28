/*
 * Copyright (c) 2023 Ronald Brill.
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
package org.htmlunit.csp;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import java.util.regex.Pattern;

public final class Utils {
    public static final Predicate<String> IS_BASE64_VALUE
                            = Pattern.compile("[a-zA-Z0-9+/\\-_]+=?=?").asPredicate();

    // https://infra.spec.whatwg.org/#split-on-ascii-whitespace
    static List<String> splitOnAsciiWhitespace(final String input) {
        final ArrayList<String> out = new ArrayList<>();
        for (final String value : input.split("[" + Constants.WHITESPACE_CHARS + "]")) {
            if (value.isEmpty()) {
                continue;
            }
            out.add(value);
        }
        return out;
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
        try {
            return URLDecoder.decode(s, "UTF-8");
        }
        catch (final UnsupportedEncodingException e) {
            return s;
        }
    }

    private Utils() {
        // Utility class
    }
}
