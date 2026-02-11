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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

public class UtilsTrimAsciiWhitespaceTest {

    // ===== NULL AND EMPTY TESTS =====

    @Test
    public void testTrim_Null() {
        assertNull(Utils.trimAsciiWhitespace(null));
    }

    @Test
    public void testTrim_EmptyString() {
        assertEquals("", Utils.trimAsciiWhitespace(""));
    }

    // ===== NO WHITESPACE TESTS =====

    @Test
    public void testTrim_NoWhitespace() {
        assertEquals("hello", Utils.trimAsciiWhitespace("hello"));
    }

    @Test
    public void testTrim_SingleCharacter() {
        assertEquals("x", Utils.trimAsciiWhitespace("x"));
    }

    @Test
    public void testTrim_SpecialCharacters() {
        assertEquals("!@#$%", Utils.trimAsciiWhitespace("!@#$%"));
    }

    @Test
    public void testTrim_UnicodeCharacters() {
        assertEquals("日本語", Utils.trimAsciiWhitespace("日本語"));
    }

    // ===== LEADING WHITESPACE TESTS =====

    @Test
    public void testTrim_LeadingSpace() {
        assertEquals("hello", Utils.trimAsciiWhitespace(" hello"));
    }

    @Test
    public void testTrim_LeadingSpaces() {
        assertEquals("hello", Utils.trimAsciiWhitespace("   hello"));
    }

    @Test
    public void testTrim_LeadingTab() {
        assertEquals("hello", Utils.trimAsciiWhitespace("\thello"));
    }

    @Test
    public void testTrim_LeadingNewline() {
        assertEquals("hello", Utils.trimAsciiWhitespace("\nhello"));
    }

    @Test
    public void testTrim_LeadingCarriageReturn() {
        assertEquals("hello", Utils.trimAsciiWhitespace("\rhello"));
    }

    @Test
    public void testTrim_LeadingFormFeed() {
        assertEquals("hello", Utils.trimAsciiWhitespace("\fhello"));
    }

    @Test
    public void testTrim_LeadingMixedWhitespace() {
        assertEquals("hello", Utils.trimAsciiWhitespace(" \t\n\r\fhello"));
    }

    // ===== TRAILING WHITESPACE TESTS =====

    @Test
    public void testTrim_TrailingSpace() {
        assertEquals("hello", Utils.trimAsciiWhitespace("hello "));
    }

    @Test
    public void testTrim_TrailingSpaces() {
        assertEquals("hello", Utils.trimAsciiWhitespace("hello   "));
    }

    @Test
    public void testTrim_TrailingTab() {
        assertEquals("hello", Utils.trimAsciiWhitespace("hello\t"));
    }

    @Test
    public void testTrim_TrailingNewline() {
        assertEquals("hello", Utils.trimAsciiWhitespace("hello\n"));
    }

    @Test
    public void testTrim_TrailingCarriageReturn() {
        assertEquals("hello", Utils.trimAsciiWhitespace("hello\r"));
    }

    @Test
    public void testTrim_TrailingFormFeed() {
        assertEquals("hello", Utils.trimAsciiWhitespace("hello\f"));
    }

    @Test
    public void testTrim_TrailingMixedWhitespace() {
        assertEquals("hello", Utils.trimAsciiWhitespace("hello \t\n\r\f"));
    }

    // ===== BOTH SIDES WHITESPACE TESTS =====

    @Test
    public void testTrim_BothSidesSpace() {
        assertEquals("hello", Utils.trimAsciiWhitespace(" hello "));
    }

    @Test
    public void testTrim_BothSidesMultipleSpaces() {
        assertEquals("hello", Utils.trimAsciiWhitespace("   hello   "));
    }

    @Test
    public void testTrim_BothSidesMixedWhitespace() {
        assertEquals("hello", Utils.trimAsciiWhitespace(" \t\nhello\r\f "));
    }

    @Test
    public void testTrim_ComplexWhitespace() {
        assertEquals("hello world", Utils.trimAsciiWhitespace("\t\n\r  hello world  \r\n\t"));
    }

    // ===== ALL WHITESPACE TESTS =====

    @Test
    public void testTrim_AllSpaces() {
        assertEquals("", Utils.trimAsciiWhitespace("   "));
    }

    @Test
    public void testTrim_AllTabs() {
        assertEquals("", Utils.trimAsciiWhitespace("\t\t\t"));
    }

    @Test
    public void testTrim_AllNewlines() {
        assertEquals("", Utils.trimAsciiWhitespace("\n\n\n"));
    }

    @Test
    public void testTrim_AllMixedWhitespace() {
        assertEquals("", Utils.trimAsciiWhitespace(" \t\n\r\f "));
    }

    @Test
    public void testTrim_SingleSpace() {
        assertEquals("", Utils.trimAsciiWhitespace(" "));
    }

    @Test
    public void testTrim_SingleTab() {
        assertEquals("", Utils.trimAsciiWhitespace("\t"));
    }

    @Test
    public void testTrim_SingleNewline() {
        assertEquals("", Utils.trimAsciiWhitespace("\n"));
    }

    // ===== INTERNAL WHITESPACE TESTS =====

    @Test
    public void testTrim_InternalSpacePreserved() {
        assertEquals("hello world", Utils.trimAsciiWhitespace("hello world"));
    }

    @Test
    public void testTrim_InternalWhitespacePreserved() {
        assertEquals("hello\tworld", Utils.trimAsciiWhitespace("hello\tworld"));
    }

    @Test
    public void testTrim_InternalAndExternalWhitespace() {
        assertEquals("hello world", Utils.trimAsciiWhitespace("  hello world  "));
    }

    @Test
    public void testTrim_MultipleInternalSpaces() {
        assertEquals("hello   world", Utils.trimAsciiWhitespace("  hello   world  "));
    }

    // ===== EDGE CASES =====

    @Test
    public void testTrim_OnlyNonWhitespaceAtStart() {
        assertEquals("x", Utils.trimAsciiWhitespace("x   "));
    }

    @Test
    public void testTrim_OnlyNonWhitespaceAtEnd() {
        assertEquals("x", Utils.trimAsciiWhitespace("   x"));
    }

    @Test
    public void testTrim_TwoCharacters() {
        assertEquals("ab", Utils.trimAsciiWhitespace("ab"));
    }

    @Test
    public void testTrim_TwoCharactersWithWhitespace() {
        assertEquals("ab", Utils.trimAsciiWhitespace(" ab "));
    }

    @Test
    public void testTrim_WindowsLineEnding() {
        assertEquals("hello", Utils.trimAsciiWhitespace("hello\r\n"));
    }

    @Test
    public void testTrim_UnixLineEnding() {
        assertEquals("hello", Utils.trimAsciiWhitespace("hello\n"));
    }

    @Test
    public void testTrim_MacLineEnding() {
        assertEquals("hello", Utils.trimAsciiWhitespace("hello\r"));
    }

    // ===== CHARACTERS THAT SHOULD NOT BE TRIMMED =====

    @Test
    public void testTrim_NonBreakingSpace() {
        // Non-breaking space (Unicode 00A0) should NOT be trimmed
        assertEquals("\u00A0hello\u00A0", Utils.trimAsciiWhitespace("\u00A0hello\u00A0"));
    }

    @Test
    public void testTrim_VerticalTab() {
        // Vertical tab (Unicode 000B) should NOT be trimmed (not in our whitespace set)
        assertEquals("\u000Bhello\u000B", Utils.trimAsciiWhitespace("\u000Bhello\u000B"));
    }

    @Test
    public void testTrim_OtherUnicodeWhitespace() {
        // Other Unicode whitespace should NOT be trimmed
        assertEquals("\u2000hello\u2000", Utils.trimAsciiWhitespace("\u2000hello\u2000"));
    }

    // ===== PERFORMANCE TESTS (optional, for benchmarking) =====

    @Test
    public void testTrim_LargeString() {
        StringBuilder sb = new StringBuilder();
        sb.append("    "); // leading whitespace
        for (int i = 0; i < 10000; i++) {
            sb.append("a");
        }
        sb.append("    "); // trailing whitespace

        String result = Utils.trimAsciiWhitespace(sb.toString());
        assertEquals(10000, result.length());
        assertEquals('a', result.charAt(0));
        assertEquals('a', result.charAt(result.length() - 1));
    }

    @Test
    public void testTrim_LargeWhitespaceString() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 10000; i++) {
            sb.append(" ");
        }

        String result = Utils.trimAsciiWhitespace(sb.toString());
        assertEquals("", result);
    }
}