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

import org.junit.jupiter.api.Test;

public class UtilsExtractLeadingTokenTest {

    // ===== NULL AND EMPTY TESTS =====

    @Test
    public void testExtractLeadingToken_Null() {
        assertEquals("", Utils.extractLeadingToken(null));
    }

    @Test
    public void testExtractLeadingToken_EmptyString() {
        assertEquals("", Utils.extractLeadingToken(""));
    }

    // ===== SIMPLE TOKEN TESTS =====

    @Test
    public void testExtractLeadingToken_SingleWord() {
        assertEquals("hello", Utils.extractLeadingToken("hello"));
    }

    @Test
    public void testExtractLeadingToken_SingleCharacter() {
        assertEquals("x", Utils.extractLeadingToken("x"));
    }

    @Test
    public void testExtractLeadingToken_TwoWords() {
        assertEquals("hello", Utils.extractLeadingToken("hello world"));
    }

    @Test
    public void testExtractLeadingToken_MultipleWords() {
        assertEquals("first", Utils.extractLeadingToken("first second third"));
    }

    // ===== WHITESPACE DELIMITER TESTS =====

    @Test
    public void testExtractLeadingToken_SpaceDelimiter() {
        assertEquals("hello", Utils.extractLeadingToken("hello world"));
    }

    @Test
    public void testExtractLeadingToken_TabDelimiter() {
        assertEquals("hello", Utils.extractLeadingToken("hello\tworld"));
    }

    @Test
    public void testExtractLeadingToken_NewlineDelimiter() {
        assertEquals("hello", Utils.extractLeadingToken("hello\nworld"));
    }

    @Test
    public void testExtractLeadingToken_CarriageReturnDelimiter() {
        assertEquals("hello", Utils.extractLeadingToken("hello\rworld"));
    }

    @Test
    public void testExtractLeadingToken_FormFeedDelimiter() {
        assertEquals("hello", Utils.extractLeadingToken("hello\fworld"));
    }

    @Test
    public void testExtractLeadingToken_MixedWhitespaceDelimiter() {
        assertEquals("hello", Utils.extractLeadingToken("hello \t\n\rworld"));
    }

    @Test
    public void testExtractLeadingToken_MultipleSpaces() {
        assertEquals("hello", Utils.extractLeadingToken("hello   world"));
    }

    // ===== LEADING WHITESPACE TESTS (should return empty) =====

    @Test
    public void testExtractLeadingToken_LeadingSpace() {
        assertEquals("", Utils.extractLeadingToken(" hello"));
    }

    @Test
    public void testExtractLeadingToken_LeadingSpaces() {
        assertEquals("", Utils.extractLeadingToken("   hello"));
    }

    @Test
    public void testExtractLeadingToken_LeadingTab() {
        assertEquals("", Utils.extractLeadingToken("\thello"));
    }

    @Test
    public void testExtractLeadingToken_LeadingNewline() {
        assertEquals("", Utils.extractLeadingToken("\nhello"));
    }

    @Test
    public void testExtractLeadingToken_LeadingCarriageReturn() {
        assertEquals("", Utils.extractLeadingToken("\rhello"));
    }

    @Test
    public void testExtractLeadingToken_LeadingFormFeed() {
        assertEquals("", Utils.extractLeadingToken("\fhello"));
    }

    @Test
    public void testExtractLeadingToken_LeadingMixedWhitespace() {
        assertEquals("", Utils.extractLeadingToken(" \t\n\rhello"));
    }

    // ===== ALL WHITESPACE TESTS =====

    @Test
    public void testExtractLeadingToken_AllSpaces() {
        assertEquals("", Utils.extractLeadingToken("   "));
    }

    @Test
    public void testExtractLeadingToken_AllTabs() {
        assertEquals("", Utils.extractLeadingToken("\t\t\t"));
    }

    @Test
    public void testExtractLeadingToken_AllNewlines() {
        assertEquals("", Utils.extractLeadingToken("\n\n\n"));
    }

    @Test
    public void testExtractLeadingToken_AllMixedWhitespace() {
        assertEquals("", Utils.extractLeadingToken(" \t\n\r\f "));
    }

    @Test
    public void testExtractLeadingToken_SingleSpace() {
        assertEquals("", Utils.extractLeadingToken(" "));
    }

    @Test
    public void testExtractLeadingToken_SingleTab() {
        assertEquals("", Utils.extractLeadingToken("\t"));
    }

    @Test
    public void testExtractLeadingToken_SingleNewline() {
        assertEquals("", Utils.extractLeadingToken("\n"));
    }

    // ===== TRAILING WHITESPACE TESTS =====

    @Test
    public void testExtractLeadingToken_TrailingSpace() {
        assertEquals("hello", Utils.extractLeadingToken("hello "));
    }

    @Test
    public void testExtractLeadingToken_TrailingSpaces() {
        assertEquals("hello", Utils.extractLeadingToken("hello   "));
    }

    @Test
    public void testExtractLeadingToken_TrailingTab() {
        assertEquals("hello", Utils.extractLeadingToken("hello\t"));
    }

    @Test
    public void testExtractLeadingToken_TrailingNewline() {
        assertEquals("hello", Utils.extractLeadingToken("hello\n"));
    }

    @Test
    public void testExtractLeadingToken_TrailingMixedWhitespace() {
        assertEquals("hello", Utils.extractLeadingToken("hello \t\n\r"));
    }

    // ===== SPECIAL CHARACTER TESTS =====

    @Test
    public void testExtractLeadingToken_NumbersAndLetters() {
        assertEquals("abc123", Utils.extractLeadingToken("abc123 xyz"));
    }

    @Test
    public void testExtractLeadingToken_SpecialCharacters() {
        assertEquals("hello@world.com", Utils.extractLeadingToken("hello@world.com next"));
    }

    @Test
    public void testExtractLeadingToken_Punctuation() {
        assertEquals("hello!", Utils.extractLeadingToken("hello! world"));
    }

    @Test
    public void testExtractLeadingToken_MixedSpecialChars() {
        assertEquals("test-123_abc.xyz", Utils.extractLeadingToken("test-123_abc.xyz more"));
    }

    @Test
    public void testExtractLeadingToken_OnlySpecialChars() {
        assertEquals("!@#$%", Utils.extractLeadingToken("!@#$% text"));
    }

    // ===== UNICODE TESTS =====

    @Test
    public void testExtractLeadingToken_UnicodeCharacters() {
        assertEquals("日本語", Utils.extractLeadingToken("日本語 text"));
    }

    @Test
    public void testExtractLeadingToken_EmojiCharacters() {
        assertEquals("hello😀world", Utils.extractLeadingToken("hello😀world next"));
    }

    @Test
    public void testExtractLeadingToken_AccentedCharacters() {
        assertEquals("café", Utils.extractLeadingToken("café restaurant"));
    }

    @Test
    public void testExtractLeadingToken_MixedUnicode() {
        assertEquals("Ñoño", Utils.extractLeadingToken("Ñoño más"));
    }

    // ===== EDGE CASES =====

    @Test
    public void testExtractLeadingToken_VeryLongToken() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 10000; i++) {
            sb.append("a");
        }
        sb.append(" next");

        String result = Utils.extractLeadingToken(sb.toString());
        assertEquals(10000, result.length());
        assertEquals('a', result.charAt(0));
        assertEquals('a', result.charAt(result.length() - 1));
    }

    @Test
    public void testExtractLeadingToken_NoWhitespace() {
        assertEquals("helloworld", Utils.extractLeadingToken("helloworld"));
    }

    @Test
    public void testExtractLeadingToken_OnlyToken() {
        assertEquals("token", Utils.extractLeadingToken("token"));
    }

    @Test
    public void testExtractLeadingToken_TokenFollowedByMultipleWhitespace() {
        assertEquals("hello", Utils.extractLeadingToken("hello    \t\n   world"));
    }

    // ===== LINE ENDING TESTS =====

    @Test
    public void testExtractLeadingToken_WindowsLineEnding() {
        assertEquals("hello", Utils.extractLeadingToken("hello\r\nworld"));
    }

    @Test
    public void testExtractLeadingToken_UnixLineEnding() {
        assertEquals("hello", Utils.extractLeadingToken("hello\nworld"));
    }

    @Test
    public void testExtractLeadingToken_MacLineEnding() {
        assertEquals("hello", Utils.extractLeadingToken("hello\rworld"));
    }

    @Test
    public void testExtractLeadingToken_MixedLineEndings() {
        assertEquals("first", Utils.extractLeadingToken("first\r\nsecond\nthird"));
    }

    // ===== CHARACTERS THAT SHOULD NOT BE TREATED AS WHITESPACE =====

    @Test
    public void testExtractLeadingToken_NonBreakingSpace() {
        // Non-breaking space (U+00A0) is NOT in our whitespace set
        assertEquals("hello\u00A0world", Utils.extractLeadingToken("hello\u00A0world next"));
    }

    @Test
    public void testExtractLeadingToken_VerticalTab() {
        // Vertical tab (U+000B) is NOT in our whitespace set
        assertEquals("hello\u000Bworld", Utils.extractLeadingToken("hello\u000Bworld next"));
    }

    @Test
    public void testExtractLeadingToken_ZeroWidthSpace() {
        // Zero-width space (U+200B) is NOT in our whitespace set
        assertEquals("hello\u200Bworld", Utils.extractLeadingToken("hello\u200Bworld next"));
    }

    // ===== REAL-WORLD SCENARIOS =====

    @Test
    public void testExtractLeadingToken_EmailAddress() {
        assertEquals("user@example.com", Utils.extractLeadingToken("user@example.com more text"));
    }

    @Test
    public void testExtractLeadingToken_Url() {
        assertEquals("https://example.com", Utils.extractLeadingToken("https://example.com description"));
    }

    @Test
    public void testExtractLeadingToken_FilePath() {
        assertEquals("/path/to/file.txt", Utils.extractLeadingToken("/path/to/file.txt content"));
    }

    @Test
    public void testExtractLeadingToken_IpAddress() {
        assertEquals("192.168.1.1", Utils.extractLeadingToken("192.168.1.1 hostname"));
    }

    @Test
    public void testExtractLeadingToken_CommandLineArg() {
        assertEquals("--flag=value", Utils.extractLeadingToken("--flag=value other"));
    }

    @Test
    public void testExtractLeadingToken_JsonKey() {
        assertEquals("\"name\":", Utils.extractLeadingToken("\"name\": \"value\""));
    }

    // ===== BOUNDARY TESTS =====

    @Test
    public void testExtractLeadingToken_OnlyOneCharBeforeSpace() {
        assertEquals("a", Utils.extractLeadingToken("a b"));
    }

    @Test
    public void testExtractLeadingToken_OnlyOneCharBeforeTab() {
        assertEquals("x", Utils.extractLeadingToken("x\ty"));
    }

    @Test
    public void testExtractLeadingToken_TwoCharsNoWhitespace() {
        assertEquals("ab", Utils.extractLeadingToken("ab"));
    }

    @Test
    public void testExtractLeadingToken_AlternatingPattern() {
        assertEquals("a", Utils.extractLeadingToken("a b c d e"));
    }
}