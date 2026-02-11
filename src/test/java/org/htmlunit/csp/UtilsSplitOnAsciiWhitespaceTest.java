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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

public class UtilsSplitOnAsciiWhitespaceTest {

    // ===== NULL AND EMPTY TESTS =====

    @Test
    public void testSplit_Null() {
        List<String> result = Utils.splitOnAsciiWhitespace(null);
        assertTrue(result.isEmpty());
    }

    @Test
    public void testSplit_EmptyString() {
        List<String> result = Utils.splitOnAsciiWhitespace("");
        assertTrue(result.isEmpty());
    }

    @Test
    public void testSplit_AllWhitespace() {
        List<String> result = Utils.splitOnAsciiWhitespace("   \t\n\r\f   ");
        assertTrue(result.isEmpty());
    }

    // ===== SINGLE TOKEN TESTS =====

    @Test
    public void testSplit_SingleWord() {
        List<String> result = Utils.splitOnAsciiWhitespace("hello");
        assertEquals(Arrays.asList("hello"), result);
    }

    @Test
    public void testSplit_SingleCharacter() {
        List<String> result = Utils.splitOnAsciiWhitespace("x");
        assertEquals(Arrays.asList("x"), result);
    }

    @Test
    public void testSplit_SingleWordWithLeadingSpace() {
        List<String> result = Utils.splitOnAsciiWhitespace(" hello");
        assertEquals(Arrays.asList("hello"), result);
    }

    @Test
    public void testSplit_SingleWordWithTrailingSpace() {
        List<String> result = Utils.splitOnAsciiWhitespace("hello ");
        assertEquals(Arrays.asList("hello"), result);
    }

    @Test
    public void testSplit_SingleWordWithBothSpaces() {
        List<String> result = Utils.splitOnAsciiWhitespace(" hello ");
        assertEquals(Arrays.asList("hello"), result);
    }

    // ===== MULTIPLE TOKEN TESTS =====

    @Test
    public void testSplit_TwoWords() {
        List<String> result = Utils.splitOnAsciiWhitespace("hello world");
        assertEquals(Arrays.asList("hello", "world"), result);
    }

    @Test
    public void testSplit_ThreeWords() {
        List<String> result = Utils.splitOnAsciiWhitespace("one two three");
        assertEquals(Arrays.asList("one", "two", "three"), result);
    }

    @Test
    public void testSplit_MultipleWords() {
        List<String> result = Utils.splitOnAsciiWhitespace("the quick brown fox");
        assertEquals(Arrays.asList("the", "quick", "brown", "fox"), result);
    }

    // ===== DIFFERENT WHITESPACE DELIMITER TESTS =====

    @Test
    public void testSplit_TabDelimiter() {
        List<String> result = Utils.splitOnAsciiWhitespace("hello\tworld");
        assertEquals(Arrays.asList("hello", "world"), result);
    }

    @Test
    public void testSplit_NewlineDelimiter() {
        List<String> result = Utils.splitOnAsciiWhitespace("hello\nworld");
        assertEquals(Arrays.asList("hello", "world"), result);
    }

    @Test
    public void testSplit_CarriageReturnDelimiter() {
        List<String> result = Utils.splitOnAsciiWhitespace("hello\rworld");
        assertEquals(Arrays.asList("hello", "world"), result);
    }

    @Test
    public void testSplit_FormFeedDelimiter() {
        List<String> result = Utils.splitOnAsciiWhitespace("hello\fworld");
        assertEquals(Arrays.asList("hello", "world"), result);
    }

    @Test
    public void testSplit_MixedWhitespace() {
        List<String> result = Utils.splitOnAsciiWhitespace("hello\t\n\r\fworld");
        assertEquals(Arrays.asList("hello", "world"), result);
    }

    @Test
    public void testSplit_AllWhitespaceTypes() {
        List<String> result = Utils.splitOnAsciiWhitespace("a\tb\nc\rd\fe");
        assertEquals(Arrays.asList("a", "b", "c", "d", "e"), result);
    }

    // ===== MULTIPLE CONSECUTIVE WHITESPACE TESTS =====

    @Test
    public void testSplit_MultipleSpaces() {
        List<String> result = Utils.splitOnAsciiWhitespace("hello   world");
        assertEquals(Arrays.asList("hello", "world"), result);
    }

    @Test
    public void testSplit_MultipleTabs() {
        List<String> result = Utils.splitOnAsciiWhitespace("hello\t\t\tworld");
        assertEquals(Arrays.asList("hello", "world"), result);
    }

    @Test
    public void testSplit_MultipleNewlines() {
        List<String> result = Utils.splitOnAsciiWhitespace("hello\n\n\nworld");
        assertEquals(Arrays.asList("hello", "world"), result);
    }

    @Test
    public void testSplit_MixedMultipleWhitespace() {
        List<String> result = Utils.splitOnAsciiWhitespace("hello \t\n\r\f world");
        assertEquals(Arrays.asList("hello", "world"), result);
    }

    @Test
    public void testSplit_ManyConsecutiveSpaces() {
        List<String> result = Utils.splitOnAsciiWhitespace("a          b");
        assertEquals(Arrays.asList("a", "b"), result);
    }

    // ===== LEADING/TRAILING WHITESPACE TESTS =====

    @Test
    public void testSplit_LeadingWhitespace() {
        List<String> result = Utils.splitOnAsciiWhitespace("   hello world");
        assertEquals(Arrays.asList("hello", "world"), result);
    }

    @Test
    public void testSplit_TrailingWhitespace() {
        List<String> result = Utils.splitOnAsciiWhitespace("hello world   ");
        assertEquals(Arrays.asList("hello", "world"), result);
    }

    @Test
    public void testSplit_BothLeadingAndTrailing() {
        List<String> result = Utils.splitOnAsciiWhitespace("   hello world   ");
        assertEquals(Arrays.asList("hello", "world"), result);
    }

    @Test
    public void testSplit_ExcessiveWhitespaceEverywhere() {
        List<String> result = Utils.splitOnAsciiWhitespace("  \t\n  hello  \r\f  world  \t\n  ");
        assertEquals(Arrays.asList("hello", "world"), result);
    }

    // ===== SPECIAL CHARACTERS TESTS =====

    @Test
    public void testSplit_NumbersAndLetters() {
        List<String> result = Utils.splitOnAsciiWhitespace("abc123 def456");
        assertEquals(Arrays.asList("abc123", "def456"), result);
    }

    @Test
    public void testSplit_SpecialCharacters() {
        List<String> result = Utils.splitOnAsciiWhitespace("hello@world.com test!123");
        assertEquals(Arrays.asList("hello@world.com", "test!123"), result);
    }

    @Test
    public void testSplit_Punctuation() {
        List<String> result = Utils.splitOnAsciiWhitespace("hello! world?");
        assertEquals(Arrays.asList("hello!", "world?"), result);
    }

    @Test
    public void testSplit_MixedPunctuation() {
        List<String> result = Utils.splitOnAsciiWhitespace("test-123_abc.xyz @#$%");
        assertEquals(Arrays.asList("test-123_abc.xyz", "@#$%"), result);
    }

    // ===== UNICODE TESTS =====

    @Test
    public void testSplit_UnicodeCharacters() {
        List<String> result = Utils.splitOnAsciiWhitespace("日本語 テスト");
        assertEquals(Arrays.asList("日本語", "テスト"), result);
    }

    @Test
    public void testSplit_EmojiCharacters() {
        List<String> result = Utils.splitOnAsciiWhitespace("hello😀 world🌍");
        assertEquals(Arrays.asList("hello😀", "world🌍"), result);
    }

    @Test
    public void testSplit_AccentedCharacters() {
        List<String> result = Utils.splitOnAsciiWhitespace("café résumé");
        assertEquals(Arrays.asList("café", "résumé"), result);
    }

    // ===== LINE ENDING TESTS =====

    @Test
    public void testSplit_WindowsLineEndings() {
        List<String> result = Utils.splitOnAsciiWhitespace("line1\r\nline2\r\nline3");
        assertEquals(Arrays.asList("line1", "line2", "line3"), result);
    }

    @Test
    public void testSplit_UnixLineEndings() {
        List<String> result = Utils.splitOnAsciiWhitespace("line1\nline2\nline3");
        assertEquals(Arrays.asList("line1", "line2", "line3"), result);
    }

    @Test
    public void testSplit_MacLineEndings() {
        List<String> result = Utils.splitOnAsciiWhitespace("line1\rline2\rline3");
        assertEquals(Arrays.asList("line1", "line2", "line3"), result);
    }

    @Test
    public void testSplit_MixedLineEndings() {
        List<String> result = Utils.splitOnAsciiWhitespace("line1\r\nline2\nline3\rline4");
        assertEquals(Arrays.asList("line1", "line2", "line3", "line4"), result);
    }

    // ===== EDGE CASES =====

    @Test
    public void testSplit_SingleSpace() {
        List<String> result = Utils.splitOnAsciiWhitespace(" ");
        assertTrue(result.isEmpty());
    }

    @Test
    public void testSplit_SingleTab() {
        List<String> result = Utils.splitOnAsciiWhitespace("\t");
        assertTrue(result.isEmpty());
    }

    @Test
    public void testSplit_OnlyWhitespaceCharacters() {
        List<String> result = Utils.splitOnAsciiWhitespace("\t\n\f\r ");
        assertTrue(result.isEmpty());
    }

    @Test
    public void testSplit_VeryLongString() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            sb.append("word").append(i).append(" ");
        }

        List<String> result = Utils.splitOnAsciiWhitespace(sb.toString());
        assertEquals(1000, result.size());
        assertEquals("word0", result.get(0));
        assertEquals("word999", result.get(999));
    }

    @Test
    public void testSplit_ManyTokens() {
        List<String> result = Utils.splitOnAsciiWhitespace("a b c d e f g h i j");
        assertEquals(Arrays.asList("a", "b", "c", "d", "e", "f", "g", "h", "i", "j"), result);
    }

    // ===== REAL-WORLD SCENARIOS =====

    @Test
    public void testSplit_CommandLine() {
        List<String> result = Utils.splitOnAsciiWhitespace("git commit -m \"test message\"");
        assertEquals(Arrays.asList("git", "commit", "-m", "\"test", "message\""), result);
    }

    @Test
    public void testSplit_CsvLike() {
        List<String> result = Utils.splitOnAsciiWhitespace("name age city");
        assertEquals(Arrays.asList("name", "age", "city"), result);
    }

    @Test
    public void testSplit_LogLine() {
        List<String> result = Utils.splitOnAsciiWhitespace("2024-01-15 ERROR Failed to connect");
        assertEquals(Arrays.asList("2024-01-15", "ERROR", "Failed", "to", "connect"), result);
    }

    @Test
    public void testSplit_FilePath() {
        List<String> result = Utils.splitOnAsciiWhitespace("/usr/local/bin /home/user");
        assertEquals(Arrays.asList("/usr/local/bin", "/home/user"), result);
    }

    // ===== NON-WHITESPACE UNICODE SPACES (should NOT split) =====

    @Test
    public void testSplit_NonBreakingSpace() {
        // Non-breaking space (U+00A0) should NOT split
        List<String> result = Utils.splitOnAsciiWhitespace("hello\u00A0world");
        assertEquals(Arrays.asList("hello\u00A0world"), result);
    }

    @Test
    public void testSplit_ZeroWidthSpace() {
        // Zero-width space (U+200B) should NOT split
        List<String> result = Utils.splitOnAsciiWhitespace("hello\u200Bworld");
        assertEquals(Arrays.asList("hello\u200Bworld"), result);
    }
}