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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class DirectiveContainsNonDirectiveCharacterTest {

    // ===== NULL AND EMPTY TESTS =====

    @Test
    public void testContainsNonDirectiveCharacter_Null() {
        assertFalse(Directive.containsNonDirectiveCharacter(null));
    }

    @Test
    public void testContainsNonDirectiveCharacter_EmptyString() {
        assertFalse(Directive.containsNonDirectiveCharacter(""));
    }

    // ===== NO NON-DIRECTIVE CHARACTERS =====

    @Test
    public void testContainsNonDirectiveCharacter_PlainText() {
        assertFalse(Directive.containsNonDirectiveCharacter("hello"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_SingleCharacter() {
        assertFalse(Directive.containsNonDirectiveCharacter("x"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_Alphanumeric() {
        assertFalse(Directive.containsNonDirectiveCharacter("abc123"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_SpecialCharactersAllowed() {
        assertFalse(Directive.containsNonDirectiveCharacter("hello-world_test.file"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_PunctuationAllowed() {
        assertFalse(Directive.containsNonDirectiveCharacter("hello!world?"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_AllLetters() {
        assertFalse(Directive.containsNonDirectiveCharacter("abcdefghijklmnopqrstuvwxyz"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_AllNumbers() {
        assertFalse(Directive.containsNonDirectiveCharacter("0123456789"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_MixedCase() {
        assertFalse(Directive.containsNonDirectiveCharacter("HelloWorld"));
    }

    // ===== WHITESPACE TESTS (should return true) =====

    @Test
    public void testContainsNonDirectiveCharacter_Space() {
        assertTrue(Directive.containsNonDirectiveCharacter("hello world"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_LeadingSpace() {
        assertTrue(Directive.containsNonDirectiveCharacter(" hello"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_TrailingSpace() {
        assertTrue(Directive.containsNonDirectiveCharacter("hello "));
    }

    @Test
    public void testContainsNonDirectiveCharacter_OnlySpace() {
        assertTrue(Directive.containsNonDirectiveCharacter(" "));
    }

    @Test
    public void testContainsNonDirectiveCharacter_MultipleSpaces() {
        assertTrue(Directive.containsNonDirectiveCharacter("   "));
    }

    @Test
    public void testContainsNonDirectiveCharacter_Tab() {
        assertTrue(Directive.containsNonDirectiveCharacter("hello\tworld"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_OnlyTab() {
        assertTrue(Directive.containsNonDirectiveCharacter("\t"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_LeadingTab() {
        assertTrue(Directive.containsNonDirectiveCharacter("\thello"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_TrailingTab() {
        assertTrue(Directive.containsNonDirectiveCharacter("hello\t"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_Newline() {
        assertTrue(Directive.containsNonDirectiveCharacter("hello\nworld"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_OnlyNewline() {
        assertTrue(Directive.containsNonDirectiveCharacter("\n"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_LeadingNewline() {
        assertTrue(Directive.containsNonDirectiveCharacter("\nhello"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_TrailingNewline() {
        assertTrue(Directive.containsNonDirectiveCharacter("hello\n"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_CarriageReturn() {
        assertTrue(Directive.containsNonDirectiveCharacter("hello\rworld"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_OnlyCarriageReturn() {
        assertTrue(Directive.containsNonDirectiveCharacter("\r"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_LeadingCarriageReturn() {
        assertTrue(Directive.containsNonDirectiveCharacter("\rhello"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_TrailingCarriageReturn() {
        assertTrue(Directive.containsNonDirectiveCharacter("hello\r"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_FormFeed() {
        assertTrue(Directive.containsNonDirectiveCharacter("hello\fworld"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_OnlyFormFeed() {
        assertTrue(Directive.containsNonDirectiveCharacter("\f"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_LeadingFormFeed() {
        assertTrue(Directive.containsNonDirectiveCharacter("\fhello"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_TrailingFormFeed() {
        assertTrue(Directive.containsNonDirectiveCharacter("hello\f"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_MixedWhitespace() {
        assertTrue(Directive.containsNonDirectiveCharacter("hello \t\n\r\fworld"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_AllWhitespaceTypes() {
        assertTrue(Directive.containsNonDirectiveCharacter(" \t\n\r\f"));
    }

    // ===== COMMA TESTS (should return true) =====

    @Test
    public void testContainsNonDirectiveCharacter_Comma() {
        assertTrue(Directive.containsNonDirectiveCharacter("hello,world"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_LeadingComma() {
        assertTrue(Directive.containsNonDirectiveCharacter(",hello"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_TrailingComma() {
        assertTrue(Directive.containsNonDirectiveCharacter("hello,"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_OnlyComma() {
        assertTrue(Directive.containsNonDirectiveCharacter(","));
    }

    @Test
    public void testContainsNonDirectiveCharacter_MultipleCommas() {
        assertTrue(Directive.containsNonDirectiveCharacter("a,b,c"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_CommaWithSpace() {
        assertTrue(Directive.containsNonDirectiveCharacter("hello, world"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_ConsecutiveCommas() {
        assertTrue(Directive.containsNonDirectiveCharacter("hello,,world"));
    }

    // ===== SEMICOLON TESTS (should return true) =====

    @Test
    public void testContainsNonDirectiveCharacter_Semicolon() {
        assertTrue(Directive.containsNonDirectiveCharacter("hello;world"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_LeadingSemicolon() {
        assertTrue(Directive.containsNonDirectiveCharacter(";hello"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_TrailingSemicolon() {
        assertTrue(Directive.containsNonDirectiveCharacter("hello;"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_OnlySemicolon() {
        assertTrue(Directive.containsNonDirectiveCharacter(";"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_MultipleSemicolons() {
        assertTrue(Directive.containsNonDirectiveCharacter("a;b;c"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_SemicolonWithSpace() {
        assertTrue(Directive.containsNonDirectiveCharacter("hello; world"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_ConsecutiveSemicolons() {
        assertTrue(Directive.containsNonDirectiveCharacter("hello;;world"));
    }

    // ===== COMBINATION TESTS =====

    @Test
    public void testContainsNonDirectiveCharacter_CommaAndSemicolon() {
        assertTrue(Directive.containsNonDirectiveCharacter("hello,world;test"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_AllNonDirectiveChars() {
        assertTrue(Directive.containsNonDirectiveCharacter("hello world,test;done"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_SpaceAndComma() {
        assertTrue(Directive.containsNonDirectiveCharacter("a, b, c"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_SpaceAndSemicolon() {
        assertTrue(Directive.containsNonDirectiveCharacter("a; b; c"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_TabAndComma() {
        assertTrue(Directive.containsNonDirectiveCharacter("hello\t,world"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_NewlineAndSemicolon() {
        assertTrue(Directive.containsNonDirectiveCharacter("hello\n;world"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_AllThreeTypes() {
        assertTrue(Directive.containsNonDirectiveCharacter("a b,c;d"));
    }

    // ===== POSITION TESTS =====

    @Test
    public void testContainsNonDirectiveCharacter_FirstCharacterIsSpace() {
        assertTrue(Directive.containsNonDirectiveCharacter(" abc"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_LastCharacterIsSpace() {
        assertTrue(Directive.containsNonDirectiveCharacter("abc "));
    }

    @Test
    public void testContainsNonDirectiveCharacter_MiddleCharacterIsSpace() {
        assertTrue(Directive.containsNonDirectiveCharacter("ab c"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_SecondCharacterIsSpace() {
        assertTrue(Directive.containsNonDirectiveCharacter("a bcd"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_FirstCharacterIsComma() {
        assertTrue(Directive.containsNonDirectiveCharacter(",abc"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_LastCharacterIsComma() {
        assertTrue(Directive.containsNonDirectiveCharacter("abc,"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_MiddleCharacterIsComma() {
        assertTrue(Directive.containsNonDirectiveCharacter("ab,c"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_FirstCharacterIsSemicolon() {
        assertTrue(Directive.containsNonDirectiveCharacter(";abc"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_LastCharacterIsSemicolon() {
        assertTrue(Directive.containsNonDirectiveCharacter("abc;"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_MiddleCharacterIsSemicolon() {
        assertTrue(Directive.containsNonDirectiveCharacter("ab;c"));
    }

    // ===== UNICODE TESTS =====

    @Test
    public void testContainsNonDirectiveCharacter_UnicodeNoNonDirective() {
        assertFalse(Directive.containsNonDirectiveCharacter("日本語"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_UnicodeWithSpace() {
        assertTrue(Directive.containsNonDirectiveCharacter("日本 語"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_UnicodeWithComma() {
        assertTrue(Directive.containsNonDirectiveCharacter("日本,語"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_UnicodeWithSemicolon() {
        assertTrue(Directive.containsNonDirectiveCharacter("日本;語"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_EmojiNoNonDirective() {
        assertFalse(Directive.containsNonDirectiveCharacter("😀😁😂"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_EmojiWithSpace() {
        assertTrue(Directive.containsNonDirectiveCharacter("😀 😁"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_AccentedCharacters() {
        assertFalse(Directive.containsNonDirectiveCharacter("café"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_AccentedWithComma() {
        assertTrue(Directive.containsNonDirectiveCharacter("café,résumé"));
    }

    // ===== SPECIAL CHARACTERS THAT SHOULD NOT TRIGGER =====

    @Test
    public void testContainsNonDirectiveCharacter_Period() {
        assertFalse(Directive.containsNonDirectiveCharacter("hello.world"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_Hyphen() {
        assertFalse(Directive.containsNonDirectiveCharacter("hello-world"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_Underscore() {
        assertFalse(Directive.containsNonDirectiveCharacter("hello_world"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_Slash() {
        assertFalse(Directive.containsNonDirectiveCharacter("hello/world"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_Backslash() {
        assertFalse(Directive.containsNonDirectiveCharacter("hello\\world"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_Colon() {
        assertFalse(Directive.containsNonDirectiveCharacter("hello:world"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_AtSign() {
        assertFalse(Directive.containsNonDirectiveCharacter("hello@world"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_Equals() {
        assertFalse(Directive.containsNonDirectiveCharacter("key=value"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_QuestionMark() {
        assertFalse(Directive.containsNonDirectiveCharacter("hello?world"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_ExclamationMark() {
        assertFalse(Directive.containsNonDirectiveCharacter("hello!world"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_Parentheses() {
        assertFalse(Directive.containsNonDirectiveCharacter("hello(world)"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_Brackets() {
        assertFalse(Directive.containsNonDirectiveCharacter("hello[world]"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_Braces() {
        assertFalse(Directive.containsNonDirectiveCharacter("hello{world}"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_Quotes() {
        assertFalse(Directive.containsNonDirectiveCharacter("\"hello\""));
    }

    @Test
    public void testContainsNonDirectiveCharacter_Apostrophe() {
        assertFalse(Directive.containsNonDirectiveCharacter("don't"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_Ampersand() {
        assertFalse(Directive.containsNonDirectiveCharacter("hello&world"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_Percent() {
        assertFalse(Directive.containsNonDirectiveCharacter("100%"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_Dollar() {
        assertFalse(Directive.containsNonDirectiveCharacter("$100"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_Hash() {
        assertFalse(Directive.containsNonDirectiveCharacter("#hashtag"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_Asterisk() {
        assertFalse(Directive.containsNonDirectiveCharacter("hello*world"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_Plus() {
        assertFalse(Directive.containsNonDirectiveCharacter("1+1"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_LessThan() {
        assertFalse(Directive.containsNonDirectiveCharacter("<html>"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_GreaterThan() {
        assertFalse(Directive.containsNonDirectiveCharacter("</html>"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_Pipe() {
        assertFalse(Directive.containsNonDirectiveCharacter("hello|world"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_Tilde() {
        assertFalse(Directive.containsNonDirectiveCharacter("~user"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_Backtick() {
        assertFalse(Directive.containsNonDirectiveCharacter("`code`"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_Caret() {
        assertFalse(Directive.containsNonDirectiveCharacter("2^3"));
    }

    // ===== REAL-WORLD SCENARIOS =====

    @Test
    public void testContainsNonDirectiveCharacter_HttpDirective() {
        assertFalse(Directive.containsNonDirectiveCharacter("max-age=3600"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_HttpDirectiveList() {
        assertTrue(Directive.containsNonDirectiveCharacter("no-cache, no-store"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_CacheControlSingle() {
        assertFalse(Directive.containsNonDirectiveCharacter("no-cache"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_CacheControlMultiple() {
        assertTrue(Directive.containsNonDirectiveCharacter("no-cache,must-revalidate"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_Url() {
        assertFalse(Directive.containsNonDirectiveCharacter("https://example.com/path"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_FileName() {
        assertFalse(Directive.containsNonDirectiveCharacter("document.pdf"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_FilePath() {
        assertFalse(Directive.containsNonDirectiveCharacter("/usr/local/bin"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_EmailAddress() {
        assertFalse(Directive.containsNonDirectiveCharacter("user@example.com"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_IpAddress() {
        assertFalse(Directive.containsNonDirectiveCharacter("192.168.1.1"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_CssClass() {
        assertFalse(Directive.containsNonDirectiveCharacter("btn-primary"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_JsonKey() {
        assertFalse(Directive.containsNonDirectiveCharacter("userName"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_Base64() {
        assertFalse(Directive.containsNonDirectiveCharacter("SGVsbG8gV29ybGQ="));
    }

    @Test
    public void testContainsNonDirectiveCharacter_HexColor() {
        assertFalse(Directive.containsNonDirectiveCharacter("#FF5733"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_Uuid() {
        assertFalse(Directive.containsNonDirectiveCharacter("550e8400-e29b-41d4-a716-446655440000"));
    }

    // ===== EDGE CASES =====

    @Test
    public void testContainsNonDirectiveCharacter_VeryLongStringNoMatch() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 10000; i++) {
            sb.append("a");
        }
        assertFalse(Directive.containsNonDirectiveCharacter(sb.toString()));
    }

    @Test
    public void testContainsNonDirectiveCharacter_VeryLongStringWithMatchAtEnd() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 10000; i++) {
            sb.append("a");
        }
        sb.append(" ");
        assertTrue(Directive.containsNonDirectiveCharacter(sb.toString()));
    }

    @Test
    public void testContainsNonDirectiveCharacter_VeryLongStringWithMatchAtStart() {
        StringBuilder sb = new StringBuilder();
        sb.append(" ");
        for (int i = 0; i < 10000; i++) {
            sb.append("a");
        }
        assertTrue(Directive.containsNonDirectiveCharacter(sb.toString()));
    }

    @Test
    public void testContainsNonDirectiveCharacter_VeryLongStringWithMatchInMiddle() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 5000; i++) {
            sb.append("a");
        }
        sb.append(",");
        for (int i = 0; i < 5000; i++) {
            sb.append("b");
        }
        assertTrue(Directive.containsNonDirectiveCharacter(sb.toString()));
    }

    @Test
    public void testContainsNonDirectiveCharacter_OnlyAllowedSpecialChars() {
        assertFalse(Directive.containsNonDirectiveCharacter("!@#$%^&*()_+-=[]{}|:<>?/\\"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_TwoCharacters() {
        assertFalse(Directive.containsNonDirectiveCharacter("ab"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_TwoCharactersWithSpace() {
        assertTrue(Directive.containsNonDirectiveCharacter("a b"));
    }

    // ===== NON-ASCII WHITESPACE (should NOT trigger) =====

    @Test
    public void testContainsNonDirectiveCharacter_NonBreakingSpace() {
        // Non-breaking space (U+00A0) is NOT ASCII whitespace
        assertFalse(Directive.containsNonDirectiveCharacter("hello\u00A0world"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_ZeroWidthSpace() {
        // Zero-width space (U+200B) is NOT ASCII whitespace
        assertFalse(Directive.containsNonDirectiveCharacter("hello\u200Bworld"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_VerticalTab() {
        // Vertical tab (U+000B) is NOT in our ASCII whitespace set
        assertFalse(Directive.containsNonDirectiveCharacter("hello\u000Bworld"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_EnSpace() {
        // En space (U+2002) is NOT ASCII whitespace
        assertFalse(Directive.containsNonDirectiveCharacter("hello\u2002world"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_EmSpace() {
        // Em space (U+2003) is NOT ASCII whitespace
        assertFalse(Directive.containsNonDirectiveCharacter("hello\u2003world"));
    }

    // ===== LINE ENDING TESTS =====

    @Test
    public void testContainsNonDirectiveCharacter_WindowsLineEnding() {
        assertTrue(Directive.containsNonDirectiveCharacter("hello\r\nworld"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_UnixLineEnding() {
        assertTrue(Directive.containsNonDirectiveCharacter("hello\nworld"));
    }

    @Test
    public void testContainsNonDirectiveCharacter_MacLineEnding() {
        assertTrue(Directive.containsNonDirectiveCharacter("hello\rworld"));
    }
}