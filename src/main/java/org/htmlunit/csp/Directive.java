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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.function.Predicate;
import java.util.regex.Pattern;

/**
 * Base class for all CSP directive representations.
 * <p>
 * A {@code Directive} holds the list of raw string values that were parsed for a
 * single directive in a Content Security Policy. Subclasses interpret those
 * values into structured data (source expressions, sandbox keywords, etc.).
 * </p>
 */
public class Directive {

    /** Predicate that tests whether a string is a valid directive name ({@code ALPHA / DIGIT / "-"}). */
    public static final Predicate<String> IS_DIRECTIVE_NAME = Pattern.compile("^[A-Za-z0-9\\-]+$").asPredicate();

    private List<String> values_;

    /**
     * Tests if a string contains any non-directive characters.
     * Non-directive characters are: ASCII whitespace (tab, newline, form feed,
     * carriage return, space), comma, or semicolon.
     *
     * @param input the string to test (can be null)
     * @return true if the string contains any non-directive characters, false otherwise
     */
    public static boolean containsNonDirectiveCharacter(final String input) {
        if (input == null) {
            return false;
        }

        for (int i = 0; i < input.length(); i++) {
            final char c = input.charAt(i);
            if (Constants.isAsciiWhitespace(c) || c == ',' || c == ';') {
                return true;
            }
        }

        return false;
    }

    /**
     * Appends a value to this directive's value list.
     * <p>
     * The value must be a non-empty ASCII string that does not contain whitespace,
     * commas, or semicolons.
     * </p>
     *
     * @param value the value to add
     * @throws IllegalArgumentException if the value is empty, non-ASCII,
     *         or contains whitespace / comma / semicolon
     */
    protected void addValue(final String value) {
        Policy.enforceAscii(value);
        if (containsNonDirectiveCharacter(value)) {
            throw new IllegalArgumentException("values must not contain whitespace, ',', or ';'");
        }
        if (value.isEmpty()) {
            throw new IllegalArgumentException("values must not be empty");
        }
        values_.add(value);
    }

    /**
     * Returns an unmodifiable view of this directive's raw string values.
     *
     * @return the list of values for this directive
     */
    public List<String> getValues() {
        return Collections.unmodifiableList(values_);
    }

    /**
     * Constructs a directive with the given list of values.
     * <p>
     * Each value is validated through {@link #addValue(String)} during construction.
     * </p>
     *
     * @param values the raw string values for this directive
     * @throws IllegalArgumentException if any value is empty, non-ASCII,
     *         or contains whitespace / comma / semicolon
     */
    protected Directive(final List<String> values) {
        values_ = new ArrayList<>();
        for (final String value : values) {
            // We use this API so we get the validity checks
            addValue(value);
        }
    }

    /**
     * Removes all occurrences of a value from this directive (case-insensitive comparison).
     *
     * @param value the value to remove (compared case-insensitively)
     */
    protected void removeValueIgnoreCase(final String value) {
        final String lowercaseValue = value.toLowerCase(Locale.ROOT);

        // Could we use some fancy data structure to avoid the linear indexing here?
        // Yes, probably. But in practice these are short lists, and iterating them is not that expensive.
        final ArrayList<String> copy = new ArrayList<>(values_.size());
        for (final String existing : values_) {
            if (!existing.toLowerCase(Locale.ROOT).equals(lowercaseValue)) {
                copy.add(existing);
            }
        }
        values_ = copy;
    }

    /**
     * A callback interface for receiving errors and warnings encountered while
     * parsing a single directive's values.
     * <p>
     * A {@code valueIndex} of {@code -1} indicates the error does not pertain
     * to a specific value within the directive.
     * </p>
     */
    @FunctionalInterface
    public interface DirectiveErrorConsumer {
        /** A no-op consumer that silently ignores all errors. */
        DirectiveErrorConsumer ignored = (severity, message, valueIndex) -> { };

        /**
         * Called when a parsing error or warning is encountered.
         *
         * @param severity the severity of the issue
         * @param message a human-readable description of the issue
         * @param valueIndex the zero-based index of the value within the directive,
         *        or {@code -1} if the issue does not pertain to a specific value
         */
        void add(Policy.Severity severity, String message,
                int valueIndex); // index = -1 for errors not pertaining to a value

    }
}
