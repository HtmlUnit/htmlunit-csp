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

public class Directive {
    /** IS_DIRECTIVE_NAME. */
    public static final Predicate<String> IS_DIRECTIVE_NAME = Pattern.compile("^[A-Za-z0-9\\-]+$").asPredicate();
    /** containsNonDirectiveCharacter. */
    public static final Predicate<String> containsNonDirectiveCharacter
                    = Pattern.compile("[" + Constants.WHITESPACE_CHARS + ",;]").asPredicate();
    private List<String> values_;

    protected void addValue(final String value) {
        Policy.enforceAscii(value);
        if (containsNonDirectiveCharacter.test(value)) {
            throw new IllegalArgumentException("values must not contain whitespace, ',', or ';'");
        }
        if (value.isEmpty()) {
            throw new IllegalArgumentException("values must not be empty");
        }
        values_.add(value);
    }

    public List<String> getValues() {
        return Collections.unmodifiableList(values_);
    }

    protected Directive(final List<String> values) {
        values_ = new ArrayList<>();
        for (final String value : values) {
            // We use this API so we get the validity checks
            addValue(value);
        }
    }

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

    protected void removeValueExact(final String value) {
        values_.remove(value);
    }

    @FunctionalInterface
    public interface DirectiveErrorConsumer {
        /** ignored. */
        DirectiveErrorConsumer ignored = (severity, message, valueIndex) -> { };

        void add(Policy.Severity severity, String message,
                int valueIndex); // index = -1 for errors not pertaining to a value

    }

    /** ManipulationErrorConsumer. */
    @FunctionalInterface
    public interface ManipulationErrorConsumer {
        /** ignored. */
        ManipulationErrorConsumer ignored = (severity, message) -> { };

        void add(Severity severity, String message);

        /** Severity. */
        enum Severity {
            /** Info. */
            Info,
            /** Warning. */
            Warning
        }
    }
}
