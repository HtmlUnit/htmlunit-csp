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
package org.htmlunit.csp.directive;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import org.htmlunit.csp.Directive;
import org.htmlunit.csp.Policy;
import org.htmlunit.csp.value.MediaType;

/**
 * Represents the (deprecated) {@code plugin-types} CSP directive.
 * <p>
 * The {@code plugin-types} directive restricts the set of plugins that can be
 * embedded via {@code <object>}, {@code <embed>}, or {@code <applet>} by
 * specifying an allow-list of media types. Note that this directive has been
 * deprecated and is no longer supported by most browsers.
 * </p>
 *
 * @see <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/plugin-types">
 *      plugin-types on MDN</a>
 */
public class PluginTypesDirective extends Directive {
    private final List<MediaType> mediaTypes_ = new ArrayList<>();

    /**
     * Parses a {@code plugin-types} directive from the given list of media-type values.
     * <p>
     * Each token is parsed as a media type ({@code type/subtype}). Invalid tokens
     * and duplicates are reported through the supplied {@code errors} consumer.
     * Note that empty lists are allowed per
     * <a href="https://github.com/w3c/webappsec-csp/pull/374">w3c/webappsec-csp#374</a>.
     * </p>
     *
     * @param values the raw string values for this directive
     * @param errors consumer that receives parsing errors and warnings
     */
    public PluginTypesDirective(final List<String> values, final DirectiveErrorConsumer errors) {
        super(values);

        int index = 0;
        for (final String token : values) {
            final Optional<MediaType> type = MediaType.parseMediaType(token);
            if (type.isPresent()) {
                addMediaType(type.get(), index, errors);
            }
            else {
                errors.add(Policy.Severity.Error, "Expecting media-type but found \"" + token + "\"", index);
            }
            index++;
        }

        // Note that empty lists are allowed: https://github.com/w3c/webappsec-csp/pull/374
    }

    private boolean addMediaType(final MediaType type, final int index, final DirectiveErrorConsumer errors) {
        if (mediaTypes_.contains(type)) {
            errors.add(Policy.Severity.Warning, "Duplicate media type " + type.toString(), index);
            return false;
        }

        if ("*".equals(type.type()) || "*".equals(type.subtype())) {
            errors.add(Policy.Severity.Warning,
                        "Media types can only be matched literally. Make sure using `*` is not an oversight.",
                        index);
        }
        mediaTypes_.add(type);
        return true;
    }

    /**
     * Returns an unmodifiable list of the media types allowed by this directive.
     *
     * @return the list of parsed {@link MediaType} values
     */
    public List<MediaType> getMediaTypes() {
        return Collections.unmodifiableList(mediaTypes_);
    }
}
