/*
 * Copyright (c) 2023-2025 Ronald Brill.
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

public class PluginTypesDirective extends Directive {
    private final List<MediaType> mediaTypes_ = new ArrayList<>();

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

        if (type.getType().equals("*") || type.getSubtype().equals("*")) {
            errors.add(Policy.Severity.Warning,
                        "Media types can only be matched literally. Make sure using `*` is not an oversight.",
                        index);
        }
        mediaTypes_.add(type);
        return true;
    }

    public List<MediaType> getMediaTypes() {
        return Collections.unmodifiableList(mediaTypes_);
    }
}
