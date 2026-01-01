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

/**
 * HtmlUnit Content Security Policy (CSP) parser and validator.
 * 
 * <p>This module provides functionality for:
 * <ul>
 *   <li>Parsing CSP policies from serialized strings</li>
 *   <li>Validating CSP policy syntax and semantics</li>
 *   <li>Querying CSP policies for allowed/restricted content</li>
 *   <li>Detecting deprecated or insecure CSP configurations</li>
 * </ul>
 *
 * @author Ronald Brill
 * @since 5.0
 */
module org.htmlunit.csp {
    exports org.htmlunit.csp;
    exports org.htmlunit.csp.directive;
    exports org.htmlunit.csp.value;
    exports org.htmlunit.csp.url;
}