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

import org.htmlunit.csp.url.URLWithScheme;

/**
 * A convenience wrapper that pairs a {@link Policy} with its
 * {@link URLWithScheme origin}, providing simplified query methods that
 * automatically supply the origin to the underlying policy checks.
 * <p>
 * Each {@code allows*} method is defined on {@link CspQueriesInOrigin} and
 * delegates to {@link Policy} ({@link CspQueries}), filling in
 * {@code Optional.of(origin)} for the origin parameter and
 * {@code Optional.empty()} for unused parameters (nonce, integrity, redirects).
 * </p>
 *
 * @author Ronald Brill
 * @see CspQueriesInOrigin
 * @see PolicyListInOrigin
 */
public class PolicyInOrigin extends CspQueriesInOrigin {

    /**
     * Ctor.
     *
     * @param policy the Content Security Policy to query against
     * @param origin the origin of the protected resource
     */
    public PolicyInOrigin(final Policy policy, final URLWithScheme origin) {
        super(policy, origin);
    }

    /**
     * Returns the underlying {@link Policy}.
     *
     * @return the policy associated with this origin-bound wrapper
     */
    public Policy getPolicy() {
        return (Policy) getQueries();
    }
}
