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
 * A convenience wrapper that pairs a {@link PolicyList} with its
 * {@link URLWithScheme origin}. Query methods are defined on
 * {@link CspQueriesInOrigin}; AND semantics come from {@link PolicyList}.
 *
 * @author Ronald Brill
 * @see CspQueriesInOrigin
 * @see PolicyInOrigin
 * @see PolicyList
 * @since 5.4.0
 */
public class PolicyListInOrigin extends CspQueriesInOrigin {

    /**
     * Ctor.
     *
     * @param policyList the Content Security Policy list to query against
     * @param origin the origin of the protected resource
     */
    public PolicyListInOrigin(final PolicyList policyList, final URLWithScheme origin) {
        super(policyList, origin);
    }

    /**
     * Returns the underlying {@link PolicyList}.
     *
     * @return the policy list associated with this origin-bound wrapper
     */
    public PolicyList getPolicyList() {
        return (PolicyList) getQueries();
    }
}
