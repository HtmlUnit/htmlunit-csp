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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * {@link CspQueries#isFetchDirectiveUnrestricted} and {@link CspQueries#isBaseUriUnrestricted}.
 *
 * @author Rick Mitchell
 */
public class UnrestrictedQueriesTest extends TestBase {

    private static Policy policy(final String s) {
        return Policy.parseSerializedCSP(s, ThrowIfPolicyError);
    }

    private static PolicyList list(final String... s) {
        return PolicyList.ofSerialized(List.of(s), ThrowIfPolicyListError);
    }

    @Test
    public void missingIsUnrestricted() {
        final Policy p = policy("img-src 'self'");
        assertTrue(p.isFetchDirectiveUnrestricted(FetchDirectiveKind.ScriptSrc));
        assertTrue(p.isBaseUriUnrestricted());
    }

    @Test
    public void starIsUnrestricted() {
        final Policy p = policy("script-src *; base-uri *");
        assertTrue(p.isFetchDirectiveUnrestricted(FetchDirectiveKind.ScriptSrc));
        assertTrue(p.isBaseUriUnrestricted());
    }

    @Test
    public void restrictedIsNot() {
        final Policy p = policy("script-src 'self'; base-uri 'none'");
        assertFalse(p.isFetchDirectiveUnrestricted(FetchDirectiveKind.ScriptSrc));
        assertFalse(p.isBaseUriUnrestricted());
    }

    @Test
    public void followsFallbackChain() {
        final Policy p = policy("default-src 'self'");
        assertFalse(p.isFetchDirectiveUnrestricted(FetchDirectiveKind.ScriptSrcElem));
        assertFalse(p.isFetchDirectiveUnrestricted(FetchDirectiveKind.ImgSrc));
        final Policy q = policy("default-src 'self'; script-src *");
        assertTrue(q.isFetchDirectiveUnrestricted(FetchDirectiveKind.ScriptSrcElem));
        assertFalse(q.isFetchDirectiveUnrestricted(FetchDirectiveKind.ImgSrc));
    }

    @Test
    public void strictDynamicIgnoresStarForScriptKindsOnly() {
        final Policy p = policy("script-src * 'strict-dynamic' 'nonce-abc'");
        assertFalse(p.isFetchDirectiveUnrestricted(FetchDirectiveKind.ScriptSrcElem));
        assertFalse(p.isFetchDirectiveUnrestricted(FetchDirectiveKind.ScriptSrc));
        // no worker-src / child-src: script-src governs workers, so strict-dynamic applies
        assertFalse(p.isFetchDirectiveUnrestricted(FetchDirectiveKind.WorkerSrc));

        final Policy d = policy("default-src * 'strict-dynamic'");
        assertFalse(d.isFetchDirectiveUnrestricted(FetchDirectiveKind.ScriptSrcElem));
        assertTrue(d.isFetchDirectiveUnrestricted(FetchDirectiveKind.ImgSrc));

        assertFalse(list("script-src *", "script-src * 'strict-dynamic'")
                .isFetchDirectiveUnrestricted(FetchDirectiveKind.ScriptSrcElem));
    }

    @Test
    public void strictDynamicAppliesToWorkersWhicheverDirectiveGoverns() {
        // like browsers (Chrome, Firefox), not only for script-src as in CSP3
        assertFalse(policy("script-src * 'strict-dynamic'; worker-src * 'strict-dynamic'")
                .isFetchDirectiveUnrestricted(FetchDirectiveKind.WorkerSrc));
        assertFalse(policy("script-src *; child-src * 'strict-dynamic'")
                .isFetchDirectiveUnrestricted(FetchDirectiveKind.WorkerSrc));
        assertFalse(policy("default-src * 'strict-dynamic'")
                .isFetchDirectiveUnrestricted(FetchDirectiveKind.WorkerSrc));
        // a governing worker-src without the keyword wins over script-src
        assertTrue(policy("script-src * 'strict-dynamic'; worker-src *")
                .isFetchDirectiveUnrestricted(FetchDirectiveKind.WorkerSrc));
    }

    @Test
    public void baseUriDoesNotFallBackToDefaultSrc() {
        assertTrue(policy("default-src 'none'").isBaseUriUnrestricted());
    }

    @Test
    public void listRequiresEveryPolicyUnrestricted() {
        assertTrue(list().isFetchDirectiveUnrestricted(FetchDirectiveKind.ScriptSrc));
        assertTrue(list().isBaseUriUnrestricted());
        assertTrue(list("script-src *", "img-src 'self'")
                .isFetchDirectiveUnrestricted(FetchDirectiveKind.ScriptSrc));
        assertFalse(list("script-src *", "script-src 'self'")
                .isFetchDirectiveUnrestricted(FetchDirectiveKind.ScriptSrc));
        assertFalse(list("default-src *", "default-src 'self'")
                .isFetchDirectiveUnrestricted(FetchDirectiveKind.ImgSrc));
        assertTrue(list("default-src *", "script-src 'self'")
                .isFetchDirectiveUnrestricted(FetchDirectiveKind.ImgSrc));
        assertFalse(list("base-uri *", "base-uri 'self'").isBaseUriUnrestricted());
    }

    @Test
    public void nullKindThrows() {
        assertThrows(NullPointerException.class, () -> policy("").isFetchDirectiveUnrestricted(null));
        assertThrows(NullPointerException.class, () -> list().isFetchDirectiveUnrestricted(null));
    }
}
