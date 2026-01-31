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

import org.htmlunit.csp.Policy.PolicyErrorConsumer;
import org.htmlunit.csp.url.URI;
import org.htmlunit.csp.value.Scheme;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ReadmeTest extends TestBase {

    @Test
    public void createPolicy() {
        String policyText = "script-src 'none'";
        Policy policy = Policy.parseSerializedCSP(policyText, (severity, message, directiveIndex, valueIndex) -> {
            System.err.println(severity.name() + " at directive " + directiveIndex + (valueIndex == -1 ? "" : " at value " + valueIndex) + ": " + message);
        });
    }

    @Test
    public void queryPolicy() {
        Policy policy = Policy.parseSerializedCSP("script-src http://a", Policy.PolicyErrorConsumer.ignored);

        System.out.println(policy.allowsExternalScript(
                Optional.empty(),
                Optional.empty(),
                URI.parseURI("http://a"),
                Optional.empty(),
                Optional.empty()
        ));
        System.out.println(policy.allowsExternalScript(
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty()
        ));
    }

    @Test
    public void queryPolicy2() {
        Policy policy = Policy.parseSerializedCSP("script-src 'strict-dynamic'", Policy.PolicyErrorConsumer.ignored);

        // Assumes the policy has a `script-src` directive (or else the `get` would throw),
        // and checks if it contains the `'strict-dynamic'` source expression
        System.out.println(policy.getFetchDirective(FetchDirectiveKind.ScriptSrc).get().strictDynamic());    }
}
