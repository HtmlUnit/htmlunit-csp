# HtmlUnit - CSP

This is a general purpose library for working with Content Security Policy policies.

* parse CSP policies into an easy-to-use representation
* ask questions about what a CSP policy allows or restricts
* warn about nonsensical CSP policies and deprecated or nonstandard features

This is the code repository of the Content Security Policy support used by HtmlUnit.

The library was forked from the [salvation](https://github.com/shapesecurity/salvation) project, which is no longer actively maintained.  
The code has been adapted to match HtmlUnit's code style rules, and support for editing policies has been removed.  
The code is being expanded, restructured and improved primarily to meet the requirements of this project.

[![Maven Central Version](https://img.shields.io/maven-central/v/org.htmlunit/htmlunit-csp)](https://central.sonatype.com/artifact/org.htmlunit/htmlunit-csp)

:heart: [Sponsor](https://github.com/sponsors/rbri)

### Project News

**[Developer Blog](https://htmlunit.github.io/htmlunit-blog/)**

[HtmlUnit@mastodon](https://fosstodon.org/@HtmlUnit) | [HtmlUnit@bsky](https://bsky.app/profile/htmlunit.bsky.social) | [HtmlUnit@Twitter](https://twitter.com/HtmlUnit)

#### Version 5

Starting with version 5.0.0, **JDK 17 or higher is required**.  
If you are still on JDK 8, see [Legacy Support (JDK 8)](#legacy-support-jdk-8) below.


### Latest release Version 5.6.0 / October 11, 2026

### Maven

Add to your `pom.xml`:

```xml
<dependency>
    <groupId>org.htmlunit</groupId>
    <artifactId>htmlunit-csp</artifactId>
    <version>5.6.0</version>
</dependency>
```

### Gradle

Add to your `build.gradle`:

```groovy
implementation group: 'org.htmlunit', name: 'htmlunit-csp', version: '5.6.0'
```

## Projects Using This Library

Beyond HtmlUnit itself, htmlunit-csp is used by various open-source projects for Content Security Policy parsing and validation:

### Security Tools

- **[ZAP (Zed Attack Proxy)](https://www.zaproxy.org/)** - The world's most widely used web application security scanner. ZAP uses htmlunit-csp in its [Content Security Policy Scan Rule](https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/ContentSecurityPolicyScanRule.java) to analyze and validate CSP headers for security vulnerabilities.

### HTML Parsing and Validation
- **[The Nu Html Checker (vnu)](https://github.com/validator/validator/)** - An HTML conformance checker that uses htmlunit-csp for checking Content Security Policy directives in web documents.

If your project uses HtmlUnit-CSP, feel free to submit a pull request to add it to this list!

### A Note on CSP

The [CSP specification](https://www.w3.org/TR/CSP3/) is fairly complex even if you only care about the latest version. However, in practice you are likely to care that your policy does the things you intend it to on the browsers you care about, which are likely to implement different and potentially broken subsets of the specification (and potentially additional behavior which is not in the specification). And there are inevitable tradeoffs to be made regarding the size of your policy vs the security it provides.

As such, this project does not attempt to provide a one-size-fits-all way to manipulate a policy purely in terms of its effects - the full set of effects across all browsers is too vast to provide an effective API in general. It can help you build up a policy based on the directives and source-expressions you want, but to ensure your policy is correct, for your own definition of correct, there is no alternative to testing it on the real browsers you care about.


### Create a Policy

Parse a policy using either `Policy.parseSerializedCSP` or `Policy.parseSerializedCSPList`. The second parameter will be called for each warning or error.

```java
String policyText = "script-src 'none'";
Policy policy = Policy.parseSerializedCSP(policyText, (severity, message, directiveIndex, valueIndex) -> {
  System.err.println(severity.name() + " at directive " + directiveIndex + (valueIndex == -1 ? "" : " at value " + valueIndex) + ": " + message);
});
```

For a policy from a [`<meta http-equiv="Content-Security-Policy">`](https://html.spec.whatwg.org/multipage/semantics.html#attr-meta-http-equiv-content-security-policy) element, pass `true` as the third argument so that `frame-ancestors`, `sandbox`, and `report-uri` produce warnings (HTML requires that those directives must not appear in meta `content`, and browsers ignore them):

```java
Policy metaPolicy = Policy.parseSerializedCSP(metaContent, consumer, true);
```

Those three directives remain available via getters for analysis, but `allows*` methods ignore `frame-ancestors` and `sandbox` on meta-delivered policies (matching browser enforce after HTML strips them). See also [CSP3 meta element](https://w3c.github.io/webappsec-csp/#meta-element).

### Multiple Policies

Browsers do not conceptually merge multiple policies into a single policy. They independently evaluate each policy and allow an action only if every policy allows it ([CSP3 multiple policies](https://w3c.github.io/webappsec-csp/#multiple-policies)). Accordingly, this library preserves policies separately and evaluates queries across the collection (`PolicyList`, stopping at the first denying policy). An empty `PolicyList` is unrestricted: all `allows*` methods return `true`.

`Policy` and `PolicyList` share the enforcement query surface via `CspQueries`. Origin-bound helpers (`PolicyInOrigin` / `PolicyListInOrigin`) extend `CspQueriesInOrigin`, so new query methods belong on the interface (and one origin wrapper), not four copy-pasted classes.

```java
// Several Content-Security-Policy header values (each may itself be a comma-separated list)
PolicyList list = PolicyList.ofSerialized(List.of(
    "img-src img.example.com",
    "img-src more-images.example.com"
), Policy.PolicyListErrorConsumer.ignored);

PolicyListInOrigin bound = new PolicyListInOrigin(list, URI.parseURI("https://example.com").orElseThrow());

boolean allowed = bound.allowsImageFromSource(URI.parseURI("https://img.example.com/a.png").orElseThrow());
// allowed == false — second policy blocks even though first allows

// Or a single comma-separated header value:
PolicyList fromOneHeader = Policy.parseSerializedCSPList(
    "img-src 'self', script-src 'none'", Policy.PolicyListErrorConsumer.ignored);
```

Keep Report-Only policies in a separate `PolicyList`. Directive inspection and parse warnings stay per member policy via `getPolicies()`.

`ofSerialized` always parses as header delivery (`deliveredViaMeta = false`). For mixed header + meta, parse each `Policy` with the correct flag, then build the list:

```java
Policy headerPolicy = Policy.parseSerializedCSP(headerValue, consumer, false);
Policy metaPolicy = Policy.parseSerializedCSP(metaContent, consumer, true);
PolicyList enforce = new PolicyList(List.of(headerPolicy, metaPolicy));
```

### Query a Policy

The high-level querying methods allow you to specify whatever relevant information you have. The missing information will be assumed to be worst-case - that is, these methods will return `true` only if any object which matches the provided characteristics would be allowed, regardless of its other characteristics. 

```java
Policy policy = Policy.parseSerializedCSP("script-src http://a", Policy.PolicyErrorConsumer.ignored);

// true
System.out.println(policy.allowsExternalScript(
  Optional.empty(),
  Optional.empty(),
  URI.parse("http://a"),
  Optional.empty(),
  Optional.empty()
));

// false
System.out.println(policy.allowsExternalScript(
  Optional.empty(),
  Optional.empty(),
  Optional.empty(),
  Optional.empty(),
  Optional.empty()
));
```

Because the `Policy` objects are rich structures, you can also ask about the presence or absence of specific directives or expressions:

```java
Policy policy = Policy.parseSerializedCSP("script-src 'strict-dynamic'", Policy.PolicyErrorConsumer.ignored);

// Assumes the policy has a `script-src` directive (or else the `get` would throw), and checks if it contains the `'strict-dynamic'` source expression
System.out.println(policy.getFetchDirective(FetchDirectiveKind.ScriptSrc).get().strictDynamic());
```

#### Trusted Types

`Policy` and `PolicyList` (via `CspQueries`) answer Trusted Types questions without inspecting directives:

```java
Policy policy = Policy.parseSerializedCSP("require-trusted-types-for 'script'; trusted-types foo 'allow-duplicates'", Policy.PolicyErrorConsumer.ignored);

policy.enforcesTrustedTypesForScript();          // true: sinks require Trusted Types
policy.allowsTrustedTypesPolicyName("foo");      // true
policy.allowsTrustedTypesPolicyName("bar");      // false
policy.allowsAnyTrustedTypesPolicyName();        // false (only true without the directive, or with `*`)
policy.allowsDuplicateTrustedTypesPolicies();    // true
```

Semantics follow the [Trusted Types spec](https://w3c.github.io/trusted-types/dist/spec/#should-block-create-policy):

- A missing `trusted-types` directive allows every policy name and duplicates.
- An empty directive or a lone `'none'` allows no policy name. `'none'` combined with other values is ignored.
- `*` allows any name but does not imply `'allow-duplicates'`.
- Policy names are matched case-sensitively.

For a `PolicyList`, the `allows*` methods require every policy to allow, while `enforcesTrustedTypesForScript()` is true if any policy enforces.

`allowsAnyTrustedTypesPolicyName()` answers whether any name may be created. It differs from `Policy.allowsWildcardPolicyNames()`, which only reports whether the directive contains `*` and returns `false` when there is no directive.

`allowsDuplicateTrustedTypesPolicies()` only says whether the policy permits creating a name more than once. Tracking which names have already been created is up to the caller.

Browsers only block policy creation for enforced policies, so query a list built from `Content-Security-Policy` headers; Report-Only policies belong in a separate `PolicyList` (see [Multiple Policies](#multiple-policies)).

These queries do not depend on the document's origin, so `PolicyInOrigin` and `PolicyListInOrigin` do not wrap them; call them on `getQueries()`.

#### Fallback, `-elem` / `-attr` and eval keywords

`Policy.getGoverningDirectiveForEffectiveDirective(kind)` resolves the [CSP3 fallback list](https://www.w3.org/TR/CSP3/#directive-fallback-list):

| effective directive | chain |
| --- | --- |
| `script-src-elem`, `script-src-attr` | itself, `script-src`, `default-src` |
| `style-src-elem`, `style-src-attr` | itself, `style-src`, `default-src` |
| `worker-src` | itself, `child-src`, `script-src`, `default-src` |
| `frame-src` | itself, `child-src`, `default-src` (not `script-src`) |
| other fetch directives | itself, `default-src` |

CSP3 only defines chains for effective directives; the library also resolves `script-src`, `style-src`, `prefetch-src`, `child-src` (itself, `default-src`) and `default-src` for analysis. `script-src-elem` / `script-src-attr` never govern workers, `eval()` or WebAssembly: those use `script-src`, then `default-src`.

| query | allowed when the governing `script-src` / `default-src` ... |
| --- | --- |
| `allowsEval()` | is absent or has `'unsafe-eval'` |
| `allowsWasmEval()` | is absent or has `'wasm-unsafe-eval'` or `'unsafe-eval'` |
| `allowsTrustedTypesEval()` | is absent, has `'unsafe-eval'`, or has `'trusted-types-eval'` while `require-trusted-types-for 'script'` is enforced |

Keywords without an `allows*` query are exposed on `SourceExpressionDirective`: `trustedTypesEval()`, `unsafeWasm()`, `unsafeWebTransportHashes()` and `getReportHashAlgorithms()` (`'report-sha256'` / `384` / `512`, which only trigger `csp-hash` reports and never affect enforcement). Putting a keyword where it has no effect produces a parse warning: an eval or WebTransport keyword in a directive that never consults it (or in `default-src` when `script-src` / `connect-src` governs instead), or a `'report-sha*'` keyword in a directive that does not impact script-like destinations. If several `'report-sha*'` keywords are present, the browser reports with the strongest one.

`allowsWebTransportWithCertificateHashes()` covers `'unsafe-webtransport-hashes'`: WebTransport connections using `serverCertificateHashes` are allowed only if the governing `connect-src` (else `default-src`) contains the keyword, or neither exists.

`'trusted-types-eval'` only lets a `TrustedScript` through, so `allowsEval()` (plain strings) stays `false` for it. In a `PolicyList` the enforcement is evaluated over the whole list, as in CSP3, so `script-src 'trusted-types-eval'` in one policy is activated by `require-trusted-types-for 'script'` in another. As in the spec, only *enforced* policies count towards that requirement; the library has no per-policy disposition, so for a Report-Only `PolicyList` `allowsTrustedTypesEval()` can differ from a browser in either direction (it ignores an enforced `require-trusted-types-for`, and counts a Report-Only one). Pass the enforced list's answer instead: `reportOnly.allowsTrustedTypesEval(enforced.enforcesTrustedTypesForScript())`.

<a name="legacy-support-jdk-8"></a>
### Legacy Support (JDK 8)

If you need to continue using **JDK 8**, versions 4.x remain available as-is.
Ongoing maintenance and fixes for JDK 8 are only available through sponsorship —
please contact me via email to discuss options. Sponsorship provides:

- Backporting security and bug fixes to the 4.x branch
- Compatibility maintenance with older Java versions
- Timely releases for critical issues

Without sponsorship, the 4.x branch will not receive further updates.


### Last CI build
The latest builds are available from our
[Jenkins CI build server](https://jenkins.wetator.org/job/HtmlUnit%20-%20CSP/ "HtmlUnit - CSP CI")

[![Build Status](https://jenkins.wetator.org/buildStatus/icon?job=HtmlUnit+-+CSP)](https://jenkins.wetator.org/job/HtmlUnit%20-%20CSP/)

If you use maven please add:

    <dependency>
        <groupId>org.htmlunit</groupId>
        <artifactId>htmlunit-csp</artifactId>
        <version>5.7.0-SNAPSHOT</version>
    </dependency>

You have to add the sonatype-central snapshot repository to your pom `repositories` section also:

    <repositories>
        <repository>
            <name>Central Portal Snapshots</name>
            <id>central-portal-snapshots</id>
            <url>https://central.sonatype.com/repository/maven-snapshots/</url>
            <releases>
                <enabled>false</enabled>
            </releases>
            <snapshots>
                <enabled>true</enabled>
            </snapshots>
        </repository>
    </repositories>


## Start HtmlUnit - CSP Development

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.
See deployment for notes on how to deploy the project on a live system.

### Prerequisites

You need:
* Java 17 or later
* A local Maven installation

### Building

Create a local clone of the repository and you are ready to start.

Open a command line window from the root folder of the project and call

```
mvn compile
```

### Running the tests

```
mvn test
```

## Contributing

Pull Requests and all other Community Contributions are essential for open source software.
Every contribution - from bug reports to feature requests, typos to full new features - are greatly appreciated.

## Deployment and Versioning

This part is intended for committer who are packaging a release.

* Check all your files are checked in
* Execute these mvn commands to be sure all tests are passing and everything is up to data

```
   mvn versions:display-plugin-updates
   mvn versions:display-dependency-updates
   mvn -U clean test
```

* Update the version number in pom.xml and README.md
* Commit the changes


* Build and deploy the artifacts 

```
   mvn -up clean deploy
```

* Go to [Maven Central Portal](https://central.sonatype.com/) and process the deploy
  - publish the package and wait until it is processed

* Create the version on Github
    * login to Github and open project https://github.com/HtmlUnit/htmlunit-csp
    * click Releases > Draft new release
    * fill the tag and title field with the release number (e.g. 5.0.0)
    * append 
        * htmlunit-csp-5.x.x.jar
        * htmlunit-csp-5.x.x.jar.asc 
        * htmlunit-csp-5.x.x.pom
        * htmlunit-csp-5.x.x.pom.asc 
        * htmlunit-csp-5.x.x-javadoc.jar
        * htmlunit-csp-5.x.x-javadoc.jar.asc
        * htmlunit-csp-5.x.x-sources.jar
        * htmlunit-csp-5.x.x-sources.jar.asc
    * and publish the release 

* Update the version number in pom.xml to start next snapshot development
* Update the htmlunit pom to use the new release

## Authors

* **RBRi**
* all the contributors to [salvation](https://github.com/shapesecurity/salvation)

## License

This project is licensed under the Apache 2.0 License

## Acknowledgments

Many thanks to all of you contributing to [salvation](https://github.com/shapesecurity/salvation) in the past.

### Development Tools

Special thanks to:

<a href="https://www.jetbrains.com/community/opensource/"><img src="https://resources.jetbrains.com/storage/products/company/brand/logos/jb_beam.svg" alt="JetBrains" width="42"></a>
<a href="https://www.jetbrains.com/idea/"><img src="https://resources.jetbrains.com/storage/products/company/brand/logos/IntelliJ_IDEA_icon.svg" alt="IntelliJ IDEA" width="42"></a>  
**[JetBrains](https://www.jetbrains.com/)** for providing IntelliJ IDEA under their [open source development license](https://www.jetbrains.com/community/opensource/) and

<a href="https://www.eclipse.org/"><img src="https://www.eclipse.org/eclipse.org-common/themes/solstice/public/images/logo/eclipse-foundation-grey-orange.svg" alt="Eclipse Foundation" width="80"></a>  
Eclipse Foundation for their Eclipse IDE

<a href="https://www.syntevo.com/smartgit/"><img src="https://www.syntevo.com/assets/images/logos/smartgit-8c1aa1e2.svg" alt="SmartGit" width="54"></a>  
to **[Syntevo](https://www.syntevo.com/)** for their excellent [SmartGit](https://www.smartgit.dev/)!
