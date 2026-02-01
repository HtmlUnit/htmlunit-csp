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

Work on HtmlUnit-CSP 5.0 has started. This new major version will require **JDK 17 or higher**.


#### Legacy Support (JDK 8)

If you need to continue using **JDK 8**, please note that versions 4.x will remain available as-is. However,
**ongoing maintenance and fixes for JDK 8 compatibility are only available through sponsorship**.

Maintaining separate fix versions for JDK 8 requires significant additional effort for __backporting__, testing, and release management.

**To enable continued JDK 8 support**, please contact me via email to discuss sponsorship options. Sponsorship provides:

- __Backporting__ security and bug fixes to the 4.x branch
- Maintaining compatibility with older Java versions
- Timely releases for critical issues

Without sponsorship, the 4.x branch will not receive updates. Your support ensures the long-term __sustainability__ of this project across multiple Java versions.

### Latest release Version 4.21.0 / December 28, 2025

### Maven

Add to your `pom.xml`:

```xml
<dependency>
    <groupId>org.htmlunit</groupId>
    <artifactId>htmlunit-csp</artifactId>
    <version>4.21.0</version>
</dependency>
```

### Gradle

Add to your `build.gradle`:

```groovy
implementation group: 'org.htmlunit', name: 'htmlunit-csp', version: '4.21.0'
```

## Projects Using This Library

Beyond HtmlUnit itself, htmlunit-csp is used by various open-source projects for Content Security Policy parsing and validation:

### Security Tools
- **[OWASP ZAP (Zed Attack Proxy)](https://www.zaproxy.org/)** - The world's most widely used web application security scanner. ZAP uses htmlunit-csp in its [Content Security Policy Scan Rule](https://github.com/zaproxy/zap-extensions/blob/main/addOns/pscanrules/src/main/java/org/zaproxy/zap/extension/pscanrules/ContentSecurityPolicyScanRule.java) to analyze and validate CSP headers for security vulnerabilities.

### HTML Parsing and Validation
- **[Validator.nu](https://validator.nu/)** - An HTML5 validator and conformance checker that uses htmlunit-csp for validating Content Security Policy directives in web documents.

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

### Last CI build
The latest builds are available from our
[Jenkins CI build server](https://jenkins.wetator.org/job/HtmlUnit%20-%20CSS%20Parser/ "HtmlUnit - CSS Parser CI")

[![Build Status](https://jenkins.wetator.org/buildStatus/icon?job=HtmlUnit+-+CSP)](https://jenkins.wetator.org/job/HtmlUnit%20-%20CSP/)

If you use maven please add:

    <dependency>
        <groupId>org.htmlunit</groupId>
        <artifactId>htmlunit-csp</artifactId>
        <version>4.22.0-SNAPSHOT</version>
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

Pull Requests and and all other Community Contributions are essential for open source software.
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
    * fill the tag and title field with the release number (e.g. 4.0.0)
    * append 
        * htmlunit-csp-4.x.x.jar
        * htmlunit-csp-4.x.x.jar.asc 
        * htmlunit-csp-4.x.x.pom
        * htmlunit-csp-4.x.x.pom.asc 
        * htmlunit-csp-4.x.x-javadoc.jar
        * htmlunit-csp-4.x.x-javadoc.jar.asc
        * htmlunit-csp-4.x.x-sources.jar
        * htmlunit-csp-4.x.x-sources.jar.asc
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