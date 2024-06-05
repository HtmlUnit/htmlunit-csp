# HtmlUnit - CSP

This is a general purpose library for working with Content Security Policy policies.

* parse CSP policies into an easy-to-use representation
* ask questions about what a CSP policy allows or restricts
* warn about nonsensical CSP policies and deprecated or nonstandard features

This is the code repository of the Content Security Policy support used by HtmlUnit.

The library was created by forking the [salvation][5] project as it is apparently no longer maintained.  
For HtmlUnit, the code has been adapted to the code style rules used, and support for editing policies has been removed.  
The code is being expanded, restructured and improved primarily to meet the requirements of this project.

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/org.htmlunit/htmlunit-csp/badge.svg)](https://maven-badges.herokuapp.com/maven-central/org.htmlunit/htmlunit-csp)

:heart: [Sponsor](https://github.com/sponsors/rbri)

### Project News

[HtmlUnit@mastodon][4] | [HtmlUnit@Twitter][3]

### Latest release Version 4.2.0 / June 05, 2024

### Maven

Add to your `pom.xml`:

```xml
<dependency>
    <groupId>org.htmlunit</groupId>
    <artifactId>htmlunit-csp</artifactId>
    <version>4.2.0</version>
</dependency>
```

### Gradle

Add to your `build.gradle`:

```groovy
implementation group: 'org.htmlunit', name: 'htmlunit-csp', version: '4.2.0'
```

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
  Optional.of(URI.parse("http://a")),
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
[Jenkins CI build server][2]

[![Build Status](https://jenkins.wetator.org/buildStatus/icon?job=HtmlUnit+-+CSP)](https://jenkins.wetator.org/job/HtmlUnit%20-%20CSP/)

If you use maven please add:

    <dependency>
        <groupId>org.htmlunit</groupId>
        <artifactId>htmlunit-csp</artifactId>
        <version>4.3.0-SNAPSHOT</version>
    </dependency>

You have to add the sonatype snapshot repository to your pom `repositories` section also:

    <repository>
        <id>OSS Sonatype snapshots</id>
        <url>https://s01.oss.sonatype.org/content/repositories/snapshots/</url>
        <snapshots>
            <enabled>true</enabled>
            <updatePolicy>always</updatePolicy>
        </snapshots>
        <releases>
            <enabled>false</enabled>
        </releases>
    </repository>


## Start HtmlUnit - CSP Development

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.
See deployment for notes on how to deploy the project on a live system.

### Prerequisites

You simply only need a local maven installation.


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

* Go to [Sonatype staging repositories](https://s01.oss.sonatype.org/index.html#stagingRepositories) and process the deploy
  - select the repository and close it - wait until the close is processed
  - release the package and wait until it is processed

* Create the version on Github
    * login to Github and open project https://github.com/HtmlUnit/htmlunit-csp
    * click Releases > Draft new release
    * fill the tag and title field with the release number (e.g. 4.0.0)
    * append 
        * htmlunit-csp-4.x.x.jar
        * htmlunit-csp-4.x.x.jar.asc 
        * htmlunit-csp-4.x.x-javadoc.jar
        * htmlunit-csp-4.x.x-javadoc.jar.asc
    * and publish the release 

* Update the version number in pom.xml to start next snapshot development
* Update the htmlunit pom to use the new release

## Authors

* **RBRi**
* all the contributors to [salvation][5]

## License

This project is licensed under the Apache 2.0 License

## Acknowledgments

Many thanks to all of you contributing to HtmlUnit/CSSParser/Rhino and [salvation][5] in the past.


[2]: https://jenkins.wetator.org/job/HtmlUnit%20-%20CSP/ "HtmlUnit - CSP CI"
[3]: https://twitter.com/HtmlUnit "https://twitter.com/HtmlUnit"
[4]: https://fosstodon.org/@HtmlUnit
[5]: https://github.com/shapesecurity/salvation