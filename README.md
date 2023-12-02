# HtmlUnit - CSP

This is the code repository of the Content Security Policy support used by HtmlUnit.

The library was created by forking the [salvation][5] project
as it is apparently no longer maintained.

For HtmlUnit, the code has been adapted to the code style rules used, and support for editing policies has been removed.

The code is being expanded, restructured and improved primarily to meet the requirements of this project.

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/org.htmlunit/htmlunit-csp/badge.svg)](https://maven-badges.herokuapp.com/maven-central/org.htmlunit/htmlunit-csp)

:heart: [Sponsor](https://github.com/sponsors/rbri)

### Project News

[HtmlUnit@mastodon][4] | [HtmlUnit@Twitter][3]

### Latest release Version 3.9.0 / December 03, 2023

### Maven

Add to your `pom.xml`:

```xml
<dependency>
    <groupId>org.htmlunit</groupId>
    <artifactId>htmlunit-csp</artifactId>
    <version>3.9.0</version>
</dependency>
```

### Gradle

Add to your `build.gradle`:

```groovy
implementation group: 'org.htmlunit', name: 'htmlunit-csp', version: '3.9.0'
```

### Last CI build
The latest builds are available from our
[Jenkins CI build server][2]

[![Build Status](https://jenkins.wetator.org/buildStatus/icon?job=HtmlUnit+-+csp)](https://jenkins.wetator.org/job/HtmlUnit%20-%20csp/)

If you use maven please add:

    <dependency>
        <groupId>org.htmlunit</groupId>
        <artifactId>htmlunit-csp</artifactId>
        <version>3.10.0-SNAPSHOT</version>
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
* Execute "mvn -U clean test" to be sure all tests are passing
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
    * fill the tag and title field with the release number (e.g. 3.9.0)
    * append 
        * htmlunit-csp-3.x.x.jar
        * htmlunit-csp-3.x.x.jar.asc 
        * htmlunit-csp-3.x.x-javadoc.jar
        * htmlunit-csp-3.x.x-javadoc.jar.asc
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