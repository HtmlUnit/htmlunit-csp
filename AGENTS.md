# htmlunit-csp

This repository contains the Content Security Policy (CSP) parsing and validation library used by HtmlUnit. It's a Java library that 
parses CSP policies into an easy-to-use representation, validates them, and allows querying what a policy permits or restricts.
The project was forked from the salvation library, which is no longer actively maintained. The code has been adapted to HtmlUnit's coding standards and enhanced with additional functionality.

This project is licensed under Apache License 2.0. Ensure all new files include the appropriate license header.

## Tech Stack

Language: Java 17+ (version 5.x will require JDK 17)
Build Tool: Maven
Testing: JUnit
Code Quality: Checkstyle, PMD, SpotBugs
CI/CD: Jenkins

## Useful commands

1. Build: `./mvn package`
2. Run tests: `./mvn test`
3. Checks (tests, formatting): `./mvn check`

## Rules and code style

- Follow the Checkstyle rules defined in checkstyle.xml
- Use 4 spaces for indentation (no tabs)
- Maximum line length: check checkstyle.xml for current limit
- Follow Java naming conventions strictly
- All public methods and classes must have Javadoc comments
- Be restrained in regard to writing code comments.
- Always add unit tests for any new feature or bug fixes. They should go either in `rhino` or `tests`; search for
  existing tests to make a decision on a case-by-case basis.
- New test classes should be written using JUnit 5.
- Code style is enforced via checkstyle. After every change, make sure there are no checkstyle validations.