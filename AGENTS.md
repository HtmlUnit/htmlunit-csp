# htmlunit-csp

This repository contains the Content Security Policy (CSP) parsing and validation library used by HtmlUnit.
It parses CSP policies into a structured representation, validates them against the grammar, and allows
querying what a policy permits or restricts.

The project was forked from the [salvation](https://github.com/shapesecurity/salvation) library, which is
no longer actively maintained. The code has been adapted to HtmlUnit's coding standards and enhanced with
additional functionality.

This project is licensed under Apache License 2.0. All files must include the standard license header
(enforced by Checkstyle).

## Reference specification

The implementation targets [W3C CSP Level 3](https://www.w3.org/TR/CSP3/). Key spec sections:
- Parsing: [§6.6.1 Parse a serialized CSP list](https://www.w3.org/TR/CSP3/#parse-serialized-policy-list),
  [§6.6.2 Parse a serialized CSP](https://www.w3.org/TR/CSP3/#parse-serialized-policy)
- Matching: [§6.7 Match URLs to source list](https://www.w3.org/TR/CSP3/#match-url-to-source-list)
- Fetch directive fallback: [§6.5 Directive fallback list](https://www.w3.org/TR/CSP3/#directive-fallback-list)

## Tech stack

- **Language:** Java 17+ (version 5.x requires JDK 17; uses records, switch expressions, text blocks)
- **Build tool:** Maven (requires 3.6.3+)
- **Testing:** JUnit Jupiter 6.x (`org.junit.jupiter`)
- **Code quality:** Checkstyle, PMD, SpotBugs
- **CI/CD:** Jenkins

## Project structure

```
src/main/java/org/htmlunit/csp/
├── Policy.java                        # Central class: parsing and high-level querying
├── PolicyList.java                    # List of policies (from comma-separated CSP headers)
├── PolicyInOrigin.java                # Policy bound to a specific origin for querying
├── Directive.java                     # Base class for all directive types
├── FetchDirectiveKind.java            # Enum of fetch directives with fallback chains
├── Constants.java                     # Regex patterns, port constants
├── Utils.java                         # ASCII whitespace splitting, trimming helpers
├── directive/                         # Specific directive implementations
│   ├── SourceExpressionDirective.java # script-src, style-src, etc.
│   ├── HostSourceDirective.java       # Base for host/scheme matching
│   ├── SandboxDirective.java
│   ├── FrameAncestorsDirective.java
│   ├── TrustedTypesDirective.java
│   └── ...
├── value/                             # Parsed value types
│   ├── Hash.java                      # 'sha256-...' (record)
│   ├── Nonce.java                     # 'nonce-...' (record)
│   ├── Host.java                      # Host source expressions (record)
│   ├── Scheme.java                    # scheme-source (record)
│   └── ...
└── url/                               # URL representations
    ├── URI.java                       # Parsed URI for matching
    ├── GUID.java                      # Non-hierarchical URLs (data:, blob:, javascript:)
    └── URLWithScheme.java             # Interface for URL types
```

Tests are in `src/test/java/org/htmlunit/csp/` mirroring the main source structure.

## Useful commands

1. **Build:** `mvn package`
2. **Run tests:** `mvn test`
3. **Checkstyle:** `mvn checkstyle:check`
4. **PMD:** `mvn pmd:check`
5. **SpotBugs:** `mvn spotbugs:check`
6. **Full verify:** `mvn verify`

## Rules and code style

### General

- Follow the Checkstyle rules defined in `checkstyle.xml`.
- Code style is enforced via Checkstyle. After every change, run `mvn checkstyle:check` to verify.
- Be restrained in regard to writing code comments.
- Maximum line length: **120 characters** (imports and Javadoc links are excluded).
- Use **4 spaces** for indentation (no tabs — enforced by `FileTabCharacter` check).
- No trailing whitespace.
- No two consecutive empty lines.
- No `System.out.println` / `System.err.println` in production code (enforced by regex check).
- No `serialVersionUID` fields.

### Naming conventions (enforced by Checkstyle)

- **Instance fields:** `camelCase` with trailing underscore: `^[a-z][a-zA-Z0-9_]+_$`
  (e.g., `unsafeInline_`, `nonces_`, `fetchDirectives_`)
- **Static fields:** `PascalCase` with trailing underscore: `^[A-Z][a-zA-Z0-9_]+_$`
  (e.g., `ScriptSrcFallback_`)
- **Local variables and parameters:** standard `camelCase`, no underscore suffix
- **Methods:** `^[a-zA-Z0-9]+` or `test[A-Z][a-zA-Z0-9_]+$` for test methods
- **Catch parameters:** `^(ex?|ignored|expected)$`
- **Types:** standard `PascalCase`

### `final` keyword (strictly enforced)

- **All local variables** must be declared `final`.
- **All method parameters** must be declared `final`.
- **Enhanced for-loop variables** must be declared `final`.
- This is enforced by Checkstyle's `FinalLocalVariable` rule.

### Braces and formatting

- Opening brace `{` at **end of line** (K&R / "eol" style).
- Closing brace `}` **alone on its own line**.
- `else`, `catch`, `finally` go on a **new line** after the closing brace (not same line):
  ```java
  if (condition) {
      doSomething();
  }
  else {
      doOther();
  }
  ```
- All control structures (`if`, `for`, `while`, etc.) **must use braces**, even for single statements.

### Javadoc

- All `public` and `protected` methods must have Javadoc.
- `@author` tag format: at least two words separated by a space (e.g., `@author First Last`).
- Javadoc for `protected` and above fields is required.

### Java features

- Java `record` types are used for value objects (e.g., `Hash`, `Nonce`, `Host`, `Scheme`).
- Switch expressions with arrow syntax (`->`) are used where appropriate.
- `Optional` is used extensively for query method return values and parameters.

### Testing

- All new features and bug fixes must have unit tests.
- Tests go in `src/test/java/org/htmlunit/csp/` — search existing test classes for the best location.
- New test classes must use **JUnit Jupiter (JUnit 5+ API)**: `org.junit.jupiter.api.Test`.
- Use `TestBase` as the base class for test classes that need common error consumers
  (`ThrowIfPolicyError`, `ThrowIfPolicyListError`, `ThrowIfDirectiveError`).
- Checkstyle rules are relaxed for test files (`BeforeExecutionExclusionFileFilter` excludes `/test/`).