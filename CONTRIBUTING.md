# Contributing

Feedback and contributions are very welcome!

## General Guidelines

- For specific proposals, please submit
  [pull requests](../../pulls) or
  [issues](../../issues).
- Pull requests are preferred for their specificity.
- Create separate branches for different logical changes and submit a
  pull request to the `main` branch when done.

## Code Changes

Code should be DRY (Don't Repeat Yourself), clear, and obviously correct.
Some technical debt is inevitable, but avoid excessive debt.

### Automated Tests

- Include new tests when adding or changing functionality.
- Maintain at least 80% statement coverage.
- We encourage test-driven development: create tests first, ensure they fail,
  then add code to pass them.

### Documentation Standards

**Test documentation**: Every test function must have a doc comment that
reads **outside-in**:

1. What the tested code achieves for the end user (in their terms).
2. Which module or feature area the tested code belongs to.
3. What specific behavior the test verifies.

For table-driven tests, document the overall function with the
outside-in structure and give each sub-test a descriptive name that
reads as an assertion.

**Function/method documentation**: Every exported function and method
must have a godoc comment that covers:

1. A concise summary starting with the function name.
2. Parameters — type, valid ranges, and purpose.
3. Return values — success and error cases.
4. Usage context — when and why to call this function, related functions,
   and common patterns.

Think of it like good JavaDoc: not just *what* it does, but *how* and
*when* to use it.

### Security

- Pay attention to security and work *with* the existing security hardening.
- Never commit secrets or credentials.
- All contributions are scanned by CodeQL, golangci-lint (including gosec),
  and Grype.

### Continuous Integration

We use [GitHub Actions](../../actions) for continuous integration.
All checks must pass before a PR can be merged.

## Commit Messages

1. Separate subject from body with a blank line.
2. Limit the subject line to 72 characters.
3. Capitalize the subject line.
4. Do not end the subject line with a period.
5. Use the imperative mood ("Add feature", not "Added feature").
6. Wrap the body at 72 characters.
7. Use the body to explain *what* and *why*, not *how*.

## Dependencies (Supply Chain)

- Minimize external dependencies; evaluate all new components before adding them.
- All dependencies must be open source.
- Update only one or a few components per commit to simplify debugging.
- Run `go mod tidy` after adding or removing dependencies.

## Vulnerability Reporting

Please privately report vulnerabilities you find.
See [SECURITY.md](./SECURITY.md) for details.
