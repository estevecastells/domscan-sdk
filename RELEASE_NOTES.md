# DomScan SDK v0.3.0

This release makes the TypeScript and Python SDKs first-class typed clients for DomScan API v2.15.0.

- The TypeScript SDK now includes generated request and response types for every supported operation, with precise full-response overloads.
- The Python SDK now includes generated `TypedDict` response models, keyword parameter stubs, `py.typed`, and precise full-response overloads validated with mypy.
- Both SDKs expose request IDs, credits, rate limits, response time, API version, and data freshness through optional full-response metadata.
- Structured API errors map to actionable classes with stable type, code, HTTP status, retry guidance, request ID, and documentation fields.
- Safe retries honor `Retry-After`. GET requests can retry automatically, while write retries require an explicit idempotency key.
- Empty and malformed JSON responses, caller cancellation, network failures, timeouts, and Python keyword aliases now have deterministic behavior and test coverage.
- The shared endpoint manifest now covers 120 public non-session operations across 11 namespaces.

The GitHub release includes installable Node.js and Python archives plus the maintained release artifacts for Go, Ruby, PHP, Java, C#, Kotlin, Swift, and Rust.
