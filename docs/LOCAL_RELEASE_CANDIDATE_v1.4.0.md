# Burp MCP v1.4.0 ? local release candidate finalization

This local commit preserves the verified implementation and regression harnesses without changing functionality. No JAR was rebuilt, renamed or overwritten. No live test or full suite was repeated during finalization. Prior evidence remains in ignored `build/` reports and milestone archives; binaries and private evidence are not included in Git. The only tracked binary policy exception is the existing Gradle wrapper JAR.

## Artifact identity

| Artifact | SHA-256 | Meaning |
|---|---|---|
| `build/libs/burp-mcp-20261101.13-burp2024.1.1.1.jar` | `3c481bd6bb8407e889560a68a8ea8094fe21a2aaba2f1f779a8d4e739f313e32` | Historical versioned .13 artifact, unchanged; differs from the release manifest. |
| `build/libs/burp-mcp-all.jar` | `930ba28d126fe7b296ad61ecd4bab830044dfc07bccb1dee484cd72a35dbe8c2` | Verified artifact matching the preserved release manifest and working rollback copy. |
| `build/releases/burp-mcp-v1.4.0-build.13-20261102T094348Z/burp-mcp-1.4.0-build.13.jar` | `930ba28d126fe7b296ad61ecd4bab830044dfc07bccb1dee484cd72a35dbe8c2` | Release-bundle copy; matches `manifest.json`. |

The historical and release JARs expose the same build ID but are not byte-identical. Four class entries and the manifest differ. All four `javap -p -c` listings match; debug metadata differences were observed. This comparison does not replace checksum identity. The historical artifact must not be substituted for the manifest-matching release copy. The original manifest and all rollback artifacts remain untouched.

The working rollback is retained at `build/milestones/live-proxy-9-exchanges-20261102T090247Z/burp-mcp-20261101.13-930ba28d126f.jar`. Its hash matches the release copy. Historical `.5` and other preserved backups are retained where already present; no unrelated files were removed.

## Validation and release scope

[Release readiness](FINAL_RELEASE_READINESS_v1.4.0.md) records nine successful LIVE_PROXY exchanges, continuous request/response rules, compatible rules, pause/resume and all four reliability phases PASS. The completed final regression recorded 217 JVM and 91 Python passes plus applicable PowerShell/local checks. Live evidence, integration tests, unit tests and unverified individual tool paths are distinguished.

Automatic cookie rewriting and WebSocket frame interception/editing remain unsupported. Not all 86 tools have individual live verification. The historical MCP freeze has not been conclusively root-caused. Compatibility is evidenced for Burp Professional 2024.1.1.1-26891 and the recorded bounded HTTP scenarios, not universal website automation.

## Publication review

Source, tests and sanitized documentation are suitable for a reviewed GitHub push after this local commit. Artifact publication must use the manifest-matching release-bundle JAR and retain the distinction from the historical versioned file. No push or GitHub release publication is performed by finalization. Local evidence links depend on the preserved ignored `build/` directory and will not resolve in a source-only Git checkout.

The finalization review includes staged and unstaged diffs, explicit file selection, secret/identity checks, artifact checksums and `git diff --check`. Deterministic synthetic identities in unit fixtures are intentional; actual bearer tokens, run/server identities, private traffic and generated evidence remain outside the commit.
