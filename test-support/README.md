# Existing offline campaign support

These reviewed source files were copied byte-for-byte from the local
`build/reports/post-batch-a-preparation-20261107T155141Z/` preparation bundle.
They contain synthetic definitions and offline checks, not captured traffic or
Scanner findings. The original evidence remains unchanged and ignored.

## Pure Python checks

```powershell
python -B -m unittest discover -s test-support/campaign -p 'test_*.py'
```

The 26 tests use in-memory fake transports. `campaign_checks.py` validates the
fixed synthetic Scanner markers, pagination/count/error mutants, exact proposed
C-H method/URL/Host contracts, delivery identity and timeout uncertainty.
`guarded_proxy_sender.py` has no default connection factory, CLI or native
activation: a caller must supply a transport and real readiness. Its per-window
durable STARTED marker prevents replay. It is preparation infrastructure, not an
approved C-H runner or a general proof of arbitrary-content sanitization.

Never supply a real connection factory or constant readiness callback under
offline/preflight authorization. The fixed marker prefix identifies the original
reviewed dataset; it does not authorize reseeding, private finding inspection or
reuse of historical evidence. See [remaining campaign](../docs/SUPERVISED_CAMPAIGN.md).

## Scanner seed source only

`scanner-seed/ControlledScannerSeed.java` is an isolated **TEST ONLY** extension,
not compiled into Burp MCP. Its seven-assertion offline companion checks synthetic
definition shape and that initialization only registers a name/panel. Historical
Java 17 / Montoya 2023.12.1 compilation and offline assertions passed; native
loading/seeding/retention/removal have **not** been verified. No JAR is committed.

For offline compilation only, after recovering the compile API dependency, set
`$montoyaApiJar` to the locally verified Montoya 2023.12.1 JAR path. Then:

```powershell
New-Item -ItemType Directory -Force .\build\test-support\scanner-seed | Out-Null
javac --release 17 -cp $montoyaApiJar -d .\build\test-support\scanner-seed .\test-support\scanner-seed\ControlledScannerSeed.java .\test-support\scanner-seed\ControlledScannerSeedTest.java
java -Djava.awt.headless=true -cp ".\build\test-support\scanner-seed;$montoyaApiJar" ControlledScannerSeedTest
```

These commands do not package/load/seed the extension. No native operation is
authorized by this README. Before any future packaging/load/seed, separately
review source and exact hash, intended project/scope, data access, native human
confirmation, one-shot behavior and cleanup. Native seed operation reads issue
names to reject duplicate owned markers, adds exactly three synthetic audit
issues, and reports owned counts. It sends no HTTP or Scanner audit, but that
does not grant permission to inspect project data. Partial failure means stop;
no automatic retry. Unloading does not remove issues. The compile API has no
issue-removal method: cleanup requires separately approved human removal of only
the three owned synthetic issues. Do not load this helper as part of resumption
or ordinary tests.
