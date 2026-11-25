# License and source notices

Burp MCP 1.0.0-custom is a modified local package of PortSwigger's Burp Suite
MCP Server Extension. The upstream project license is GPL-3.0. The unmodified
license text is included as [LICENSE](LICENSE). The release was assembled
on 25 November 2026. The working source, build instructions, wrapper, tests,
and fixtures are in `source.zip`. The customized extension adds Proxy rewrite
rules and controls, HTTP/2 response support, approval-dialog fixes, and the
related tests and documentation. [Upstream project](https://github.com/PortSwigger/mcp-server)

The JAR carries the upstream Stdio MCP Proxy byte-for-byte from
`source/libs/mcp-proxy-all.jar` in the source snapshot. Its provenance is the
server commit `318c909ab81f72031b97c4fb488bea56e5152bf2`. The matching upstream
proxy source revision identified by the linked change is
`4535adbf1624ae7943499071631d62769fec3c6c`. Its source archive and GPL-3.0
license are included in `licenses/`. The two license entries found inside
the embedded proxy are preserved there as well. [Server proxy update](https://github.com/PortSwigger/mcp-server/commit/318c909ab81f72031b97c4fb488bea56e5152bf2), [Proxy source update](https://github.com/PortSwigger/mcp-proxy/pull/7)

Bundled dependencies retain their own notices and terms.
`licenses/dependency-notices.json` indexes locally matched dependency archives,
their available Maven license declarations, and notices preserved from them in
`licenses/dependencies/`. The package also includes upstream license or notice
files for the Kotlin MCP SDK, Netty, JCTools, and Jetty ALPN's parent project.
This inventory reflects available metadata and is not a complete redistribution audit.
Burp Suite itself is a separately installed PortSwigger product.

This package was made for local use. If you later distribute a copy, consult
GPL-3.0 for the applicable source and notice requirements and check all
bundled dependencies for any additional terms. [GNU GPL-3.0](https://www.gnu.org/licenses/gpl-3.0.html), [GNU GPL FAQ on private modifications](https://www.gnu.org/licenses/gpl-faq.html#GPLRequireSourcePostedPublic)
