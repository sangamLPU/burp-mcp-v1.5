# Burp MCP extension UI layout

The Burp MCP tab is organized into five sections:

- **Server Settings** — server state, endpoint, host, and port.
- **Security** — authentication, read-only mode, approval policies, credential filtering, and authorized-host allowlist.
- **Live Interception** — locally approved session controls, heartbeat and lease health, pending messages, preview, and decisions.
- **MCP Tools** — searchable list of the registered tool names with a copy action.
- **Activity Logs** — the bounded, payload-free recent activity log.

Settings and live interception use width-tracking scrollable viewports. Compact windows scroll vertically to keep every control reachable; at larger sizes, the live queue/preview split grows into the available height. The forms use Swing layout managers (`BorderLayout`, `GridBagLayout`, and `JSplitPane`) so fields and queue/preview panes follow the available space. Text uses Burp's Swing UI fonts; shared spacing derives from the active UI font size. Tool names are listed individually and filtered as the search field changes rather than being joined into one long label.

The endpoint remains `http://127.0.0.1:9876/mcp`. This UI refactor does not change authentication, authorization, registered tools, or interception decisions.

## Verification

The rebuilt extension was loaded in Burp Suite Professional 2024.1.1.1. The Burp MCP tab was visually checked in a compact `627 × 474` window and maximized at `1536 × 816`. All five sections remained reachable, the tool list expanded to available space, and the settings/interception sections remained scrollable. The current Windows display scaling factor was not changed during the check.
