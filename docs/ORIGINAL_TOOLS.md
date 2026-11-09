# Preserved original tool inventory

The existing source registers 52 tools in Professional Edition, 49 in Community. The three unprefixed Scanner/Collaborator tools are conditionally registered in Professional; prefixed scanner tools remain discoverable but return explicit unsupported errors in Community. Existing endpoint, authentication and names are preserved.

| Group | Original tool names |
|---|---|
| HTTP and Repeater | `send_http1_request`, `send_http2_request`, `create_repeater_tab`, `create_repeater_tab_http2` |
| Utilities | `url_encode`, `url_decode`, `base64_encode`, `base64_decode`, `generate_random_string` |
| Configuration | `output_project_options`, `output_user_options`, `set_project_options`, `set_user_options` |
| Professional only registrations | `get_scanner_issues`, `generate_collaborator_payload`, `get_collaborator_interactions` |
| History / Organizer | `get_proxy_http_history`, `get_proxy_http_history_regex`, `get_organizer_items`, `get_organizer_items_regex` |
| Burp state / editor | `set_task_execution_engine_state`, `set_proxy_intercept_state`, `get_active_editor_contents`, `set_active_editor_contents` |
| Connection | `burp_get_status`, `burp_get_capabilities`, `burp_get_project_info`, `burp_get_scope`, `burp_check_connection` |
| Captured traffic | `burp_get_proxy_history`, `burp_search_http_history`, `burp_get_request`, `burp_get_response`, `burp_analyze_request`, `burp_analyze_response`, `burp_get_site_map`, `burp_get_response_headers` |
| Requests | `burp_send_to_repeater`, `burp_send_http_request`, `burp_compare_responses`, `burp_modify_request`, `burp_get_repeater_tabs` |
| Analysis | `burp_analyze_security_headers`, `burp_analyze_cookies`, `burp_analyze_cors`, `burp_analyze_authentication`, `burp_find_sensitive_data` |
| Scanner and reports | `burp_get_scanner_issues`, `burp_start_scan`, `burp_get_scan_status`, `burp_stop_scan`, `burp_generate_security_report` |
| Local test scope (build `.2`) | `burp_configure_local_test_scope` — only fixed `127.0.0.1:8000` test paths; local Burp confirmation required |

Before this upgrade, `set_proxy_intercept_state` only toggled Burp's native interception. `burp_modify_request` generated a proposal from supplied text and did not operate on held traffic. There was no registered Proxy request/response handler and no controllable pending queue. The upgrade adds 17 tools without removing any of these registrations. `burp_set_proxy_intercept_state` is an added prefixed alias, not a rename of the existing tool.

The UI's tool catalog now reads the actual registered tool names after startup, including edition-dependent tools, rather than showing only the previous static list of 28 prefixed tools. Build `.2` retains these existing names and adds the one localhost-scope helper, for 71 tools in Professional and 68 in Community. The running `.1` build remains at 70 Professional tools until reloaded.
