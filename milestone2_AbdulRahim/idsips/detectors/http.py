"""
HTTP detector - looks for suspicious keywords in HTTP requests.
"""

from ..agent.logging import emit_event

# List of keywords to check for
KEYWORDS = ["admin", "password", "login"]

def detect_http(cfg, pkt, src, dst):
    # Check if this is HTTP
    if not hasattr(pkt, "http"):
        return

    # Get URI and host
    uri = ""
    if hasattr(pkt.http, "request_full_uri"):
        uri = pkt.http.request_full_uri
    elif hasattr(pkt.http, "request_uri"):
        uri = pkt.http.request_uri

    host = ""
    if hasattr(pkt.http, "host"):
        host = pkt.http.host

    # Combine host and uri, make lowercase
    combined = (host + uri).lower()

    # Check if any keyword is in the combined string
    found_keyword = False
    for keyword in KEYWORDS:
        if keyword in combined:
            found_keyword = True
            break

    if found_keyword:
        emit_event(cfg,
            src=str(src) if src else "",
            dst=str(dst) if dst else "",
            proto="HTTP",
            rule_id="HTTP_KEYWORD",
            severity="low",
            summary="HTTP keyword match",
            metadata={"host": host, "uri": uri},
        )
