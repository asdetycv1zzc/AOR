# Design

All production images are digest-pinned, application containers run non-root with read-only roots and dropped capabilities, default network policy is deny, audit retention is compliance WORM for at least 400 days, and Windows is explicit native `NONE`.
