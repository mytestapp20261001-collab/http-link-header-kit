# Maintenance changes

## 2026-10-24

Reject literal colons in the first relative-path segment of Link targets and anchors, per [RFC 3986 section 4.2](https://www.rfc-editor.org/rfc/rfc3986.html#section-4.2). Explicit dot-segment, absolute-path, percent-encoded, query and fragment forms remain supported. This is a narrow correction to the documented strict subset, not full URI validation.

Historical migration evidence remains unchanged; see [maintenance receipt](docs/MAINTENANCE_2026-10-24.json).
