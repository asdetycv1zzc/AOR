# Configuration Reference

`configuration-catalog.json` is the authoritative field-by-field operations reference for `AORConfiguration`. The deployment test requires an entry for every leaf in the JSON Schema and rejects undocumented fields.

Reload modes are enforced as follows:

- `IMMUTABLE`: the setting cannot change for a running deployment.
- `STATIC_RESTART`: a controlled rollout is required before the value takes effect.
- `HOT_RELOAD_AUDITED`: the service may apply the value without restart only after recording the old and new configuration hashes.

Values marked sensitive are omitted from ordinary logs and require the same change approval as security policy. Secret-valued settings use `secret://` references; the catalog never contains secret material.
