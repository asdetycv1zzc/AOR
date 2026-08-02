# WP-00 Interfaces

## Build Interface

- `make build`: compile all Go commands.
- `make test`: execute Go tests.
- `make lint`: run formatting and static analysis checks.
- `make schema`: validate repository JSON and YAML structure with the conformance command.
- `make verify`: execute all required local gates in fixed order.

## Repository Interface

- Machine-readable contracts live below `api/`.
- Requirement traceability lives at `conformance/requirements.yaml`.
- Architecture decisions live at `adr/NNNN-*.md`.
- Work-package handoffs live at `work-packages/<wp-id>/`.

Commands return non-zero on failure and do not mutate tracked source during validation.
