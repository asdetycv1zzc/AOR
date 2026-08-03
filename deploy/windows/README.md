# Windows Worker

The Windows worker runs as a directly managed native process and always reports `isolationLevel=NONE`. It accepts trusted single-tenant work only. Tasks requiring isolation, hidden-test confidentiality, hostile multi-tenancy, or network isolation are rejected before scheduling.

## Support Matrix

| Operating system | Edition | Architecture | Isolation |
|---|---|---|---|
| Windows Server 2022 (21H2) | Standard or Datacenter, Desktop Experience | amd64 | `NONE` |
| Windows 11 (24H2) | Pro, Enterprise, or Education | amd64 | `NONE` |

Native validation must run on every listed operating system before a production release. Cross-compilation in CI is necessary but does not replace reparse-point, junction, long-path, case-folding, and process-tree tests on Windows.
