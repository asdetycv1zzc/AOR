# Windows Worker

The Windows worker runs as a directly managed native process and always reports `isolationLevel=NONE`. It accepts trusted single-tenant work only. Tasks requiring isolation, hidden-test confidentiality, hostile multi-tenancy, or network isolation are rejected before scheduling.
