# Contributing

Changes must be traceable to a SPEC requirement and a work-package task. Before implementation, update the work package's module specification, interfaces, threat model, test plan, allowed paths, and acceptance criteria.

## Workflow

1. Start from an approved GoalSpec and current PlanSpec or repository bootstrap task.
2. Add or update Schema and a failing behavioral test before implementation.
3. Keep commits atomic and reference the requirement and task ID.
4. Run `make verify`.
5. Submit an immutable commit and machine-readable evidence for independent audit.

Executors must not modify policies, knowledge sources, hidden tests, audit evidence, release signing configuration, GoalSpec, or PlanSpec. Do not commit credentials, skipped tests, unowned placeholder work, or force-bypass switches.

Commit form:

```text
<type>(<scope>): <summary> [<Requirement ID>] [<Task ID>]
```
