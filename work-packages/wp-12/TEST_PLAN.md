# Test Plan

- Reject path and interface conflicts without invoking merge.
- Verify successful merge invokes the executor once and replay returns the original result.
- Verify invalid commits, evidence digests, and duplicate task IDs fail closed.
