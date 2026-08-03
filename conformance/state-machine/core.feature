Feature: Deterministic AOR state authority

  Scenario: Goal approval is exact
    Given a project negotiating GoalSpec version 1
    And the GoalSpec has no unresolved items
    When the user approves version 1 and its canonical SHA-256
    Then the project enters PLANNING
    And an immutable approval reference is retained

  Scenario: Wrong Goal digest is rejected
    Given a project negotiating a proposed GoalSpec
    When approval names a different content digest
    Then the command fails with AOR_GOAL_HASH_MISMATCH
    And the aggregate version does not change

  Scenario: Third audit failure belongs to the user
    Given a ModuleTask in its third attempt series submission
    When deterministic or LLM audit fails
    Then the ModuleTask enters BLOCKED_USER_DECISION
    And dependent ModuleTasks enter BLOCKED_DEPENDENCY
    And no automatic rework command is legal

  Scenario: Repeated command has one effect
    Given an accepted command with a principal-scoped idempotency key
    When the identical request is delivered 100 times
    Then one aggregate version is appended
    And one outbox event is created
    And every response equals the first response

  Scenario: Replay tolerates delivery disorder
    Given a contiguous immutable aggregate event history
    When events are duplicated, delayed, and delivered out of order
    Then the rebuilt projection equals the online projection field by field
