BEGIN;

WITH expected_limits AS (
  SELECT account.tenant_id,
         account.id,
         COALESCE(
           (budget.state_jsonb->>'hardLimitMinor')::bigint,
           (project.state_jsonb->>'budgetHardLimitMinor')::bigint
         ) AS hard_limit_minor,
         COALESCE(
           (budget.state_jsonb->>'softLimitMinor')::bigint,
           (project.state_jsonb->>'budgetSoftLimitMinor')::bigint
         ) AS soft_limit_minor
  FROM budget_accounts AS account
  JOIN aggregate_projections AS project
    ON project.tenant_id = account.tenant_id
   AND project.aggregate_type = 'project'
   AND project.aggregate_id = account.scope_id
  LEFT JOIN aggregate_projections AS budget
    ON budget.tenant_id = account.tenant_id
   AND budget.aggregate_type = 'budget'
   AND budget.aggregate_id = account.id
  WHERE account.scope_type = 'PROJECT'
)
UPDATE budget_accounts AS account
SET hard_limit_micros = account.hard_limit_micros * 10000,
    soft_limit_micros = account.soft_limit_micros * 10000,
    version = account.version + 1
FROM expected_limits AS expected
WHERE expected.tenant_id = account.tenant_id
  AND expected.id = account.id
  AND account.hard_limit_micros <= 922337203685477
  AND account.soft_limit_micros <= 922337203685477
  AND expected.hard_limit_minor = account.hard_limit_micros
  AND expected.soft_limit_minor = account.soft_limit_micros;

COMMIT;
