BEGIN;

CREATE UNIQUE INDEX budget_accounts_project_scope_unique
  ON budget_accounts (tenant_id, scope_id)
  WHERE scope_type = 'PROJECT';

COMMIT;
