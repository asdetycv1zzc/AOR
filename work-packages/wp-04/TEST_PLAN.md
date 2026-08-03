# WP-04 Test Plan

1. Test every reservation, settlement, release and reconciliation edge.
2. Race identical reservations and assert one budget effect.
3. Exercise provider errors and verify reservation reconciliation state.
4. Verify cache-key changes for every privacy and policy input.
5. Fuzz malformed structured output and credential-like strings.
