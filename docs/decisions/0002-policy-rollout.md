# 0002: Fail-closed policy rollouts

- Status: accepted
- Date: 2026-11-06

## Context

A commit used to broadcast a policy to every connected agent immediately.
Agents persisted the pack and acknowledged before the sensor thread had
installed the new rule engine. The control plane recorded the
acknowledgement but did not wait for a ratio and did not roll back.

## Decision

A rollout is a separate operation after commit. It has these properties:

- It targets one committed policy version and stores the previous
  committed or applied version for rollback.
- It requires the previous version to exist. A first policy can still be
  committed and broadcast manually, but a thresholded rollout without a
  rollback target is rejected.
- It snapshots the expected agents at creation: agents seen in the last
  five minutes, or every agent with `force`.
- It rejects creation when the expected count is zero.
- It allows one pending rollout per cluster. A new commit is refused while
  a rollout is pending.
- It broadcasts the target and counts acknowledgements that arrive after
  `started_at` with status `applied` and the matching digest.
- It promotes when `applied / expected >= min_ratio`.
- It rolls back on any `rejected` acknowledgement, on timeout, or when the
  previous policy disappears. Rollback broadcasts the previous snapshot.
- It writes audit rows for creation, promotion, and rollback.

The agent reports `applied` only after the sensor thread has parsed the
pack and swapped the rule engine. The delivery task persists the pack and
hands it to the sensor thread; the acknowledgement comes back through a
separate channel. A policy that persists but cannot be activated is
reported as `rejected`.

`WatchControl` sends the current policy as the first stream item. That
makes reconnecting agents converge after a rollback and lets a pending
rollout count an agent that was online at creation but reconnected later.

## Consequences

- Policy versions are treated as cluster-unique and one policy name per
  cluster is assumed for rollout. The rollout row stores the policy id so
  status updates cannot hit another policy with the same version number.
- An agent that goes offline after the snapshot remains in the denominator;
  the timeout is the safety path. An agent that was offline at creation is
  excluded unless `force` is used.
- A rollout that cannot broadcast has no successful outcome; acks simply do
  not arrive and the timeout rolls it back.
- The control plane needs no new protobuf fields; the existing `PolicyAck`
  status and digest carry the acknowledgement.
