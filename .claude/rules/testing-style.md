---
paths:
  - "tests/**/*.py"
---

# Testing Style (CRITICAL)

**Always use full equality assertions.** Never assert individual fields when you can assert the whole object. This catches more bugs and replaces multiple lines with a single, complete check.

Bad:
```python
assert len(capture.sent) == 1
_, rpc = capture.sent[0]
assert rpc.control is not None
assert len(rpc.control.prune) == 1
```

Good:
```python
assert capture.sent == [
    (peer_id, RPC(control=ControlMessage(prune=[ControlPrune(topic_id=topic, backoff=60)])))
]
```

Bad:
```python
event = queue.get_nowait()
assert event.peer_id == peer_id
assert event.topic == "topic"
```

Good:
```python
assert queue.get_nowait() == GossipsubPeerEvent(
    peer_id=peer_id, topic="topic", subscribed=True
)
```

When order is non-deterministic (random peer selection), assert exact RPC shape and exact peer set separately:
```python
expected_rpc = RPC(control=ControlMessage(graft=[ControlGraft(topic_id=topic)]))
assert {p for p, _ in capture.sent} == expected_peers
assert all(rpc == expected_rpc for _, rpc in capture.sent)
```

