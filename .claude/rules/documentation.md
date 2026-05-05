---
paths:
  - "**/*.py"
---

# Documentation Rules (CRITICAL)

**NEVER use explicit function or method names in documentation.**

Names change. Documentation becomes stale. Use plain language instead.

Bad:
```python
# The shutdown task waits for stop() to be called, then signals
# all services to terminate. Once all services exit, TaskGroup completes.
```

Good:
```python
# A separate task monitors the shutdown signal.
# When triggered, it stops all services.
# Once services exit, execution completes.
```

**Write short, scannable sentences.**

Attention spans are short. Capture the reader precisely and concisely.

- One idea per line.
- Add blank lines between logical groups.
- Avoid long compound sentences.

Bad:
```python
# The state includes initial checkpoints, validator registry,
# and configuration derived from genesis time.
```

Good:
```python
# Includes initial checkpoints, validator registry, and config.
```

**Use bullet points or enumeration for lists.**

When listing multiple items, use structured formatting. Helps readers maintain focus.

Bad:
```python
"""
The verification checks structural validity, cryptographic correctness,
and state transition rules before accepting the block.
"""
```

Good:
```python
"""
The verification checks:

- Structural validity
- Cryptographic correctness
- State transition rules
"""
```

Or with numbered steps:
```python
"""
Processing proceeds in order:

1. Validate input format
2. Check signatures
3. Apply state transition
4. Update forkchoice
"""
```

Bad:
```python
"""
Wait for shutdown signal then stop services.

This task runs alongside the services. When shutdown is signaled,
it stops both services, allowing their run loops to exit gracefully.
"""
```

Good:
```python
"""
Wait for shutdown signal then stop services.

Runs alongside the services.
When shutdown is signaled, stops all services gracefully.
"""
```

