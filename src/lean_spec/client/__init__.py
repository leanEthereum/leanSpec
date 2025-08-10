"""
Specification for pqdevnet-0

Key differences from 3SF-mini.py:
- Using `U64` instead of native `int` for all fields
- Using `Bytes32` instead of native `str` for all fields
- Combined `*_root` and `*_slot` pairs into a single `Checkpoint` field
- Removed optionals from `Block`
"""
