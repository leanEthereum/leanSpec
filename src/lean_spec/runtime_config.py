"""Runtime configuration for the Lean Ethereum specification.

This module contains flags and settings that control runtime behavior,
particularly for testing vs production execution.
"""

USE_TEST_SCHEME = False
"""
Global flag to control which XMSS signature scheme is used.

When False (default): Uses production XMSS parameters (PROD_CONFIG)
When True: Uses test XMSS parameters (TEST_CONFIG) for faster execution

This flag is set by test frameworks in conftest.py to enable lighter-weight
cryptographic operations during testing while keeping the spec code clean
and independent of test-specific logic.
"""
