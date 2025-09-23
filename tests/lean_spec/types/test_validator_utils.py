"""Tests for validator-related utilities."""

import pytest

from lean_spec.types import StakerIndex, Uint64, is_proposer


class TestIsProposer:
    """Test the is_proposer utility function."""

    def test_is_proposer_basic(self) -> None:
        """
        Test basic proposer selection logic.

        Validates that the round-robin proposer selection works correctly
        for basic cases with a small validator set.
        """
        num_validators = Uint64(10)

        # At slot 0, validator 0 should be the proposer (0 % 10 == 0)
        assert is_proposer(StakerIndex(0), Uint64(0), num_validators) is True
        assert is_proposer(StakerIndex(1), Uint64(0), num_validators) is False

        # At slot 7, validator 7 should be the proposer (7 % 10 == 7)
        assert is_proposer(StakerIndex(7), Uint64(7), num_validators) is True
        assert is_proposer(StakerIndex(8), Uint64(7), num_validators) is False

        # At slot 9, validator 9 should be the proposer (9 % 10 == 9)
        assert is_proposer(StakerIndex(9), Uint64(9), num_validators) is True
        assert is_proposer(StakerIndex(0), Uint64(9), num_validators) is False

    def test_is_proposer_wraparound(self) -> None:
        """
        Test proposer selection with slot numbers that wrap around.

        Validates that the modulo operation correctly handles slots
        greater than the number of validators.
        """
        num_validators = Uint64(10)

        # At slot 10, wrap-around selects validator 0 (10 % 10 == 0)
        assert is_proposer(StakerIndex(0), Uint64(10), num_validators) is True
        assert is_proposer(StakerIndex(1), Uint64(10), num_validators) is False

        # At slot 23, wrap-around selects validator 3 (23 % 10 == 3)
        assert is_proposer(StakerIndex(3), Uint64(23), num_validators) is True
        assert is_proposer(StakerIndex(2), Uint64(23), num_validators) is False

        # At slot 100, wrap-around selects validator 0 (100 % 10 == 0)
        assert is_proposer(StakerIndex(0), Uint64(100), num_validators) is True
        assert is_proposer(StakerIndex(5), Uint64(100), num_validators) is False

    def test_is_proposer_large_numbers(self) -> None:
        """
        Test proposer selection with large validator counts and slot numbers.

        Ensures the function works correctly with realistic blockchain parameters.
        """
        num_validators = Uint64(1000)

        # Test with large slot numbers
        assert is_proposer(StakerIndex(555), Uint64(555), num_validators) is True
        assert is_proposer(StakerIndex(556), Uint64(555), num_validators) is False

        # Test wrap-around with large numbers
        slot = Uint64(12345)
        expected_proposer = StakerIndex(slot % num_validators)  # 345
        assert is_proposer(expected_proposer, slot, num_validators) is True
        assert is_proposer(StakerIndex(0), slot, num_validators) is False

    def test_is_proposer_single_validator(self) -> None:
        """
        Test proposer selection with only one validator.

        Edge case where there's only one validator in the system.
        """
        num_validators = Uint64(1)

        # With only one validator, they should always be the proposer
        assert is_proposer(StakerIndex(0), Uint64(0), num_validators) is True
        assert is_proposer(StakerIndex(0), Uint64(1), num_validators) is True
        assert is_proposer(StakerIndex(0), Uint64(100), num_validators) is True

    def test_is_proposer_edge_cases(self) -> None:
        """
        Test proposer selection edge cases.

        Tests boundary conditions and unusual but valid inputs.
        """
        # Test with small validator sets
        num_validators = Uint64(3)

        # Test all validators in a 3-validator system
        assert is_proposer(StakerIndex(0), Uint64(0), num_validators) is True
        assert is_proposer(StakerIndex(1), Uint64(1), num_validators) is True
        assert is_proposer(StakerIndex(2), Uint64(2), num_validators) is True

        # Test wrap-around in small system
        assert is_proposer(StakerIndex(0), Uint64(3), num_validators) is True
        assert is_proposer(StakerIndex(1), Uint64(4), num_validators) is True
        assert is_proposer(StakerIndex(2), Uint64(5), num_validators) is True

    def test_is_proposer_validation(self) -> None:
        """
        Test that is_proposer correctly identifies non-proposers.

        Ensures false cases are properly handled across different scenarios.
        """
        num_validators = Uint64(5)

        # Test that all non-proposer validators return False
        for slot_num in range(20):  # Test multiple cycles
            slot = Uint64(slot_num)
            expected_proposer = StakerIndex(slot_num % 5)

            for validator_idx in range(5):
                validator = StakerIndex(validator_idx)
                expected_result = validator == expected_proposer
                actual_result = is_proposer(validator, slot, num_validators)

                assert actual_result == expected_result, (
                    f"Slot {slot_num}: validator {validator_idx} should "
                    f"{'be' if expected_result else 'not be'} proposer"
                )

    def test_is_proposer_type_consistency(self) -> None:
        """
        Test that is_proposer works correctly with type system.

        Ensures the function handles the custom types properly.
        """
        num_validators = Uint64(7)

        # Test with explicit type construction
        validator = StakerIndex(3)
        slot = Uint64(10)  # 10 % 7 = 3

        assert is_proposer(validator, slot, num_validators) is True

        # Test with different validator
        other_validator = StakerIndex(4)
        assert is_proposer(other_validator, slot, num_validators) is False

    @pytest.mark.parametrize("num_validators", [1, 2, 5, 10, 100, 1000])
    def test_is_proposer_parametrized(self, num_validators: int) -> None:
        """
        Parametrized test for different validator set sizes.

        Tests the function across various realistic validator counts.
        """
        validators = Uint64(num_validators)

        # Test first few slots
        for slot_num in range(min(20, num_validators * 2)):
            slot = Uint64(slot_num)
            expected_proposer = StakerIndex(slot_num % num_validators)

            # The expected proposer should return True
            assert is_proposer(expected_proposer, slot, validators) is True

            # A different validator should return False
            if num_validators > 1:
                other_validator = StakerIndex((slot_num + 1) % num_validators)
                assert is_proposer(other_validator, slot, validators) is False
