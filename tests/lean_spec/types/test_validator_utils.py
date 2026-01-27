"""Tests for ValidatorIndex type and its methods."""

import pytest

from lean_spec.subspecs.containers import ValidatorIndex
from lean_spec.subspecs.containers.slot import Slot


class TestValidatorIndexIsProposerFor:
    """Test the is_proposer_for method on ValidatorIndex."""

    def test_is_proposer_for_basic(self) -> None:
        """
        Test basic proposer selection logic.

        Validates that the round-robin proposer selection works correctly
        for basic cases with a small validator set.
        """
        num_validators = 10

        # At slot 0, validator 0 should be the proposer (0 % 10 == 0)
        assert ValidatorIndex(0).is_proposer_for(Slot(0), num_validators) is True
        assert ValidatorIndex(1).is_proposer_for(Slot(0), num_validators) is False

        # At slot 7, validator 7 should be the proposer (7 % 10 == 7)
        assert ValidatorIndex(7).is_proposer_for(Slot(7), num_validators) is True
        assert ValidatorIndex(8).is_proposer_for(Slot(7), num_validators) is False

        # At slot 9, validator 9 should be the proposer (9 % 10 == 9)
        assert ValidatorIndex(9).is_proposer_for(Slot(9), num_validators) is True
        assert ValidatorIndex(0).is_proposer_for(Slot(9), num_validators) is False

    def test_is_proposer_for_wraparound(self) -> None:
        """
        Test proposer selection with slot numbers that wrap around.

        Validates that the modulo operation correctly handles slots
        greater than the number of validators.
        """
        num_validators = 10

        # At slot 10, wrap-around selects validator 0 (10 % 10 == 0)
        assert ValidatorIndex(0).is_proposer_for(Slot(10), num_validators) is True
        assert ValidatorIndex(1).is_proposer_for(Slot(10), num_validators) is False

        # At slot 23, wrap-around selects validator 3 (23 % 10 == 3)
        assert ValidatorIndex(3).is_proposer_for(Slot(23), num_validators) is True
        assert ValidatorIndex(2).is_proposer_for(Slot(23), num_validators) is False

        # At slot 100, wrap-around selects validator 0 (100 % 10 == 0)
        assert ValidatorIndex(0).is_proposer_for(Slot(100), num_validators) is True
        assert ValidatorIndex(5).is_proposer_for(Slot(100), num_validators) is False

    def test_is_proposer_for_large_numbers(self) -> None:
        """
        Test proposer selection with large validator counts and slot numbers.

        Ensures the method works correctly with realistic blockchain parameters.
        """
        num_validators = 1000

        # Test with large slot numbers
        assert ValidatorIndex(555).is_proposer_for(Slot(555), num_validators) is True
        assert ValidatorIndex(556).is_proposer_for(Slot(555), num_validators) is False

        # Test wrap-around with large numbers
        slot = Slot(12345)
        expected_proposer = ValidatorIndex(int(slot) % num_validators)  # 345
        assert expected_proposer.is_proposer_for(slot, num_validators) is True
        assert ValidatorIndex(0).is_proposer_for(slot, num_validators) is False

    def test_is_proposer_for_single_validator(self) -> None:
        """
        Test proposer selection with only one validator.

        Edge case where there's only one validator in the system.
        """
        num_validators = 1

        # With only one validator, they should always be the proposer
        assert ValidatorIndex(0).is_proposer_for(Slot(0), num_validators) is True
        assert ValidatorIndex(0).is_proposer_for(Slot(1), num_validators) is True
        assert ValidatorIndex(0).is_proposer_for(Slot(100), num_validators) is True

    def test_is_proposer_for_edge_cases(self) -> None:
        """
        Test proposer selection edge cases.

        Tests boundary conditions and unusual but valid inputs.
        """
        # Test with small validator sets
        num_validators = 3

        # Test all validators in a 3-validator system
        assert ValidatorIndex(0).is_proposer_for(Slot(0), num_validators) is True
        assert ValidatorIndex(1).is_proposer_for(Slot(1), num_validators) is True
        assert ValidatorIndex(2).is_proposer_for(Slot(2), num_validators) is True

        # Test wrap-around in small system
        assert ValidatorIndex(0).is_proposer_for(Slot(3), num_validators) is True
        assert ValidatorIndex(1).is_proposer_for(Slot(4), num_validators) is True
        assert ValidatorIndex(2).is_proposer_for(Slot(5), num_validators) is True

    def test_is_proposer_for_validation(self) -> None:
        """
        Test that is_proposer_for correctly identifies non-proposers.

        Ensures false cases are properly handled across different scenarios.
        """
        num_validators = 5

        # Test that all non-proposer validators return False
        for slot_num in range(20):  # Test multiple cycles
            slot = Slot(slot_num)
            expected_proposer = ValidatorIndex(slot_num % 5)

            for validator_idx in range(5):
                validator = ValidatorIndex(validator_idx)
                expected_result = validator == expected_proposer
                actual_result = validator.is_proposer_for(slot, num_validators)

                assert actual_result == expected_result, (
                    f"Slot {slot_num}: validator {validator_idx} should "
                    f"{'be' if expected_result else 'not be'} proposer"
                )

    def test_is_proposer_for_type_consistency(self) -> None:
        """
        Test that is_proposer_for works correctly with type system.

        Ensures the method handles the custom types properly.
        """
        num_validators = 7

        # Test with explicit type construction
        validator = ValidatorIndex(3)
        slot = Slot(10)  # 10 % 7 = 3

        assert validator.is_proposer_for(slot, num_validators) is True

        # Test with different validator
        other_validator = ValidatorIndex(4)
        assert other_validator.is_proposer_for(slot, num_validators) is False

    @pytest.mark.parametrize("num_validators", [1, 2, 5, 10, 100, 1000])
    def test_is_proposer_for_parametrized(self, num_validators: int) -> None:
        """
        Parametrized test for different validator set sizes.

        Tests the method across various realistic validator counts.
        """
        # Test first few slots
        for slot_num in range(min(20, num_validators * 2)):
            slot = Slot(slot_num)
            expected_proposer = ValidatorIndex(slot_num % num_validators)

            # The expected proposer should return True
            assert expected_proposer.is_proposer_for(slot, num_validators) is True

            # A different validator should return False
            if num_validators > 1:
                other_validator = ValidatorIndex((slot_num + 1) % num_validators)
                assert other_validator.is_proposer_for(slot, num_validators) is False


class TestValidatorIndexIsValid:
    """Test the is_valid method on ValidatorIndex."""

    def test_is_valid_basic(self) -> None:
        """Test basic validity checks."""
        num_validators = 10

        # Valid indices (0 to 9)
        assert ValidatorIndex(0).is_valid(num_validators) is True
        assert ValidatorIndex(5).is_valid(num_validators) is True
        assert ValidatorIndex(9).is_valid(num_validators) is True

        # Invalid indices (10+)
        assert ValidatorIndex(10).is_valid(num_validators) is False
        assert ValidatorIndex(100).is_valid(num_validators) is False

    def test_is_valid_boundary(self) -> None:
        """Test validity at boundary conditions."""
        num_validators = 5

        # Last valid index
        assert ValidatorIndex(4).is_valid(num_validators) is True

        # First invalid index
        assert ValidatorIndex(5).is_valid(num_validators) is False

    def test_is_valid_single_validator(self) -> None:
        """Test validity with single validator set."""
        num_validators = 1

        assert ValidatorIndex(0).is_valid(num_validators) is True
        assert ValidatorIndex(1).is_valid(num_validators) is False
