"""
Tests for strict type checking in XMSS component classes.

These tests verify that Pydantic-based classes properly reject subclasses,
ensuring only approved implementations are used.
"""

import pytest
from pydantic import ValidationError

from lean_spec.subspecs.xmss.constants import PROD_CONFIG, TEST_CONFIG, XmssConfig
from lean_spec.subspecs.xmss.interface import GeneralizedXmssScheme
from lean_spec.subspecs.xmss.message_hash import PROD_MESSAGE_HASHER, MessageHasher
from lean_spec.subspecs.xmss.poseidon import PROD_POSEIDON, PoseidonXmss
from lean_spec.subspecs.xmss.prf import PROD_PRF, Prf
from lean_spec.subspecs.xmss.rand import PROD_RAND, Rand
from lean_spec.subspecs.xmss.target_sum import PROD_TARGET_SUM_ENCODER, TargetSumEncoder
from lean_spec.subspecs.xmss.tweak_hash import PROD_TWEAK_HASHER, TweakHasher


class TestPrfStrictTypes:
    """Tests for Prf strict type checking."""

    def test_prf_accepts_exact_type(self) -> None:
        """Prf initialization succeeds with exact type."""
        prf = Prf(config=PROD_CONFIG)
        assert prf.config == PROD_CONFIG

    def test_prf_rejects_subclass_config(self) -> None:
        """Prf rejects XmssConfig subclass."""

        class CustomConfig(XmssConfig):
            pass

        custom_config = XmssConfig.__new__(CustomConfig)
        custom_config.__dict__.update(PROD_CONFIG.__dict__)

        with pytest.raises(TypeError, match="config must be exactly XmssConfig"):
            Prf(config=custom_config)

    def test_prf_rejects_wrong_type_config(self) -> None:
        """Prf rejects completely wrong type for config."""

        class RandomClass:
            pass

        with pytest.raises((TypeError, ValidationError)):
            Prf(config=RandomClass())  # type: ignore[arg-type]

    def test_prf_frozen(self) -> None:
        """Prf is immutable (frozen)."""
        with pytest.raises(ValidationError):
            PROD_PRF.config = TEST_CONFIG


class TestRandStrictTypes:
    """Tests for Rand strict type checking."""

    def test_rand_accepts_exact_type(self) -> None:
        """Rand initialization succeeds with exact type."""
        rand = Rand(config=PROD_CONFIG)
        assert rand.config == PROD_CONFIG

    def test_rand_rejects_subclass_config(self) -> None:
        """Rand rejects XmssConfig subclass."""

        class CustomConfig(XmssConfig):
            pass

        custom_config = XmssConfig.__new__(CustomConfig)
        custom_config.__dict__.update(PROD_CONFIG.__dict__)

        with pytest.raises(TypeError, match="config must be exactly XmssConfig"):
            Rand(config=custom_config)

    def test_rand_rejects_wrong_type_config(self) -> None:
        """Rand rejects completely wrong type for config."""

        class RandomClass:
            pass

        with pytest.raises((TypeError, ValidationError)):
            Rand(config=RandomClass())  # type: ignore[arg-type]

    def test_rand_frozen(self) -> None:
        """Rand is immutable (frozen)."""
        with pytest.raises(ValidationError):
            PROD_RAND.config = TEST_CONFIG


class TestTweakHasherStrictTypes:
    """Tests for TweakHasher strict type checking."""

    def test_tweak_hasher_accepts_exact_types(self) -> None:
        """TweakHasher initialization succeeds with exact types."""
        hasher = TweakHasher(config=PROD_CONFIG, poseidon=PROD_POSEIDON)
        assert hasher.config == PROD_CONFIG

    def test_tweak_hasher_rejects_subclass_config(self) -> None:
        """TweakHasher rejects XmssConfig subclass."""

        class CustomConfig(XmssConfig):
            pass

        custom_config = XmssConfig.__new__(CustomConfig)
        custom_config.__dict__.update(PROD_CONFIG.__dict__)

        with pytest.raises(TypeError, match="config must be exactly XmssConfig"):
            TweakHasher(config=custom_config, poseidon=PROD_POSEIDON)

    def test_tweak_hasher_rejects_subclass_poseidon(self) -> None:
        """TweakHasher rejects PoseidonXmss subclass."""

        class CustomPoseidon(PoseidonXmss):
            pass

        custom_poseidon = PoseidonXmss.__new__(CustomPoseidon)
        custom_poseidon.__dict__.update(PROD_POSEIDON.__dict__)

        with pytest.raises(TypeError, match="poseidon must be exactly PoseidonXmss"):
            TweakHasher(config=PROD_CONFIG, poseidon=custom_poseidon)

    def test_tweak_hasher_rejects_wrong_type_config(self) -> None:
        """TweakHasher rejects completely wrong type for config."""

        class RandomClass:
            pass

        with pytest.raises((TypeError, ValidationError)):
            TweakHasher(config=RandomClass(), poseidon=PROD_POSEIDON)  # type: ignore[arg-type]

    def test_tweak_hasher_rejects_wrong_type_poseidon(self) -> None:
        """TweakHasher rejects completely wrong type for poseidon."""

        class RandomClass:
            pass

        with pytest.raises((TypeError, ValidationError)):
            TweakHasher(config=PROD_CONFIG, poseidon=RandomClass())  # type: ignore[arg-type]

    def test_tweak_hasher_frozen(self) -> None:
        """TweakHasher is immutable (frozen)."""
        with pytest.raises(ValidationError):
            PROD_TWEAK_HASHER.config = TEST_CONFIG


class TestTargetSumEncoderStrictTypes:
    """Tests for TargetSumEncoder strict type checking."""

    def test_encoder_accepts_exact_types(self) -> None:
        """TargetSumEncoder initialization succeeds with exact types."""
        encoder = TargetSumEncoder(config=PROD_CONFIG, message_hasher=PROD_MESSAGE_HASHER)
        assert encoder.config == PROD_CONFIG

    def test_encoder_rejects_subclass_config(self) -> None:
        """TargetSumEncoder rejects XmssConfig subclass."""

        class CustomConfig(XmssConfig):
            pass

        custom_config = XmssConfig.__new__(CustomConfig)
        custom_config.__dict__.update(PROD_CONFIG.__dict__)

        with pytest.raises(TypeError, match="config must be exactly XmssConfig"):
            TargetSumEncoder(config=custom_config, message_hasher=PROD_MESSAGE_HASHER)

    def test_encoder_rejects_subclass_message_hasher(self) -> None:
        """TargetSumEncoder rejects MessageHasher subclass."""

        class CustomMessageHasher(MessageHasher):
            pass

        custom_hasher = MessageHasher.__new__(CustomMessageHasher)
        custom_hasher.__dict__.update(PROD_MESSAGE_HASHER.__dict__)

        with pytest.raises(TypeError, match="message_hasher must be exactly MessageHasher"):
            TargetSumEncoder(config=PROD_CONFIG, message_hasher=custom_hasher)

    def test_encoder_rejects_wrong_type_config(self) -> None:
        """TargetSumEncoder rejects completely wrong type for config."""

        class RandomClass:
            pass

        with pytest.raises((TypeError, ValidationError)):
            TargetSumEncoder(config=RandomClass(), message_hasher=PROD_MESSAGE_HASHER)  # type: ignore[arg-type]

    def test_encoder_rejects_wrong_type_message_hasher(self) -> None:
        """TargetSumEncoder rejects completely wrong type for message_hasher."""

        class RandomClass:
            pass

        with pytest.raises((TypeError, ValidationError)):
            TargetSumEncoder(config=PROD_CONFIG, message_hasher=RandomClass())  # type: ignore[arg-type]

    def test_encoder_frozen(self) -> None:
        """TargetSumEncoder is immutable (frozen)."""
        with pytest.raises(ValidationError):
            PROD_TARGET_SUM_ENCODER.config = TEST_CONFIG


class TestGeneralizedXmssSchemeStrictTypes:
    """Tests for GeneralizedXmssScheme strict type checking (integration)."""

    def test_scheme_accepts_exact_types(self) -> None:
        """GeneralizedXmssScheme initialization succeeds with exact types."""
        scheme = GeneralizedXmssScheme(
            config=PROD_CONFIG,
            prf=PROD_PRF,
            hasher=PROD_TWEAK_HASHER,
            encoder=PROD_TARGET_SUM_ENCODER,
            rand=PROD_RAND,
        )
        assert scheme.config == PROD_CONFIG

    def test_scheme_rejects_subclass_config(self) -> None:
        """GeneralizedXmssScheme rejects XmssConfig subclass."""

        class CustomConfig(XmssConfig):
            pass

        custom_config = XmssConfig.__new__(CustomConfig)
        custom_config.__dict__.update(PROD_CONFIG.__dict__)

        with pytest.raises(TypeError, match="config must be exactly XmssConfig"):
            GeneralizedXmssScheme(
                config=custom_config,
                prf=PROD_PRF,
                hasher=PROD_TWEAK_HASHER,
                encoder=PROD_TARGET_SUM_ENCODER,
                rand=PROD_RAND,
            )

    def test_scheme_rejects_subclass_prf(self) -> None:
        """GeneralizedXmssScheme rejects Prf subclass."""

        class CustomPrf(Prf):
            pass

        custom_prf = Prf.__new__(CustomPrf)
        custom_prf.__dict__.update(PROD_PRF.__dict__)

        with pytest.raises(TypeError, match="prf must be exactly Prf"):
            GeneralizedXmssScheme(
                config=PROD_CONFIG,
                prf=custom_prf,
                hasher=PROD_TWEAK_HASHER,
                encoder=PROD_TARGET_SUM_ENCODER,
                rand=PROD_RAND,
            )

    def test_scheme_rejects_subclass_hasher(self) -> None:
        """GeneralizedXmssScheme rejects TweakHasher subclass."""

        class CustomHasher(TweakHasher):
            pass

        custom_hasher = TweakHasher.__new__(CustomHasher)
        custom_hasher.__dict__.update(PROD_TWEAK_HASHER.__dict__)

        with pytest.raises(TypeError, match="hasher must be exactly TweakHasher"):
            GeneralizedXmssScheme(
                config=PROD_CONFIG,
                prf=PROD_PRF,
                hasher=custom_hasher,
                encoder=PROD_TARGET_SUM_ENCODER,
                rand=PROD_RAND,
            )

    def test_scheme_rejects_subclass_encoder(self) -> None:
        """GeneralizedXmssScheme rejects TargetSumEncoder subclass."""

        class CustomEncoder(TargetSumEncoder):
            pass

        custom_encoder = TargetSumEncoder.__new__(CustomEncoder)
        custom_encoder.__dict__.update(PROD_TARGET_SUM_ENCODER.__dict__)

        with pytest.raises(TypeError, match="encoder must be exactly TargetSumEncoder"):
            GeneralizedXmssScheme(
                config=PROD_CONFIG,
                prf=PROD_PRF,
                hasher=PROD_TWEAK_HASHER,
                encoder=custom_encoder,
                rand=PROD_RAND,
            )

    def test_scheme_rejects_subclass_rand(self) -> None:
        """GeneralizedXmssScheme rejects Rand subclass."""

        class CustomRand(Rand):
            pass

        custom_rand = Rand.__new__(CustomRand)
        custom_rand.__dict__.update(PROD_RAND.__dict__)

        with pytest.raises(TypeError, match="rand must be exactly Rand"):
            GeneralizedXmssScheme(
                config=PROD_CONFIG,
                prf=PROD_PRF,
                hasher=PROD_TWEAK_HASHER,
                encoder=PROD_TARGET_SUM_ENCODER,
                rand=custom_rand,
            )

    def test_scheme_rejects_extra_fields(self) -> None:
        """GeneralizedXmssScheme rejects extra fields."""
        with pytest.raises(ValidationError):
            GeneralizedXmssScheme(
                config=PROD_CONFIG,
                prf=PROD_PRF,
                hasher=PROD_TWEAK_HASHER,
                encoder=PROD_TARGET_SUM_ENCODER,
                rand=PROD_RAND,
                extra_field="should_fail",  # type: ignore[unknown-argument]
            )


class TestPoseidonXmssStrictTypes:
    """Tests for PoseidonXmss strict type checking."""

    def test_poseidon_accepts_exact_types(self) -> None:
        """PoseidonXmss initialization succeeds with exact types."""
        poseidon = PoseidonXmss(params16=PROD_POSEIDON.params16, params24=PROD_POSEIDON.params24)
        assert poseidon.params16 == PROD_POSEIDON.params16

    def test_poseidon_rejects_subclass_params16(self) -> None:
        """PoseidonXmss rejects Poseidon2Params subclass for params16."""
        from lean_spec.subspecs.poseidon2.permutation import Poseidon2Params

        class CustomParams(Poseidon2Params):
            pass

        custom_params = Poseidon2Params.__new__(CustomParams)
        custom_params.__dict__.update(PROD_POSEIDON.params16.__dict__)

        with pytest.raises(TypeError, match="params16 must be exactly Poseidon2Params"):
            PoseidonXmss(params16=custom_params, params24=PROD_POSEIDON.params24)

    def test_poseidon_rejects_subclass_params24(self) -> None:
        """PoseidonXmss rejects Poseidon2Params subclass for params24."""
        from lean_spec.subspecs.poseidon2.permutation import Poseidon2Params

        class CustomParams(Poseidon2Params):
            pass

        custom_params = Poseidon2Params.__new__(CustomParams)
        custom_params.__dict__.update(PROD_POSEIDON.params24.__dict__)

        with pytest.raises(TypeError, match="params24 must be exactly Poseidon2Params"):
            PoseidonXmss(params16=PROD_POSEIDON.params16, params24=custom_params)

    def test_poseidon_rejects_wrong_type_params16(self) -> None:
        """PoseidonXmss rejects completely wrong type for params16."""

        class RandomClass:
            pass

        with pytest.raises((TypeError, ValidationError)):
            PoseidonXmss(params16=RandomClass(), params24=PROD_POSEIDON.params24)  # type: ignore[arg-type]

    def test_poseidon_rejects_wrong_type_params24(self) -> None:
        """PoseidonXmss rejects completely wrong type for params24."""

        class RandomClass:
            pass

        with pytest.raises((TypeError, ValidationError)):
            PoseidonXmss(params16=PROD_POSEIDON.params16, params24=RandomClass())  # type: ignore[arg-type]

    def test_poseidon_frozen(self) -> None:
        """PoseidonXmss is immutable (frozen)."""
        with pytest.raises(ValidationError):
            PROD_POSEIDON.params16 = PROD_POSEIDON.params24


class TestMessageHasherStrictTypes:
    """Tests for MessageHasher strict type checking."""

    def test_message_hasher_accepts_exact_types(self) -> None:
        """MessageHasher initialization succeeds with exact types."""
        hasher = MessageHasher(config=PROD_CONFIG, poseidon=PROD_POSEIDON)
        assert hasher.config == PROD_CONFIG

    def test_message_hasher_rejects_subclass_config(self) -> None:
        """MessageHasher rejects XmssConfig subclass."""

        class CustomConfig(XmssConfig):
            pass

        custom_config = XmssConfig.__new__(CustomConfig)
        custom_config.__dict__.update(PROD_CONFIG.__dict__)

        with pytest.raises(TypeError, match="config must be exactly XmssConfig"):
            MessageHasher(config=custom_config, poseidon=PROD_POSEIDON)

    def test_message_hasher_rejects_subclass_poseidon(self) -> None:
        """MessageHasher rejects PoseidonXmss subclass."""

        class CustomPoseidon(PoseidonXmss):
            pass

        custom_poseidon = PoseidonXmss.__new__(CustomPoseidon)
        custom_poseidon.__dict__.update(PROD_POSEIDON.__dict__)

        with pytest.raises(TypeError, match="poseidon must be exactly PoseidonXmss"):
            MessageHasher(config=PROD_CONFIG, poseidon=custom_poseidon)

    def test_message_hasher_rejects_wrong_type_config(self) -> None:
        """MessageHasher rejects completely wrong type for config."""

        class RandomClass:
            pass

        with pytest.raises((TypeError, ValidationError)):
            MessageHasher(config=RandomClass(), poseidon=PROD_POSEIDON)  # type: ignore[arg-type]

    def test_message_hasher_rejects_wrong_type_poseidon(self) -> None:
        """MessageHasher rejects completely wrong type for poseidon."""

        class RandomClass:
            pass

        with pytest.raises((TypeError, ValidationError)):
            MessageHasher(config=PROD_CONFIG, poseidon=RandomClass())  # type: ignore[arg-type]

    def test_message_hasher_frozen(self) -> None:
        """MessageHasher is immutable (frozen)."""
        with pytest.raises(ValidationError):
            PROD_MESSAGE_HASHER.config = TEST_CONFIG
