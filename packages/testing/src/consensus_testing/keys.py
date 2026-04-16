"""
XMSS Key Management for Consensus Testing

Management of XMSS key pairs for test validators.

Keys are pre-generated and cached on disk to avoid expensive generation during tests.

Downloading Pre-generated Keys:

    python -m consensus_testing.keys --download --scheme test    # test scheme
    python -m consensus_testing.keys --download --scheme prod    # prod scheme

Regenerating Keys:

    python -m consensus_testing.keys                   # defaults
    python -m consensus_testing.keys --count 20        # more validators
    python -m consensus_testing.keys --max-slot 200    # longer lifetime

File format:

- Each key pair is stored in a separate JSON file with hex-encoded SSZ.
- Directory structure: `test_keys/{scheme}_scheme/{index}.json`
- Each file has four hex-encoded SSZ fields:
  `attestation_public`, `attestation_secret`, `proposal_public`, `proposal_secret`
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import tarfile
import tempfile
import urllib.request
from collections.abc import Iterator, Mapping
from concurrent.futures import ProcessPoolExecutor
from functools import partial
from pathlib import Path
from typing import ClassVar, Literal

from lean_spec.config import LEAN_ENV
from lean_spec.subspecs.containers import AttestationData, ValidatorIndex, ValidatorIndices
from lean_spec.subspecs.containers.block.types import (
    AggregatedAttestations,
    AttestationSignatures,
)
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.koalabear import Fp
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof
from lean_spec.subspecs.xmss.constants import TARGET_CONFIG
from lean_spec.subspecs.xmss.containers import PublicKey, SecretKey, Signature, ValidatorKeyPair
from lean_spec.subspecs.xmss.interface import (
    PROD_SIGNATURE_SCHEME,
    TEST_SIGNATURE_SCHEME,
    GeneralizedXmssScheme,
)
from lean_spec.subspecs.xmss.types import (
    HashDigestList,
    HashDigestVector,
    HashTreeOpening,
    Randomness,
)
from lean_spec.types import Bytes32, Uint64

SecretField = Literal["attestation_secret", "proposal_secret"]
"""Discriminator for which secret key to load from a validator key pair."""

KEY_DOWNLOAD_URLS = {
    "test": "https://github.com/leanEthereum/leansig-test-keys/releases/download/leanSpec-2c691ba6/test_scheme.tar.gz",
    "prod": "https://github.com/leanEthereum/leansig-test-keys/releases/download/leanSpec-2c691ba6/prod_scheme.tar.gz",
}
"""
GitHub release URLs for pre-generated key archives.

Keyed by scheme name ("test" or "prod").
Each URL points to a tar.gz containing per-validator JSON files.
"""

LEAN_ENV_TO_SCHEMES: dict[str, GeneralizedXmssScheme] = {
    "test": TEST_SIGNATURE_SCHEME,
    "prod": PROD_SIGNATURE_SCHEME,
}
"""
Maps short scheme names to their XMSS scheme instances.

Used for:

- CLI argument validation
- Deriving on-disk directory names for cached keys
- Keying the per-scheme manager cache in test fixtures
"""


def create_dummy_signature() -> Signature:
    """
    Create a structurally valid but cryptographically meaningless signature.

    All fields are zero-filled.
    The result has correct dimensions so it passes structural checks,
    but it will fail any cryptographic verification.

    Returns:
        A zero-valued signature with correct field sizes.
    """
    # Build a single zero-filled hash digest with the scheme's hash length.
    zero_digest = HashDigestVector(data=[Fp(0)] * TARGET_CONFIG.HASH_LEN_FE)

    # The Merkle authentication path needs one sibling per tree level.
    #
    # The tree height equals the log of the key lifetime.
    siblings = HashDigestList(data=[zero_digest] * TARGET_CONFIG.LOG_LIFETIME)

    # Winternitz one-time signatures use one hash chain per dimension.
    hashes = HashDigestList(data=[zero_digest] * TARGET_CONFIG.DIMENSION)

    # Assemble a complete signature with all components zeroed out.
    return Signature(
        path=HashTreeOpening(siblings=siblings),
        rho=Randomness(data=[Fp(0)] * TARGET_CONFIG.RAND_LEN_FE),
        hashes=hashes,
    )


DEFAULT_MAX_SLOT = Slot(10)
"""
Default max slot for the shared key manager.

Slot 10 is high enough for most unit tests while keeping key generation fast.
"""

NUM_VALIDATORS: int = 12
"""
Default number of validator key pairs.

Twelve validators is enough to exercise committee logic while keeping
key generation and test execution fast.
"""

CLI_DEFAULT_MAX_SLOT = Slot(100)
"""
Maximum slot when generating keys via CLI (inclusive).

One hundred slots provides ample signing headroom for typical test scenarios.
"""


def get_keys_dir(scheme_name: str) -> Path:
    """
    Resolve the on-disk directory that holds key files for a scheme.

    Args:
        scheme_name: Short scheme identifier (e.g. "test" or "prod").

    Returns:
        Absolute path to the scheme's key directory.
    """
    return Path(__file__).parent / "test_keys" / f"{scheme_name}_scheme"


class XmssKeyManager:
    """
    Stateful manager for XMSS signing in tests.

    XMSS is a stateful signature scheme.

    Each signing operation consumes a one-time leaf and advances the key state forward.
    This manager tracks that state across slots and validators.

    Keys are lazily loaded from disk on first access, with a three-tier cache:

    - Raw JSON (lightweight hex strings, ~2.7 KB per validator)
    - Deserialized public keys only (avoids the heavy secret key objects)
    - Advanced secret key state as compact SSZ bytes
    """

    __slots__ = (
        "max_slot",
        "scheme_name",
        "scheme",
        "_keys_dir",
        "_json_cache",
        "_public_cache",
        "_available_indices",
        "_secret_state",
    )

    _cache: ClassVar[dict[str, XmssKeyManager]] = {}
    """
    Per-scheme singleton cache for shared managers.

    Replaced when a caller requests a larger max slot than what is cached.
    """

    @classmethod
    def shared(cls, max_slot: Slot = DEFAULT_MAX_SLOT) -> XmssKeyManager:
        """
        Return a shared manager, creating or replacing it as needed.

        The cache holds one manager per scheme.
        If the cached manager already covers the requested slot range, reuse it.
        Otherwise, create a fresh one with the wider range.

        Args:
            max_slot: Highest slot the manager must support. Defaults to 10.

        Returns:
            A manager valid for at least the requested slot range.
        """
        # A cached manager is usable if its range covers the requested max slot.
        cached = cls._cache.get(LEAN_ENV)
        if cached is not None and cached.max_slot >= max_slot:
            return cached

        # No suitable cached manager exists. Build a new one and cache it.
        manager = cls(max_slot=max_slot, scheme_name=LEAN_ENV)
        cls._cache[LEAN_ENV] = manager
        return manager

    @classmethod
    def reset_signing_state(cls, scheme_name: str | None = None) -> None:
        """
        Clear advanced secret-key state from the cached manager.

        XMSS keys are stateful — signing advances the key past used slots.
        Without resetting, a test that signs at high slots poisons the cache
        for later tests that need low-slot signatures.

        Only the mutable signing state is cleared. The JSON and public-key
        caches are immutable and preserved to avoid expensive re-loading.

        Args:
            scheme_name: Scheme entry to reset. Defaults to the current LEAN_ENV.
        """
        cached = cls._cache.get(LEAN_ENV if scheme_name is None else scheme_name)
        if cached is not None:
            cached._secret_state.clear()

    def __init__(
        self,
        max_slot: Slot = DEFAULT_MAX_SLOT,
        scheme_name: str = "test",
    ) -> None:
        """Initialize with a scheme name and maximum slot for key validity."""
        if scheme_name not in LEAN_ENV_TO_SCHEMES:
            raise ValueError(f"Unknown scheme: {scheme_name!r}")
        self.max_slot = max_slot
        self.scheme_name = scheme_name
        self.scheme = LEAN_ENV_TO_SCHEMES[scheme_name]
        self._keys_dir = get_keys_dir(scheme_name)

        # Raw JSON cache: hex-encoded SSZ strings, very lightweight.
        self._json_cache: dict[ValidatorIndex, dict[str, str]] = {}

        # Deserialized public key pairs, still avoids secret key overhead.
        self._public_cache: dict[ValidatorIndex, tuple[PublicKey, PublicKey]] = {}

        # Populated lazily on first directory scan.
        self._available_indices: set[ValidatorIndex] | None = None

        # Advanced secret key state cached as raw SSZ bytes.
        # Raw bytes (~2.7 KB each) instead of deserialized objects (~370 MB each)
        # to avoid holding massive Pydantic model trees in memory.
        self._secret_state: dict[tuple[ValidatorIndex, SecretField], bytes] = {}

    def _scan_indices(self) -> set[ValidatorIndex]:
        """
        Discover which validator indices have key files on disk.

        The result is cached after the first call.

        Returns:
            Set of validator indices with available key files.

        Raises:
            FileNotFoundError: If the directory is missing or empty.
        """
        if self._available_indices is None:
            # Verify the key directory exists before scanning.
            if not self._keys_dir.exists():
                raise FileNotFoundError(
                    f"Keys directory not found: {self._keys_dir} - "
                    f"Run: python -m consensus_testing.keys --scheme {self.scheme_name}"
                )

            # Each JSON file is named by its validator index (e.g. "0.json").
            self._available_indices = {
                ValidatorIndex(int(f.stem)) for f in self._keys_dir.glob("*.json")
            }

            # An empty directory is as bad as a missing one.
            if not self._available_indices:
                raise FileNotFoundError(
                    f"No key files found in: {self._keys_dir} - "
                    f"Run: python -m consensus_testing.keys --scheme {self.scheme_name}"
                )
        return self._available_indices

    def _load_json(self, idx: ValidatorIndex) -> dict[str, str]:
        """
        Load raw JSON for a single validator, caching the result.

        The JSON contains four hex-encoded SSZ fields.
        Keeping them as strings avoids the cost of deserializing secret keys.

        Args:
            idx: Validator index to load.

        Returns:
            Dictionary of hex-encoded SSZ field strings.

        Raises:
            KeyError: If no key file exists for the index.
        """
        if idx not in self._json_cache:
            # Resolve the per-validator JSON file path.
            key_file = self._keys_dir / f"{idx}.json"
            try:
                with key_file.open() as f:
                    self._json_cache[idx] = json.load(f)
            except FileNotFoundError:
                raise KeyError(f"Key file not found: {key_file}") from None
        return self._json_cache[idx]

    def _get_secret_key(self, idx: ValidatorIndex, field: SecretField) -> SecretKey:
        """
        Deserialize a single secret key from disk.

        Only the requested field is decoded into a full Python object.
        The other three fields remain as lightweight hex strings in the cache.

        Args:
            idx: Validator index to look up.
            field: Which secret key to decode (attestation or proposal).

        Returns:
            The deserialized secret key.
        """
        # Load the raw JSON (cached), then decode only the requested field.
        data = self._load_json(idx)
        return SecretKey.decode_bytes(bytes.fromhex(data[field]))

    def __getitem__(self, idx: ValidatorIndex) -> ValidatorKeyPair:
        """
        Fully deserialize a key pair including secrets.

        Prefer using the public-key or signing accessors to avoid loading
        heavy secret key objects unnecessarily.
        """
        try:
            return ValidatorKeyPair.from_dict(self._load_json(idx))
        except KeyError:
            raise KeyError(f"Validator {idx} not found (available: {len(self)})") from None

    def __contains__(self, idx: object) -> bool:
        """Check whether a validator index has keys on disk."""
        if not isinstance(idx, ValidatorIndex):
            return False
        return idx in self._scan_indices()

    def __len__(self) -> int:
        """Return the number of available validator key pairs."""
        return len(self._scan_indices())

    def __iter__(self) -> Iterator[ValidatorIndex]:
        """Iterate over validator indices in ascending order."""
        return iter(sorted(self._scan_indices()))

    def get_public_keys(self, idx: ValidatorIndex) -> tuple[PublicKey, PublicKey]:
        """
        Return attestation and proposal public keys without touching secrets.

        Only the public key portions are deserialized from the hex JSON.
        Secret keys (~2.7 KB raw, ~370 MB as Python objects) are not touched.

        Args:
            idx: Validator index to look up.

        Returns:
            Tuple of (attestation public key, proposal public key).
        """
        if idx not in self._public_cache:
            # Decode only the two public key fields from the raw JSON.
            data = self._load_json(idx)
            self._public_cache[idx] = (
                PublicKey.decode_bytes(bytes.fromhex(data["attestation_public"])),
                PublicKey.decode_bytes(bytes.fromhex(data["proposal_public"])),
            )
        return self._public_cache[idx]

    def _sign_with_secret(
        self,
        validator_id: ValidatorIndex,
        slot: Slot,
        message: Bytes32,
        secret_field: SecretField,
    ) -> Signature:
        """
        Core signing logic shared by attestation and proposal paths.

        XMSS keys have a "prepared interval" -- the range of slots the key
        can currently sign for. If the target slot falls outside that range,
        the key state must be advanced forward until the slot is covered.

        Memory strategy:

        1. Deserialize the secret key from cached bytes or disk
        2. Advance and sign (only one full key object in memory)
        3. Re-serialize to compact bytes (~2.7 KB) for caching

        Args:
            validator_id: Which validator's key to use.
            slot: Target slot to sign for.
            message: The 32-byte message digest to sign.
            secret_field: Which secret key (attestation or proposal) to advance.

        Raises:
            ValueError: If the slot exceeds the key's total lifetime.
        """
        cache_key = (validator_id, secret_field)

        # Deserialize the secret key from either the byte cache or disk.
        if cache_key in self._secret_state:
            sk = SecretKey.decode_bytes(self._secret_state[cache_key])
        else:
            sk = self._get_secret_key(validator_id, secret_field)

        # Advance the key state until the target slot falls within the prepared interval.
        #
        # Each advancement step extends the interval by consuming the next one-time signing leaf.
        prepared = self.scheme.get_prepared_interval(sk)
        while int(slot) not in prepared:
            activation = self.scheme.get_activation_interval(sk)

            # If the prepared interval already reaches the activation boundary,
            # no further advancement is possible, the key is exhausted.
            if prepared.stop >= activation.stop:
                raise ValueError(f"Slot {slot} exceeds key lifetime {activation.stop}")

            sk = self.scheme.advance_preparation(sk)
            prepared = self.scheme.get_prepared_interval(sk)

        # Produce the signature for the target slot.
        signature = self.scheme.sign(sk, slot, message)

        # Re-serialize the advanced key state to compact bytes for caching.
        # This drops the full Python object tree from memory immediately.
        self._secret_state[cache_key] = sk.encode_bytes()

        return signature

    def sign_attestation_data(
        self,
        validator_id: ValidatorIndex,
        attestation_data: AttestationData,
    ) -> Signature:
        """
        Sign attestation data using the validator's attestation key.

        Advances only the attestation key state.
        The proposal key remains untouched.

        Args:
            validator_id: Which validator signs.
            attestation_data: The attestation to sign.

        Returns:
            XMSS signature over the attestation data root.

        Raises:
            ValueError: If the attestation slot exceeds key lifetime.
        """
        # Derive the message digest from the attestation data and delegate
        # to the shared signing logic with the attestation secret.
        return self._sign_with_secret(
            validator_id,
            attestation_data.slot,
            hash_tree_root(attestation_data),
            "attestation_secret",
        )

    def sign_block_root(
        self,
        validator_id: ValidatorIndex,
        slot: Slot,
        block_root: Bytes32,
    ) -> Signature:
        """
        Sign a block root using the validator's proposal key.

        Advances only the proposal key state.
        The attestation key remains untouched.

        Args:
            validator_id: Which validator signs.
            slot: Slot of the block being proposed.
            block_root: The hash tree root of the block.

        Returns:
            XMSS signature over the block root.

        Raises:
            ValueError: If the slot exceeds key lifetime.
        """
        return self._sign_with_secret(validator_id, slot, block_root, "proposal_secret")

    def sign_and_aggregate(
        self,
        validator_ids: list[ValidatorIndex],
        attestation_data: AttestationData,
    ) -> AggregatedSignatureProof:
        """
        Sign attestation data with each validator and aggregate into a single proof.

        Convenience method for the common sign-each-validator-then-aggregate pattern.

        Args:
            validator_ids: Validators to sign with.
            attestation_data: The attestation data to sign.

        Returns:
            Aggregated signature proof combining all validators' signatures.
        """
        raw_xmss = [
            (
                self.get_public_keys(vid)[0],
                self.sign_attestation_data(vid, attestation_data),
            )
            for vid in validator_ids
        ]

        xmss_participants = ValidatorIndices(data=validator_ids).to_aggregation_bits()

        return AggregatedSignatureProof.aggregate(
            xmss_participants=xmss_participants,
            children=[],
            raw_xmss=raw_xmss,
            message=hash_tree_root(attestation_data),
            slot=attestation_data.slot,
        )

    def build_attestation_signatures(
        self,
        aggregated_attestations: AggregatedAttestations,
        signature_lookup: Mapping[AttestationData, Mapping[ValidatorIndex, Signature]]
        | None = None,
    ) -> AttestationSignatures:
        """
        Produce aggregated signature proofs for a list of attestations.

        For each aggregated attestation:

        1. Identify participating validators from the aggregation bitfield
        2. Collect each participant's public key and individual signature
        3. Combine them into a single aggregated proof for the leanVM verifier

        Pre-computed signatures can be supplied via the lookup to avoid
        redundant signing. Missing signatures are computed on the fly.

        Args:
            aggregated_attestations: Attestations with aggregation bitfields set.
            signature_lookup: Optional pre-computed signatures keyed by
                attestation data then validator index.

        Returns:
            One aggregated signature proof per attestation.
        """
        lookup = signature_lookup or {}

        proofs: list[AggregatedSignatureProof] = []
        for agg in aggregated_attestations:
            # Decode which validators participated from the bitfield.
            validator_ids = agg.aggregation_bits.to_validator_indices()

            # Try the lookup first for pre-computed signatures.
            # Fall back to signing on the fly for any missing entries.
            sigs_for_data = lookup.get(agg.data, {})

            # Collect the attestation public key for each participant.
            public_keys = [self.get_public_keys(vid)[0] for vid in validator_ids]

            # Gather individual signatures, computing any that are missing.
            signatures = [
                sigs_for_data.get(vid) or self.sign_attestation_data(vid, agg.data)
                for vid in validator_ids
            ]

            # Produce a single aggregated proof that the leanVM can verify
            # in one pass over all participants.
            proof = AggregatedSignatureProof.aggregate(
                xmss_participants=agg.aggregation_bits,
                children=[],
                raw_xmss=list(zip(public_keys, signatures, strict=True)),
                message=hash_tree_root(agg.data),
                slot=agg.data.slot,
            )
            proofs.append(proof)

        return AttestationSignatures(data=proofs)


def _generate_single_keypair(
    scheme: GeneralizedXmssScheme, num_slots: int, index: int
) -> ValidatorKeyPair:
    """
    Generate attestation and proposal key pairs for one validator.

    Defined at module level so it can be pickled for multiprocessing.

    Args:
        scheme: XMSS scheme instance to use for key generation.
        num_slots: Total number of slots the keys must cover.
        index: Validator index (used only for progress logging).

    Returns:
        Complete key pair with both attestation and proposal keys.
    """
    print(f"Starting key #{index} generation...")

    # Generate two independent key pairs: one for attestations, one for proposals.
    #
    # Separate keys allow signing both roles within the same slot
    # without exhausting a one-time leaf.
    att_pk, att_sk = scheme.key_gen(Slot(0), Uint64(num_slots))
    prop_pk, prop_sk = scheme.key_gen(Slot(0), Uint64(num_slots))

    return ValidatorKeyPair(
        attestation_public=att_pk,
        attestation_secret=att_sk,
        proposal_public=prop_pk,
        proposal_secret=prop_sk,
    )


def _generate_keys(lean_env: str, count: int, max_slot: int) -> None:
    """
    Generate XMSS key pairs in parallel and write each to a separate file.

    Each validator gets its own JSON file to keep individual files small,
    which matters especially for production-scheme keys.

    Args:
        lean_env: Scheme name (e.g. "test" or "prod").
        count: Number of validator key pairs to generate.
        max_slot: Maximum signable slot (key lifetime = max_slot + 1 slots).
    """
    scheme = LEAN_ENV_TO_SCHEMES[lean_env]
    keys_dir = get_keys_dir(lean_env)
    num_slots = max_slot + 1
    num_workers = os.cpu_count() or 1

    print(
        f"Generating {count} XMSS key pairs for {lean_env} environment "
        f"({num_slots} slots) using {num_workers} cores..."
    )

    # Ensure the output directory exists.
    keys_dir.mkdir(parents=True, exist_ok=True)

    # Remove stale key files from previous runs that may have generated
    # a different number of keys.
    for old_file in keys_dir.glob("*.json"):
        old_file.unlink()

    # Generate key pairs in parallel across all CPU cores.
    # Results arrive in index order thanks to executor.map.
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        worker_func = partial(_generate_single_keypair, scheme, num_slots)
        for idx, key_pair in enumerate(executor.map(worker_func, range(count))):
            # Serialize and write each key pair as a separate JSON file named by index.
            key_file = keys_dir / f"{idx}.json"
            key_file.write_text(json.dumps(key_pair.to_dict(), indent=2))

    print(f"Saved {count} key pairs to {keys_dir}/")


def download_keys(scheme: str) -> None:
    """
    Download pre-generated key pairs from a GitHub release.

    Downloads a tar.gz archive for the specified scheme, removes any
    existing keys for that scheme, and extracts the archive in place.

    Args:
        scheme: Scheme name ("test" or "prod").
    """
    base_dir = Path(__file__).parent / "test_keys"
    url = KEY_DOWNLOAD_URLS[scheme]

    print(f"Downloading {scheme} keys from {url}...")

    # Download to a temporary file to avoid partial-write corruption.
    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp_file:
        tmp_path = Path(tmp_file.name)
        try:
            # Stream the response directly into the temp file.
            with urllib.request.urlopen(url) as response:
                shutil.copyfileobj(response, tmp_file)

            # Remove any existing keys for this scheme before extracting.
            target_dir = base_dir / f"{scheme}_scheme"
            if target_dir.exists():
                shutil.rmtree(target_dir)
            base_dir.mkdir(parents=True, exist_ok=True)

            # Extract the archive into the base directory.
            # The archive root is the scheme directory itself.
            with tarfile.open(tmp_path, "r:gz") as tar:
                tar.extractall(path=base_dir, filter="data")

            print(f"Extracted {scheme} keys to {target_dir}/")
        finally:
            # Always clean up the temporary download file.
            tmp_path.unlink(missing_ok=True)

    print("Download complete!")


def main() -> None:
    """CLI entry point for generating or downloading test keys."""
    parser = argparse.ArgumentParser(
        description="Generate XMSS key pairs for consensus testing",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--download",
        action="store_true",
        help="Download pre-generated keys from a GitHub release",
    )
    parser.add_argument(
        "--scheme",
        choices=LEAN_ENV_TO_SCHEMES.keys(),
        default="test",
        help="XMSS scheme to use",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=NUM_VALIDATORS,
        help="Number of validator key pairs",
    )
    parser.add_argument(
        "--max-slot",
        type=int,
        default=int(CLI_DEFAULT_MAX_SLOT),
        help="Maximum slot (key lifetime = max_slot + 1)",
    )
    args = parser.parse_args()

    # Download pre-generated keys instead of generating locally.
    if args.download:
        download_keys(scheme=args.scheme)
        return

    # Generate fresh keys with the specified parameters.
    _generate_keys(lean_env=args.scheme, count=args.count, max_slot=args.max_slot)


if __name__ == "__main__":
    main()
