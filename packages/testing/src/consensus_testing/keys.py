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
- The top-level object has two roles, each containing a public and secret blob:
  `{"attestation_keypair": {"public_key": ..., "secret_key": ...},
    "proposal_keypair":    {"public_key": ..., "secret_key": ...}}`
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
from lean_spec.spec.crypto.koalabear import Fp
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.crypto.xmss.aggregation import TypeOneMultiSignature
from lean_spec.spec.crypto.xmss.constants import TARGET_CONFIG
from lean_spec.spec.crypto.xmss.containers import (
    PublicKey,
    SecretKey,
    Signature,
    ValidatorKeyPair,
)
from lean_spec.spec.crypto.xmss.interface import (
    PROD_SIGNATURE_SCHEME,
    TEST_SIGNATURE_SCHEME,
    GeneralizedXmssScheme,
)
from lean_spec.spec.crypto.xmss.types import (
    HashDigestList,
    HashDigestVector,
    HashTreeOpening,
    Randomness,
)
from lean_spec.spec.forks import Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import AggregatedAttestations, AttestationData
from lean_spec.spec.ssz import Bytes32, Uint64

KeyRole = Literal["attestation", "proposal"]
"""Discriminator for which signing role's key to load from a validator key pair."""

KEY_DOWNLOAD_URLS = {
    "test": "https://github.com/leanEthereum/leansig-test-keys/releases/download/latest/test_scheme.tar.gz",
    "prod": "https://github.com/leanEthereum/leansig-test-keys/releases/download/latest/prod_scheme.tar.gz",
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

NUM_VALIDATORS: int = 8
"""
Default number of validator key pairs.

Eight validators is enough to exercise committee logic and 2/3 supermajority
thresholds while keeping key generation and test execution fast.
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
    - Advanced secret key state as live Python objects
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

        # Raw JSON cache: nested dict of hex-encoded SSZ strings, very lightweight.
        self._json_cache: dict[ValidatorIndex, dict[str, dict[str, str]]] = {}

        # Deserialized public key pairs, still avoids secret key overhead.
        self._public_cache: dict[ValidatorIndex, tuple[PublicKey, PublicKey]] = {}

        # Populated lazily on first directory scan.
        self._available_indices: set[ValidatorIndex] | None = None

        # Advanced secret-key state held as live Python objects.
        self._secret_state: dict[tuple[ValidatorIndex, KeyRole], SecretKey] = {}

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

    def _load_json(self, idx: ValidatorIndex) -> dict[str, dict[str, str]]:
        """
        Load raw JSON for a single validator, caching the result.

        The JSON has two role keys, each holding hex-encoded SSZ blobs.
        Keeping them as strings avoids the cost of deserializing secret keys.

        Args:
            idx: Validator index to load.

        Returns:
            Nested dictionary of hex-encoded SSZ strings keyed by role then field.

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

    def _get_secret_key(self, idx: ValidatorIndex, role: KeyRole) -> SecretKey:
        """
        Deserialize a single secret key from disk.

        Only the requested role's secret is decoded into a full Python object.
        The other three fields remain as lightweight hex strings in the cache.

        Args:
            idx: Validator index to look up.
            role: Which signing role's secret to decode (attestation or proposal).

        Returns:
            The deserialized secret key.
        """
        # Load the raw JSON (cached), then decode only the requested field.
        data = self._load_json(idx)
        return SecretKey.decode_bytes(bytes.fromhex(data[f"{role}_keypair"]["secret_key"]))

    def __getitem__(self, idx: ValidatorIndex) -> ValidatorKeyPair:
        """
        Fully deserialize a key pair including secrets.

        Prefer using the public-key or signing accessors to avoid loading
        heavy secret key objects unnecessarily.
        """
        try:
            return ValidatorKeyPair.model_validate(self._load_json(idx))
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
                PublicKey.decode_bytes(bytes.fromhex(data["attestation_keypair"]["public_key"])),
                PublicKey.decode_bytes(bytes.fromhex(data["proposal_keypair"]["public_key"])),
            )
        return self._public_cache[idx]

    def _sign_with_secret(
        self,
        validator_id: ValidatorIndex,
        slot: Slot,
        message: Bytes32,
        role: KeyRole,
    ) -> Signature:
        """
        Core signing logic shared by attestation and proposal paths.

        XMSS keys have a "prepared interval" -- the range of slots the key
        can currently sign for. If the target slot falls outside that range,
        the key state must be advanced forward until the slot is covered.

        Memory strategy:

        1. On cache miss, deserialize the key once from disk
        2. Advance and sign
        3. Keep the advanced object for the next sign

        Args:
            validator_id: Which validator's key to use.
            slot: Target slot to sign for.
            message: The 32-byte message digest to sign.
            role: Which signing role's key (attestation or proposal) to advance.

        Raises:
            ValueError: If the slot exceeds the key's total lifetime.
        """
        cache_key = (validator_id, role)

        # Reuse the cached object directly when present, else decode from disk.
        # Holding the object avoids the bytes-to-object round-trip on every sign.
        # That round-trip dominated prod-scheme runtime under the compact-bytes cache.
        if cache_key in self._secret_state:
            sk = self._secret_state[cache_key]
        else:
            sk = self._get_secret_key(validator_id, role)

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

        # Park the advanced object back in the cache for the next sign.
        self._secret_state[cache_key] = sk

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
            "attestation",
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
        return self._sign_with_secret(validator_id, slot, block_root, "proposal")

    def sign_and_aggregate(
        self,
        validator_ids: list[ValidatorIndex],
        attestation_data: AttestationData,
    ) -> TypeOneMultiSignature:
        """
        Sign attestation data with each validator and aggregate into a Type-1 proof.

        Each validator's XMSS attestation key signs the attestation data
        root. The signatures are then handed to the multi-signature
        binding to produce a single cryptographically valid Type-1 proof
        binding all participants to (data, slot).

        Args:
            validator_ids: Validators to sign with.
            attestation_data: The attestation data to sign.

        Returns:
            Cryptographically valid Type-1 proof covering validator_ids.
        """
        raw_xmss = [
            (
                vid,
                self.get_public_keys(vid)[0],
                self.sign_attestation_data(vid, attestation_data),
            )
            for vid in validator_ids
        ]
        return TypeOneMultiSignature.aggregate(
            children=[],
            raw_xmss=raw_xmss,
            message=hash_tree_root(attestation_data),
            slot=attestation_data.slot,
        )

    def build_attestation_proofs(
        self,
        aggregated_attestations: AggregatedAttestations,
        signature_lookup: Mapping[AttestationData, Mapping[ValidatorIndex, Signature]]
        | None = None,
    ) -> list[TypeOneMultiSignature]:
        """
        Produce Type-1 proofs aligned with the given attestations.

        For each aggregated attestation:

        1. Identify participating validators from the aggregation bitfield.
        2. Collect each participant's attestation public key and signature.
        3. Combine them into a single Type-1 single-message proof via the
           multi-signature binding.

        Pre-computed signatures can be supplied via the lookup to avoid
        redundant signing. Missing entries are signed on the fly.

        Args:
            aggregated_attestations: Attestations with aggregation bitfields set.
            signature_lookup: Optional pre-computed signatures keyed by
                attestation data then validator index.

        Returns:
            One Type-1 single-message proof per attestation, parallel to the input.
        """
        lookup = signature_lookup or {}

        proofs: list[TypeOneMultiSignature] = []
        for agg in aggregated_attestations:
            # Decode which validators participated from the bitfield.
            validator_ids = agg.aggregation_bits.to_validator_indices()

            # Try the lookup first for pre-computed signatures.
            # Fall back to signing on the fly for any missing entries.
            sigs_for_data = lookup.get(agg.data, {})

            # Collect the attestation public keys for each participant.
            public_keys = [self.get_public_keys(vid)[0] for vid in validator_ids]

            # Gather individual signatures, computing any that are missing.
            signatures = [
                sigs_for_data.get(vid) or self.sign_attestation_data(vid, agg.data)
                for vid in validator_ids
            ]

            # Produce a single aggregated proof that the leanVM can verify
            # in one pass over all participants.
            proofs.append(
                TypeOneMultiSignature.aggregate(
                    children=[],
                    raw_xmss=list(zip(validator_ids, public_keys, signatures, strict=True)),
                    message=hash_tree_root(agg.data),
                    slot=agg.data.slot,
                )
            )

        return proofs


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
    import sys
    import time

    # Generate two independent key pairs: one for attestations, one for proposals.
    #
    # Separate keys allow signing both roles within the same slot
    # without exhausting a one-time leaf.
    start = time.monotonic()
    print(f"[key #{index}] generating attestation key...", flush=True)
    attestation_keypair = scheme.key_gen(Slot(0), Uint64(num_slots))

    elapsed = time.monotonic() - start
    print(
        f"[key #{index}] attestation key done ({elapsed:.0f}s), generating proposal key...",
        flush=True,
    )
    proposal_keypair = scheme.key_gen(Slot(0), Uint64(num_slots))

    elapsed = time.monotonic() - start
    print(f"[key #{index}] done ({elapsed:.0f}s)", file=sys.stderr, flush=True)

    return ValidatorKeyPair(
        attestation_keypair=attestation_keypair, proposal_keypair=proposal_keypair
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
    import time

    gen_start = time.monotonic()
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        worker_func = partial(_generate_single_keypair, scheme, num_slots)
        for idx, key_pair in enumerate(executor.map(worker_func, range(count))):
            elapsed = time.monotonic() - gen_start
            print(f"[{idx + 1}/{count}] saved key #{idx} ({elapsed:.0f}s elapsed)")

            key_file = keys_dir / f"{idx}.json"
            key_file.write_text(key_pair.model_dump_json(indent=2))

    total = time.monotonic() - gen_start
    print(f"Saved {count} key pairs to {keys_dir}/ ({total:.0f}s total)")


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

    # Reserve a temp path; we open it explicitly below so the writer can close
    # before the reader opens.
    tmp_fd, tmp_name = tempfile.mkstemp(suffix=".tar.gz")
    os.close(tmp_fd)
    tmp_path = Path(tmp_name)

    try:
        # Close the writer before opening the reader.
        # Otherwise Python's userspace buffer can withhold the tail of the gzip stream.
        # That produces a near-end decompression failure that looks like a truncated download.
        with urllib.request.urlopen(url) as response, tmp_path.open("wb") as out:
            shutil.copyfileobj(response, out)

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
