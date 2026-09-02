"""CLI for generating or downloading the pre-generated XMSS test keys."""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
import tarfile
import tempfile
import time
import urllib.request
from concurrent.futures import ProcessPoolExecutor
from functools import partial
from pathlib import Path

import click
from ssz import Uint64

from consensus_testing.keys import (
    LEAN_ENV_TO_SCHEMES,
    compute_key_set_digest,
    get_keys_directory,
)
from lean_spec.spec.crypto.xmss.containers import ValidatorKeyPair
from lean_spec.spec.crypto.xmss.interface import GeneralizedXmssScheme
from lean_spec.spec.forks import Slot

KEY_DOWNLOAD_URLS = {
    "test": "https://github.com/leanEthereum/leansig-test-keys/releases/download/latest/test_scheme.tar.gz",
    "prod": "https://github.com/leanEthereum/leansig-test-keys/releases/download/latest/prod_scheme.tar.gz",
}
"""Release archive URL per scheme, each a tar.gz of per-validator key files."""

PINNED_KEY_ARCHIVE_SHA256 = {
    "test": "2d616857f4936cde4e2720fa95a76f2644015390f4b8c188acbaa756f521dac8",
    "prod": "a40aa60fc0c0d1b4c761f19fb1678039400ae318da85f782dd57bc8cc0eb617d",
}
"""SHA-256 of each scheme's key archive, the real pin since the release tag is mutable."""

PINNED_KEY_SET_DIGESTS = {
    "test": "0x49306dfdb6dddd72afe265ec3b20a1901834dde9b3dfe4fee6b4f7ca58c7aa43",
    "prod": "0xc2b5fc4c1f1fbc181ddf07db3df985f79e1dcedcfb7df732ef20863d7cbcf491",
}
"""Expected key-set digest per scheme, guarding on-disk keys the archive checksum cannot see."""

NUM_VALIDATORS: int = 8
"""Default validator count, enough to exercise committee logic and 2/3 thresholds while fast."""

CLI_DEFAULT_MAX_SLOT = Slot(100)
"""Maximum slot when generating keys via CLI, inclusive."""


def _generate_single_keypair(
    scheme: GeneralizedXmssScheme, num_slots: int, index: int
) -> ValidatorKeyPair:
    """
    Generate attestation and proposal key pairs for one validator.

    Defined at module level so it can be pickled for multiprocessing.
    """
    # Separate keys let one validator sign both roles in a slot without exhausting a one-time leaf.
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
    """Generate XMSS key pairs in parallel, one small JSON file per validator."""
    scheme = LEAN_ENV_TO_SCHEMES[lean_env]
    keys_directory = get_keys_directory(lean_env)
    num_slots = max_slot + 1
    num_workers = os.cpu_count() or 1

    print(
        f"Generating {count} XMSS key pairs for {lean_env} environment "
        f"({num_slots} slots) using {num_workers} cores..."
    )

    keys_directory.mkdir(parents=True, exist_ok=True)

    # Drop stale files from a prior run that may have made a different key count.
    for old_file in keys_directory.glob("*.json"):
        old_file.unlink()

    # Results arrive in index order from the parallel map.
    gen_start = time.monotonic()
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        worker_func = partial(_generate_single_keypair, scheme, num_slots)
        for validator_index, key_pair in enumerate(executor.map(worker_func, range(count))):
            elapsed = time.monotonic() - gen_start
            print(
                f"[{validator_index + 1}/{count}] saved key #{validator_index} "
                f"({elapsed:.0f}s elapsed)"
            )

            key_file = keys_directory / f"{validator_index}.json"
            key_file.write_text(key_pair.model_dump_json(indent=2))

    total = time.monotonic() - gen_start
    print(f"Saved {count} key pairs to {keys_directory}/ ({total:.0f}s total)")


def download_keys(scheme: str) -> None:
    """Download a scheme's key archive from a GitHub release and extract it in place."""
    base_directory = get_keys_directory(scheme).parent
    url = KEY_DOWNLOAD_URLS[scheme]

    print(f"Downloading {scheme} keys from {url}...")

    temporary_fd, temporary_name = tempfile.mkstemp(suffix=".tar.gz")
    os.close(temporary_fd)
    tmp_path = Path(temporary_name)

    try:
        # Close the writer before opening the reader.
        # Otherwise a buffered tail can look like a truncated, undecompressable download.
        with urllib.request.urlopen(url) as response, tmp_path.open("wb") as out:
            shutil.copyfileobj(response, out)

        # The release tag is mutable, so verify the pinned checksum before extracting.
        with tmp_path.open("rb") as archive_handle:
            archive_sha256 = hashlib.file_digest(archive_handle, "sha256").hexdigest()
        if archive_sha256 != PINNED_KEY_ARCHIVE_SHA256[scheme]:
            raise RuntimeError(
                f"downloaded {scheme} key archive does not match the pinned checksum\n"
                f"  expected: {PINNED_KEY_ARCHIVE_SHA256[scheme]}\n"
                f"  actual:   {archive_sha256}\n"
                "The release was re-cut upstream. Adopting the new key set requires "
                "updating the pinned checksum and key-set digest on purpose."
            )

        # Extract and verify in scratch first, so a rejected archive never destroys working keys.
        # The archive root is the scheme directory itself.
        with tempfile.TemporaryDirectory() as scratch_name:
            scratch_directory = Path(scratch_name)
            with tarfile.open(tmp_path, "r:gz") as tar:
                tar.extractall(path=scratch_directory, filter="data")

            # The digest catches content drift the checksum pin alone would miss.
            extracted_directory = scratch_directory / f"{scheme}_scheme"
            extracted_digest = compute_key_set_digest(extracted_directory)
            if extracted_digest != PINNED_KEY_SET_DIGESTS[scheme]:
                raise RuntimeError(
                    f"extracted {scheme} key set does not match the pinned digest\n"
                    f"  expected: {PINNED_KEY_SET_DIGESTS[scheme]}\n"
                    f"  actual:   {extracted_digest}\n"
                    "The archive carries a different key set than the canonical one. "
                    "For the test scheme, restore the committed keys from version control."
                )

            # Replace the live key set only after both checks pass.
            target_directory = base_directory / f"{scheme}_scheme"
            if target_directory.exists():
                shutil.rmtree(target_directory)
            base_directory.mkdir(parents=True, exist_ok=True)
            shutil.move(str(extracted_directory), str(target_directory))

        print(f"Extracted {scheme} keys to {target_directory}/")
    finally:
        tmp_path.unlink(missing_ok=True)

    print("Download complete!")


@click.command(
    epilog="""\
\b
Downloading pre-generated keys:
    uv run keys --download --scheme test    # test scheme
    uv run keys --download --scheme prod    # prod scheme
\b
Regenerating keys:
    uv run keys                   # defaults
    uv run keys --count 20        # more validators
    uv run keys --max-slot 200    # longer lifetime
""",
)
@click.option(
    "--download",
    is_flag=True,
    help="Download pre-generated keys from a GitHub release",
)
@click.option(
    "--scheme",
    type=click.Choice(list(LEAN_ENV_TO_SCHEMES)),
    default="test",
    show_default=True,
    help="XMSS scheme to use",
)
@click.option(
    "--count",
    type=int,
    default=NUM_VALIDATORS,
    show_default=True,
    help="Number of validator key pairs",
)
@click.option(
    "--max-slot",
    type=int,
    default=int(CLI_DEFAULT_MAX_SLOT),
    show_default=True,
    help="Maximum slot (key lifetime = max_slot + 1)",
)
def keys(download: bool, scheme: str, count: int, max_slot: int) -> None:
    """Generate XMSS key pairs for consensus testing."""
    if download:
        download_keys(scheme=scheme)
        return

    _generate_keys(lean_env=scheme, count=count, max_slot=max_slot)


if __name__ == "__main__":
    keys()
