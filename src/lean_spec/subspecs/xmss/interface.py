"""
Defines the core interface for the Generalized XMSS signature scheme.

Specification for the high-level functions (`key_gen`, `sign`, `verify`).

This constitutes the public API of the signature scheme.
"""

from __future__ import annotations

from pydantic import model_validator

from lean_spec.config import LEAN_ENV
from lean_spec.subspecs.xmss.target_sum import (
    PROD_TARGET_SUM_ENCODER,
    TEST_TARGET_SUM_ENCODER,
    TargetSumEncoder,
)
from lean_spec.types import StrictBaseModel, Uint64

from ._validation import enforce_strict_types
from .constants import (
    PROD_CONFIG,
    TEST_CONFIG,
    XmssConfig,
)
from .containers import KeyPair, PublicKey, SecretKey, Signature
from .prf import PROD_PRF, TEST_PRF, Prf
from .rand import PROD_RAND, TEST_RAND, Rand
from .subtree import HashSubTree, combined_path, verify_path
from .tweak_hash import (
    PROD_TWEAK_HASHER,
    TEST_TWEAK_HASHER,
    TweakHasher,
)
from .types import HashDigestList, HashDigestVector
from .utils import expand_activation_time


class GeneralizedXmssScheme(StrictBaseModel):
    """
    Instance of the Generalized XMSS signature scheme for a given config.

    This class holds the configuration and component instances needed to
    perform key generation, signing, and verification operations.
    """

    config: XmssConfig
    """Configuration parameters for the XMSS scheme."""

    prf: Prf
    """Pseudorandom function for deriving secret values."""

    hasher: TweakHasher
    """Hash function with tweakable domain separation."""

    encoder: TargetSumEncoder
    """Message encoder that produces valid codewords."""

    rand: Rand
    """Random data generator for key generation."""

    @model_validator(mode="after")
    def _validate_strict_types(self) -> "GeneralizedXmssScheme":
        """Reject subclasses to prevent type confusion attacks."""
        enforce_strict_types(
            self,
            config=XmssConfig,
            prf=Prf,
            hasher=TweakHasher,
            encoder=TargetSumEncoder,
            rand=Rand,
        )
        return self

    def key_gen(self, activation_epoch: Uint64, num_active_epochs: Uint64) -> KeyPair:
        """
        Generates a new cryptographic key pair for a specified range of epochs.

        This is a **randomized** algorithm that establishes a signer's identity using
        the memory-efficient Top-Bottom Tree Traversal approach.

        ### Key Generation Algorithm

        1.  **Expand Activation Time**: Align the requested activation interval to
            `sqrt(LIFETIME)` boundaries to enable efficient tree partitioning.
            This ensures the interval starts at a multiple of `sqrt(LIFETIME)` and
            has a minimum duration of `2 * sqrt(LIFETIME)` epochs.

        2.  **Generate Master Secrets**: Generate PRF key and public parameter `P`.
            The PRF key allows deterministic on-demand regeneration of one-time keys.

        3.  **Generate First Two Bottom Trees**: Create the first two bottom trees
            (covering the initial `2 * sqrt(LIFETIME)` epochs) and keep them in memory.
            Each bottom tree covers `sqrt(LIFETIME)` consecutive epochs.

        4.  **Generate Remaining Bottom Tree Roots**: For all other bottom trees in
            the range, generate only their roots (not the full trees). This saves
            memory since we only need the first two trees for the prepared window.

        5.  **Build Top Tree**: Construct the top tree from all bottom tree roots.
            The top tree's lowest layer contains the bottom tree roots, and it is
            built upward to the global Merkle root.

        ### Memory Efficiency

        Traditional approach: O(LIFETIME) memory
        Top-Bottom approach: O(sqrt(LIFETIME)) memory

        For LOG_LIFETIME=32 (2^32 epochs):
        - Traditional: ~hundreds of GiB
        - Top-Bottom: much more reasonable

        Args:
            activation_epoch: The starting epoch for which this key is valid.
            - Will be aligned downward to `sqrt(LIFETIME)` boundary.
            num_active_epochs: The number of consecutive epochs the key can be used for.
            - Will be rounded up to at least `2 * sqrt(LIFETIME)`.

        Returns:
            A `KeyPair` containing the public and secret keys.

        Note:
            The actual activation epoch and num_active_epochs in the returned SecretKey
            may be larger than requested due to alignment requirements.

        For the formal specification of this process, please refer to:
        - "Hash-Based Multi-Signatures for Post-Quantum Ethereum": https://eprint.iacr.org/2025/055
        - "Technical Note: LeanSig for Post-Quantum Ethereum": https://eprint.iacr.org/2025/1332
        - The canonical Rust implementation: https://github.com/b-wagn/hash-sig
        """
        # Retrieve the scheme's configuration parameters.
        config = self.config

        # Ensure the requested activation range is within the scheme's total supported lifetime.
        if activation_epoch + num_active_epochs > config.LIFETIME:
            raise ValueError("Activation range exceeds the key's lifetime.")

        # Generate the random public parameter `P` and the master PRF key.
        # - `P` ensures hash function outputs are unique to this key pair.
        # - PRF key is the single master secret from which all one-time keys are derived.
        parameter = self.rand.parameter()
        prf_key = self.prf.key_gen()

        # Step 1: Expand and align activation time to sqrt(LIFETIME) boundaries.
        start_bottom_tree_index, end_bottom_tree_index = expand_activation_time(
            config.LOG_LIFETIME, int(activation_epoch), int(num_active_epochs)
        )

        num_bottom_trees = end_bottom_tree_index - start_bottom_tree_index
        leaves_per_bottom_tree = 1 << (config.LOG_LIFETIME // 2)

        # Calculate the actual (expanded) activation epoch and count.
        actual_activation_epoch = start_bottom_tree_index * leaves_per_bottom_tree
        actual_num_active_epochs = num_bottom_trees * leaves_per_bottom_tree

        # Step 2: Generate the first two bottom trees (kept in memory).
        left_bottom_tree = HashSubTree.from_prf_key(
            prf=self.prf,
            hasher=self.hasher,
            rand=self.rand,
            config=config,
            prf_key=prf_key,
            bottom_tree_index=Uint64(start_bottom_tree_index),
            parameter=parameter,
        )
        right_bottom_tree = HashSubTree.from_prf_key(
            prf=self.prf,
            hasher=self.hasher,
            rand=self.rand,
            config=config,
            prf_key=prf_key,
            bottom_tree_index=Uint64(start_bottom_tree_index + 1),
            parameter=parameter,
        )

        # Collect roots for building the top tree.
        bottom_tree_roots: list[HashDigestVector] = [
            left_bottom_tree.root(),
            right_bottom_tree.root(),
        ]

        # Step 3: Generate remaining bottom trees (only their roots).
        for i in range(start_bottom_tree_index + 2, end_bottom_tree_index):
            tree = HashSubTree.from_prf_key(
                prf=self.prf,
                hasher=self.hasher,
                rand=self.rand,
                config=config,
                prf_key=prf_key,
                bottom_tree_index=Uint64(i),
                parameter=parameter,
            )
            bottom_tree_roots.append(tree.root())

        # Step 4: Build the top tree from bottom tree roots.
        top_tree = HashSubTree.new_top_tree(
            hasher=self.hasher,
            rand=self.rand,
            depth=config.LOG_LIFETIME,
            start_bottom_tree_index=Uint64(start_bottom_tree_index),
            parameter=parameter,
            bottom_tree_roots=bottom_tree_roots,
        )

        # Extract the global root.
        root = top_tree.root()

        # Assemble and return the keys.
        pk = PublicKey(root=root, parameter=parameter)
        sk = SecretKey(
            prf_key=prf_key,
            parameter=parameter,
            activation_epoch=Uint64(actual_activation_epoch),
            num_active_epochs=Uint64(actual_num_active_epochs),
            top_tree=top_tree,
            left_bottom_tree_index=Uint64(start_bottom_tree_index),
            left_bottom_tree=left_bottom_tree,
            right_bottom_tree=right_bottom_tree,
        )
        return KeyPair(public=pk, secret=sk)

    def sign(self, sk: SecretKey, epoch: Uint64, message: bytes) -> Signature:
        """
        Produces a digital signature for a given message at a specific epoch.

        This is a **deterministic** algorithm. Calling `sign` twice with the same
        (sk, epoch, message) triple produces the same signature.

        **CRITICAL SECURITY WARNING**: A secret key for a given epoch must **NEVER** be used
        to sign two different messages. Doing so would reveal parts of the secret key
        and allow an attacker to forge signatures. This is the fundamental security
        property of a synchronized (stateful) signature scheme.

        ### Signing Algorithm

        1.  **Message Encoding with Randomness (`rho`)**: The "Target Sum" scheme
            requires the message hash to be encoded into a `codeword` whose digits
            sum to a predefined target. A direct hash of the message is unlikely to
            satisfy this. Therefore, the algorithm repeatedly hashes the message
            combined with deterministic randomness (`rho`) derived from the PRF
            until a valid `codeword` is found.

        2.  **One-Time Signature**: The `codeword` dictates how the one-time signature is
            formed. For each digit `x_i` in the codeword, the signer reveals an intermediate
            hash value by applying the hash function `x_i` times to the secret start of the
            `i`-th hash chain.
            The collection of these intermediate hashes forms the one-time signature.

        3.  **Merkle Path**: The signer retrieves the Merkle authentication path for the leaf
            corresponding to the current `epoch`. This path proves that the one-time public key
            for this epoch is part of the main public key (the Merkle root).

        Args:
            sk: The secret key to use for signing.
            epoch: The epoch for which the signature is being created.
            message: The message to be signed.

        Returns:
            The resulting `Signature` object.

        For the formal specification of this process, please refer to:
        - "Hash-Based Multi-Signatures for Post-Quantum Ethereum": https://eprint.iacr.org/2025/055
        - "Technical Note: LeanSig for Post-Quantum Ethereum": https://eprint.iacr.org/2025/1332
        - The canonical Rust implementation: https://github.com/b-wagn/hash-sig
        """
        # Retrieve the scheme's configuration parameters.
        config = self.config

        # Verify that the secret key is currently active for the requested signing epoch.
        epoch_int = int(epoch)
        activation_int = int(sk.activation_epoch)
        if not (activation_int <= epoch_int < activation_int + int(sk.num_active_epochs)):
            raise ValueError("Key is not active for the specified epoch.")

        # Verify that the epoch is within the prepared interval (covered by loaded bottom trees).
        #
        # With top-bottom tree traversal, only epochs within the prepared interval can be
        # signed without computing additional bottom trees.
        #
        # If the epoch is outside this range, we need to slide the window forward.
        leaves_per_bottom_tree = 1 << (config.LOG_LIFETIME // 2)
        prepared_start = int(sk.left_bottom_tree_index) * leaves_per_bottom_tree
        prepared_end = prepared_start + 2 * leaves_per_bottom_tree
        if not (prepared_start <= epoch_int < prepared_end):
            raise ValueError(
                f"Epoch {epoch} is outside the prepared interval "
                f"[{prepared_start}, {prepared_end}). "
                f"Call advance_preparation() to slide the window forward."
            )

        # Find a valid message encoding.
        #
        # This loop repeatedly tries different randomness `rho` until the encoder
        # produces a valid codeword (i.e., one that meets the target sum constraint).
        #
        # The randomness is deterministically derived from the PRF to ensure
        # that signing is reproducible for the same (sk, epoch, message).
        for attempts in range(config.MAX_TRIES):
            # Derive deterministic randomness `rho` from PRF using the attempt counter.
            rho = self.prf.get_randomness(sk.prf_key, epoch, message, Uint64(attempts))
            # Attempt to encode the message with the deterministic `rho`.
            codeword = self.encoder.encode(sk.parameter, message, rho, epoch)
            # If encoding is successful, we've found our `rho` and `codeword`.
            #
            # We can exit the loop.
            if codeword is not None:
                break
        else:
            # This block executes only if the `for` loop completes without a `break`.
            #
            # This means that no valid encoding was found after the maximum number of tries.
            raise RuntimeError(
                f"Failed to find a valid message encoding after {config.MAX_TRIES} tries."
            )

        # Sanity check to ensure the encoder returned a codeword of the correct length.
        if len(codeword) != self.config.DIMENSION:
            raise RuntimeError("Encoding is broken: returned too many or too few chunks.")

        # Compute the one-time signature hashes based on the codeword.
        ots_hashes: list[HashDigestVector] = []
        for chain_index, steps in enumerate(codeword):
            # Derive the secret start of the current chain using the master PRF key.
            start_digest = self.prf.apply(sk.prf_key, epoch, Uint64(chain_index))
            # Walk the hash chain for the number of `steps` specified by the
            # corresponding digit in the codeword.
            #
            # The result is one component of the OTS.
            ots_digest = self.hasher.hash_chain(
                parameter=sk.parameter,
                epoch=epoch,
                chain_index=chain_index,
                start_step=0,
                num_steps=steps,
                start_digest=start_digest,
            )
            ots_hashes.append(ots_digest)

        # Retrieve the Merkle authentication path for the current epoch's leaf.
        # With top-bottom tree traversal, we use combined_path to merge paths from
        # the bottom tree and top tree.

        # Determine which bottom tree contains this epoch (reuse leaves_per_bottom_tree from above).
        boundary = (int(sk.left_bottom_tree_index) + 1) * leaves_per_bottom_tree
        bottom_tree = sk.left_bottom_tree if epoch_int < boundary else sk.right_bottom_tree

        # Ensure bottom tree exists
        if bottom_tree is None:
            raise ValueError(
                f"Epoch {epoch} requires bottom tree but it is not available. "
                f"Prepared interval may have been exceeded. Call advance_preparation() "
                f"to slide the window forward."
            )

        # Generate the combined authentication path
        path = combined_path(sk.top_tree, bottom_tree, epoch)

        # Assemble and return the final signature, which contains:
        # - The OTS,
        # - The Merkle path,
        # - The randomness `rho` needed for verification.
        return Signature(path=path, rho=rho, hashes=HashDigestList(data=ots_hashes))

    def verify(self, pk: PublicKey, epoch: Uint64, message: bytes, sig: Signature) -> bool:
        r"""
        Verifies a digital signature against a public key, message, and epoch.

        This is a **deterministic** algorithm.

        ### Verification Algorithm

        1.  **Re-encode Message**: The verifier uses the randomness `rho` from the
            signature to re-compute the codeword $x = (x_1, \dots, x_v)$ from the message `m`.
            If the encoding is invalid (e.g., does not meet the target sum), verification fails.

        2.  **Reconstruct One-Time Public Key**: For each intermediate hash $y_i$ in the
            signature's `hashes` field, the verifier completes the corresponding hash chain.
            Since $y_i$ was computed by hashing $x_i$ times, the verifier applies the
            hash function an additional `BASE - 1 - x_i` times to arrive at the
            chain's public endpoint, which is one component of the one-time public key.

        3.  **Compute Merkle Leaf**: The verifier hashes the full set of reconstructed
            chain endpoints to compute the expected Merkle leaf for the given `epoch`.

        4.  **Verify Merkle Path**: The verifier uses the authentication `path` from the
            signature to compute a candidate Merkle root, starting from the leaf computed
            in the previous step. Verification succeeds if and only if this candidate root
            matches the `root` stored in the `PublicKey`.

        Args:
            pk: The public key to verify against.
            epoch: The epoch the signature corresponds to.
            message: The message that was supposedly signed.
            sig: The signature object to be verified.

        Returns:
            `True` if the signature is valid, `False` otherwise.

        For the formal specification of this process, please refer to:
        - "Hash-Based Multi-Signatures for Post-Quantum Ethereum": https://eprint.iacr.org/2025/055
        - "Technical Note: LeanSig for Post-Quantum Ethereum": https://eprint.iacr.org/2025/1332
        - The canonical Rust implementation: https://github.com/b-wagn/hash-sig
        """
        # Retrieve the scheme's configuration parameters.
        config = self.config

        # Validate epoch bounds.
        #
        # Return False instead of raising to avoid panic on invalid signatures.
        # The epoch is attacker-controlled input.
        if epoch > self.config.LIFETIME:
            return False

        # Re-encode the message using the randomness `rho` from the signature.
        #
        # If the encoding is invalid (e.g., fails the target sum check), the signature is invalid.
        codeword = self.encoder.encode(pk.parameter, message, sig.rho, epoch)
        if codeword is None:
            return False

        # Reconstruct the one-time public key (the list of chain endpoints).
        chain_ends: list[HashDigestVector] = []
        for chain_index, xi in enumerate(codeword):
            # The signature provides `start_digest`, which is the hash value after `xi` steps.
            start_digest = sig.hashes[chain_index]
            # We must perform the remaining `BASE - 1 - xi` hashing steps
            # to compute the public endpoint of the chain.
            num_steps_remaining = config.BASE - 1 - xi
            end_digest = self.hasher.hash_chain(
                parameter=pk.parameter,
                epoch=epoch,
                chain_index=chain_index,
                start_step=xi,
                num_steps=num_steps_remaining,
                start_digest=start_digest,
            )
            chain_ends.append(end_digest)

        # Verify the Merkle path.
        #
        # This function internally:
        # - Hashes the `chain_ends` to get the leaf node for the epoch,
        # - Uses the `opening` path from the signature to compute a candidate root.
        # - It returns true if and only if this candidate root matches the public key's root.
        return verify_path(
            hasher=self.hasher,
            parameter=pk.parameter,
            root=pk.root,
            position=epoch,
            leaf_parts=chain_ends,
            opening=sig.path,
        )

    def get_activation_interval(self, sk: SecretKey) -> range:
        """
        Returns the epoch range for which this secret key is active.

        The activation interval is `[activation_epoch, activation_epoch + num_active_epochs)`.
        A signature can only be created for an epoch within this range.

        Args:
            sk: The secret key to query.

        Returns:
            A Python range object representing the valid epoch range.
        """
        start = int(sk.activation_epoch)
        end = start + int(sk.num_active_epochs)
        return range(start, end)

    def get_prepared_interval(self, sk: SecretKey) -> range:
        """
        Returns the epoch range currently prepared (covered by loaded bottom trees).

        With top-bottom tree traversal, a secret key maintains a sliding window of
        two consecutive bottom trees. This method returns the range of epochs that
        can be signed with the currently loaded trees, without needing to compute
        additional bottom trees.

        The prepared interval is:
        `[left_bottom_tree_index * sqrt(LIFETIME), (left_bottom_tree_index + 2) * sqrt(LIFETIME))`

        Args:
            sk: The secret key to query.

        Returns:
            A Python range object representing the prepared epoch range.

        Raises:
            ValueError: If the secret key is missing top-bottom tree structures.
        """
        leaves_per_bottom_tree = 1 << (self.config.LOG_LIFETIME // 2)
        start = int(sk.left_bottom_tree_index) * leaves_per_bottom_tree
        return range(start, start + 2 * leaves_per_bottom_tree)

    def advance_preparation(self, sk: SecretKey) -> SecretKey:
        """
        Advances the prepared interval by computing the next bottom tree.

        This method implements the "sliding window" strategy for top-bottom tree
        traversal. It:
        1. Computes a new bottom tree for the next interval
        2. Shifts the current right tree to become the new left tree
        3. The newly computed tree becomes the new right tree
        4. Increments `left_bottom_tree_index`

        After this operation, the prepared interval moves forward by `sqrt(LIFETIME)` epochs.

        **When to call**: Call this method after signing with an epoch that is in the
        right half of the prepared interval, to ensure the next epoch range is ready.

        Args:
            sk: The secret key to advance.

        Returns:
            A new SecretKey with the advanced preparation window.

        Raises:
            ValueError: If advancing would exceed the activation interval.
        """
        leaves_per_bottom_tree = 1 << (self.config.LOG_LIFETIME // 2)
        left_index = int(sk.left_bottom_tree_index)

        # Check if advancing would exceed the activation interval
        next_prepared_end_epoch = (left_index + 3) * leaves_per_bottom_tree
        activation_end = int(sk.activation_epoch) + int(sk.num_active_epochs)
        if next_prepared_end_epoch > activation_end:
            # Nothing to do - we're already at the end of the activation interval
            return sk

        # Compute the next bottom tree (the one after the current right tree)
        new_right_bottom_tree = HashSubTree.from_prf_key(
            prf=self.prf,
            hasher=self.hasher,
            rand=self.rand,
            config=self.config,
            prf_key=sk.prf_key,
            bottom_tree_index=Uint64(left_index + 2),
            parameter=sk.parameter,
        )

        # Return a new SecretKey with the advanced window
        return sk.model_copy(
            update={
                "left_bottom_tree": sk.right_bottom_tree,
                "right_bottom_tree": new_right_bottom_tree,
                "left_bottom_tree_index": Uint64(left_index + 1),
            }
        )


PROD_SIGNATURE_SCHEME = GeneralizedXmssScheme(
    config=PROD_CONFIG,
    prf=PROD_PRF,
    hasher=PROD_TWEAK_HASHER,
    encoder=PROD_TARGET_SUM_ENCODER,
    rand=PROD_RAND,
)
"""An instance configured for production-level parameters."""

TEST_SIGNATURE_SCHEME = GeneralizedXmssScheme(
    config=TEST_CONFIG,
    prf=TEST_PRF,
    hasher=TEST_TWEAK_HASHER,
    encoder=TEST_TARGET_SUM_ENCODER,
    rand=TEST_RAND,
)
"""A lightweight instance for test environments."""

_LEAN_ENV_TO_SCHEME = {
    "test": TEST_SIGNATURE_SCHEME,
    "prod": PROD_SIGNATURE_SCHEME,
}

TARGET_SIGNATURE_SCHEME = _LEAN_ENV_TO_SCHEME[LEAN_ENV]
"""The active XMSS signature scheme based on LEAN_ENV environment variable."""
