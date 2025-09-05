"""
Defines the core interface for the Generalized XMSS signature scheme.

Specification for the high-level functions (`key_gen`, `sign`, `verify`).

This constitutes the public API of the signature scheme.
"""

from __future__ import annotations

from typing import List, Tuple

from lean_spec.subspecs.xmss.target_sum import (
    PROD_TARGET_SUM_ENCODER,
    TEST_TARGET_SUM_ENCODER,
    TargetSumEncoder,
)

from .constants import (
    PROD_CONFIG,
    TEST_CONFIG,
    XmssConfig,
)
from .containers import HashDigest, PublicKey, SecretKey, Signature
from .merkle_tree import (
    PROD_MERKLE_TREE,
    TEST_MERKLE_TREE,
    MerkleTree,
)
from .prf import PROD_PRF, TEST_PRF, Prf
from .tweak_hash import (
    PROD_TWEAK_HASHER,
    TEST_TWEAK_HASHER,
    TreeTweak,
    TweakHasher,
)
from .utils import PROD_RAND, TEST_RAND, Rand


class GeneralizedXmssScheme:
    """Instance of the Generalized XMSS signature scheme for a given config."""

    def __init__(
        self,
        config: XmssConfig,
        prf: Prf,
        hasher: TweakHasher,
        merkle_tree: MerkleTree,
        encoder: TargetSumEncoder,
        rand: Rand,
    ):
        """Initializes the scheme with a specific parameter set."""
        self.config = config
        self.prf = prf
        self.hasher = hasher
        self.merkle_tree = merkle_tree
        self.encoder = encoder
        self.rand = rand

    def key_gen(self, activation_epoch: int, num_active_epochs: int) -> Tuple[PublicKey, SecretKey]:
        """
        Generates a new cryptographic key pair for a specified range of epochs.

        This is a **randomized** algorithm that establishes a signer's identity.
        The generated secret key is stateful and tied to the progression of epochs.

        ### Key Generation Algorithm

        1.  **Master Secrets**: A master secret (the PRF key) and a public hash
            parameter (`P`) are randomly generated. The PRF key allows for the
            deterministic derivation of one-time secrets for each epoch.

        2.  **Hash Chains**: For each epoch in the key's active lifetime, the algorithm
            derives the secret starting points for all `DIMENSION` hash chains using the PRF.
            It then computes the public endpoint of each chain by hashing it `BASE - 1` times.

        3.  **One-Time Public Keys**: The collection of all chain endpoints for a given
            epoch constitutes that epoch's one-time public key.

        4.  **Merkle Tree Construction**: Each one-time public key is hashed to form a
            single Merkle leaf. A Merkle tree is then constructed over all the leaves
            for the active epochs. The root of this tree serves as the single, compact
            public commitment for the entire key lifetime.

        Args:
            activation_epoch: The starting epoch for which this key is valid.
            num_active_epochs: The number of consecutive epochs the key can be used for.

        Returns:
            A tuple containing the `PublicKey` and `SecretKey`.

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

        # Iterate through each epoch to generate its corresponding Merkle leaf.
        leaf_hashes: List[HashDigest] = []
        for epoch in range(activation_epoch, activation_epoch + num_active_epochs):
            # For each epoch, compute the one-time public key, which consists
            # of the public endpoints of `DIMENSION` independent hash chains.
            chain_ends: List[HashDigest] = []
            for chain_index in range(config.DIMENSION):
                # Derive the secret start of the chain from the master PRF key.
                #
                # This ensures each chain is unique and cryptographically secure.
                start_digest = self.prf.apply(prf_key, epoch, chain_index)

                # Compute the public end of the chain by applying the hash function
                # `BASE - 1` times. This is the public part of the one-time key.
                end_digest = self.hasher.hash_chain(
                    parameter=parameter,
                    epoch=epoch,
                    chain_index=chain_index,
                    start_step=0,
                    num_steps=config.BASE - 1,
                    start_digest=start_digest,
                )
                chain_ends.append(end_digest)

            # The Merkle leaf for this epoch is the hash of its one-time public key.
            #
            # A unique tweak is used to domain-separate this hash from other hashes in the scheme.
            leaf_tweak = TreeTweak(level=0, index=epoch)
            leaf_hash = self.hasher.apply(parameter, leaf_tweak, chain_ends)
            leaf_hashes.append(leaf_hash)

        # Build the Merkle tree over the list of all generated leaf hashes.
        tree = self.merkle_tree.build(config.LOG_LIFETIME, activation_epoch, parameter, leaf_hashes)
        # The root of the tree is the primary component of the public key.
        root = self.merkle_tree.root(tree)

        # Assemble and return the public and secret keys.
        pk = PublicKey(root=root, parameter=parameter)
        sk = SecretKey(
            prf_key=prf_key,
            tree=tree,
            parameter=parameter,
            activation_epoch=activation_epoch,
            num_active_epochs=num_active_epochs,
        )
        return pk, sk

    def sign(self, sk: SecretKey, epoch: int, message: bytes) -> Signature:
        """
        Produces a digital signature for a given message at a specific epoch.

        This is a **randomized** algorithm.

        **CRITICAL SECURITY WARNING**: A secret key for a given epoch must **NEVER** be used
        to sign two different messages. Doing so would reveal parts of the secret key
        and allow an attacker to forge signatures. This is the fundamental security
        property of a synchronized (stateful) signature scheme.

        ### Signing Algorithm

        1.  **Message Encoding with Randomness (`rho`)**: The "Target Sum" scheme
            requires the message hash to be encoded into a `codeword` whose digits
            sum to a predefined target. A direct hash of the message is unlikely to
            satisfy this. Therefore, the algorithm repeatedly hashes the message
            combined with fresh randomness (`rho`) until a valid `codeword` is found.

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
        active_range = range(sk.activation_epoch, sk.activation_epoch + sk.num_active_epochs)
        if epoch not in active_range:
            raise ValueError("Key is not active for the specified epoch.")

        # Find a valid message encoding.
        #
        # This loop repeatedly tries different randomness `rho` until the encoder
        # produces a valid codeword (i.e., one that meets the target sum constraint).
        for _ in range(config.MAX_TRIES):
            # Sample fresh randomness `rho`.
            rho = self.rand.rho()
            # Attempt to encode the message with the new `rho`.
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
        ots_hashes: List[HashDigest] = []
        for chain_index, steps in enumerate(codeword):
            # Derive the secret start of the current chain using the master PRF key.
            start_digest = self.prf.apply(sk.prf_key, epoch, chain_index)
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
        path = self.merkle_tree.path(sk.tree, epoch)

        # Assemble and return the final signature, which contains:
        # - The OTS,
        # - The Merkle path,
        # - The randomness `rho` needed for verification.
        return Signature(path=path, rho=rho, hashes=ots_hashes)

    def verify(self, pk: PublicKey, epoch: int, message: bytes, sig: Signature) -> bool:
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

        # A signature for an epoch beyond the scheme's lifetime is invalid.
        if epoch > self.config.LIFETIME:
            raise ValueError("The signature is for a future epoch.")

        # Re-encode the message using the randomness `rho` from the signature.
        #
        # If the encoding is invalid (e.g., fails the target sum check), the signature is invalid.
        codeword = self.encoder.encode(pk.parameter, message, sig.rho, epoch)
        if codeword is None:
            return False

        # Reconstruct the one-time public key (the list of chain endpoints).
        chain_ends: List[HashDigest] = []
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
        return self.merkle_tree.verify_path(
            parameter=pk.parameter,
            root=pk.root,
            position=epoch,
            leaf_parts=chain_ends,
            opening=sig.path,
        )


PROD_SIGNATURE_SCHEME = GeneralizedXmssScheme(
    PROD_CONFIG,
    PROD_PRF,
    PROD_TWEAK_HASHER,
    PROD_MERKLE_TREE,
    PROD_TARGET_SUM_ENCODER,
    PROD_RAND,
)
"""An instance configured for production-level parameters."""

TEST_SIGNATURE_SCHEME = GeneralizedXmssScheme(
    TEST_CONFIG,
    TEST_PRF,
    TEST_TWEAK_HASHER,
    TEST_MERKLE_TREE,
    TEST_TARGET_SUM_ENCODER,
    TEST_RAND,
)
"""A lightweight instance for test environments."""
