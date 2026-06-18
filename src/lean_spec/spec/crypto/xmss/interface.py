"""Public interface for the Generalized XMSS signature scheme."""

from lean_spec.base import StrictBaseModel
from lean_spec.config import LEAN_ENV
from lean_spec.spec.crypto.xmss.constants import PROD_CONFIG, TEST_CONFIG, XmssConfig
from lean_spec.spec.crypto.xmss.containers import KeyPair, PublicKey, SecretKey, Signature
from lean_spec.spec.crypto.xmss.encoding import target_sum_encode
from lean_spec.spec.crypto.xmss.field import random_parameter
from lean_spec.spec.crypto.xmss.merkle import HashSubTree, combined_path, verify_path
from lean_spec.spec.crypto.xmss.poseidon import POSEIDON, PoseidonXmss
from lean_spec.spec.crypto.xmss.prf import PRFKey
from lean_spec.spec.crypto.xmss.types import HashDigestList, HashDigestVector
from lean_spec.spec.forks.lstar.slot import Slot
from lean_spec.spec.ssz import Bytes32, Uint64


def _expand_activation_time(
    log_lifetime: int, desired_activation_slot: int, desired_num_active_slots: int
) -> tuple[int, int]:
    """
    Snap a requested slot window onto whole bottom trees.

    # Overview

    A bottom tree covers C consecutive slots, where C is the square root of the lifetime.
    The lifetime is C such trees laid end to end, so C * C slots in total.

    Args:
        log_lifetime: Base-2 logarithm of the lifetime in slots.
        desired_activation_slot: First slot the caller wants to sign.
        desired_num_active_slots: Number of slots the caller wants to sign.

    Returns:
        The half-open bottom-tree index range (start, end).
        It covers slots [start * C, end * C).
    """
    # One bottom tree spans the square root of the lifetime in slots.
    # That span is a power of two, so clearing the low bits rounds a slot down to a tree boundary.
    leaves_per_bottom_tree = 1 << (log_lifetime // 2)
    bottom_tree_alignment_mask = ~(leaves_per_bottom_tree - 1)

    desired_end_slot = desired_activation_slot + desired_num_active_slots

    # Phase 1: round the start down and the end up onto tree boundaries.
    # Adding the span minus one before clearing the low bits rounds the end up rather than down.
    start = desired_activation_slot & bottom_tree_alignment_mask
    end = (desired_end_slot + leaves_per_bottom_tree - 1) & bottom_tree_alignment_mask

    # Phase 2: widen to two trees so the resident signing window always fits.
    if end - start < 2 * leaves_per_bottom_tree:
        end = start + 2 * leaves_per_bottom_tree

    # Phase 3: clamp the window into the lifetime.
    lifetime = leaves_per_bottom_tree * leaves_per_bottom_tree
    if end > lifetime:
        duration = end - start
        if duration > lifetime:
            # The request is wider than the whole lifetime, so cover all of it.
            start = 0
            end = lifetime
        else:
            # Slide the window back so it ends exactly at the lifetime boundary.
            end = lifetime
            start = (lifetime - duration) & bottom_tree_alignment_mask

    # Convert the slot boundaries to bottom-tree indices.
    return (start // leaves_per_bottom_tree, end // leaves_per_bottom_tree)


class GeneralizedXmssScheme(StrictBaseModel):
    """Generalized XMSS signature scheme bound to one configuration."""

    config: XmssConfig
    """Configuration parameters for this instance."""

    poseidon: PoseidonXmss
    """Cached Poseidon engine used by every primitive in the scheme."""

    def key_gen(self, activation_slot: Slot, num_active_slots: Uint64) -> KeyPair:
        """
        Generate a fresh key pair active for an aligned slot range.

        # Overview

        The signer keeps only the two leftmost bottom trees resident, plus every bottom-tree root.
        That bounds secret-key memory near the square root of the lifetime.

        The requested range is snapped outward to whole bottom trees.
        So the returned key may cover more slots than asked for.

        Args:
            activation_slot: Requested first signable slot.
            num_active_slots: Requested number of signable slots.

        Returns:
            A key pair holding the public root and the resident signer state.

        Raises:
            ValueError: When the requested range exceeds the lifetime.
        """
        config = self.config

        # The requested range must fit within the global lifetime.
        if int(activation_slot) + int(num_active_slots) > int(config.LIFETIME):
            raise ValueError("Activation range exceeds the key's lifetime.")

        # Phase 1: draw the master secret and the public parameter.
        parameter = random_parameter(config)
        prf_key = PRFKey.generate()

        # Phase 2: align the requested interval onto bottom-tree boundaries.
        start_bottom_tree_index, end_bottom_tree_index = _expand_activation_time(
            config.LOG_LIFETIME, int(activation_slot), int(num_active_slots)
        )
        actual_activation_slot = start_bottom_tree_index * config.LEAVES_PER_BOTTOM_TREE
        actual_num_active_slots = (
            end_bottom_tree_index - start_bottom_tree_index
        ) * config.LEAVES_PER_BOTTOM_TREE

        # Phase 3: build the two leftmost bottom trees and keep them resident.
        left_bottom_tree = HashSubTree.from_prf_key(
            poseidon=self.poseidon,
            config=config,
            prf_key=prf_key,
            bottom_tree_index=Uint64(start_bottom_tree_index),
            parameter=parameter,
        )
        right_bottom_tree = HashSubTree.from_prf_key(
            poseidon=self.poseidon,
            config=config,
            prf_key=prf_key,
            bottom_tree_index=Uint64(start_bottom_tree_index + 1),
            parameter=parameter,
        )

        bottom_tree_roots: list[HashDigestVector] = [
            left_bottom_tree.root(),
            right_bottom_tree.root(),
        ]

        # Phase 4: build every other bottom tree and remember only its root.
        for bottom_tree_index in range(start_bottom_tree_index + 2, end_bottom_tree_index):
            bottom_tree = HashSubTree.from_prf_key(
                poseidon=self.poseidon,
                config=config,
                prf_key=prf_key,
                bottom_tree_index=Uint64(bottom_tree_index),
                parameter=parameter,
            )
            bottom_tree_roots.append(bottom_tree.root())

        # Phase 5: assemble the top tree from all bottom-tree roots.
        top_tree = HashSubTree.new_top_tree(
            poseidon=self.poseidon,
            config=config,
            depth=config.LOG_LIFETIME,
            start_bottom_tree_index=Uint64(start_bottom_tree_index),
            parameter=parameter,
            bottom_tree_roots=bottom_tree_roots,
        )

        # Pack the public root and the resident signer state into the key pair.
        public_key = PublicKey(root=top_tree.root(), parameter=parameter)
        secret_key = SecretKey(
            prf_key=prf_key,
            parameter=parameter,
            activation_slot=Slot(actual_activation_slot),
            num_active_slots=Uint64(actual_num_active_slots),
            top_tree=top_tree,
            left_bottom_tree_index=Uint64(start_bottom_tree_index),
            left_bottom_tree=left_bottom_tree,
            right_bottom_tree=right_bottom_tree,
        )
        return KeyPair(public_key=public_key, secret_key=secret_key)

    def sign(self, secret_key: SecretKey, slot: Slot, message: Bytes32) -> Signature:
        """
        Produce a signature for a message at a specific slot.

        Phase 1: enforce that the slot is inside the activation and prepared windows.
        Phase 2: search for randomness rho whose encoding lands on the target-sum layer.
        Phase 3: walk each Winternitz chain to the released hash dictated by the codeword.
        Phase 4: build the combined Merkle path through the bottom and top trees.

        Signing is deterministic in (secret_key, slot, message).
        A secret key must never sign two different messages for the same slot.

        Args:
            secret_key: Secret key.
            slot: Signing slot.
            message: Message to sign.

        Returns:
            A signature carrying the OTS, the Merkle path, and the randomness.

        Raises:
            ValueError: When the slot is outside the activation or prepared window.
            RuntimeError: When no valid encoding is found within MAX_TRIES attempts.
        """
        config = self.config
        slot_int = int(slot)
        activation_int = int(secret_key.activation_slot)

        # Phase 1a: the slot must lie in the key's activation range.
        #
        # This is a synchronized one-time scheme: each slot consumes a distinct one-time key.
        # The key only holds material for the contiguous range fixed at generation.
        if not (activation_int <= slot_int < activation_int + int(secret_key.num_active_slots)):
            raise ValueError("Key is not active for the specified slot.")

        # Phase 1b: the slot must lie in the prepared window.
        #
        # The signature opens this slot's leaf through the bottom tree that holds it.
        # Only the two adjacent resident bottom trees are available.
        # A slot outside them would force rebuilding a tree from the PRF, so we refuse.
        prepared = self.get_prepared_interval(secret_key)
        if slot_int not in prepared:
            raise ValueError(
                f"Slot {slot} is outside the prepared interval "
                f"[{prepared.start}, {prepared.stop}). "
                f"Call advance_preparation() to slide the window forward."
            )

        # Phase 2: find randomness whose encoding lands on the target-sum layer.
        #
        # A valid codeword must have digits summing to the target.
        # That constant sum is what makes distinct codewords incomparable, hence unforgeable.
        # The message hash hits the layer only for some randomness, so resample until it does.
        #
        # The randomness is derived from the PRF, keyed by the message and an attempt counter.
        # Signing the same message twice is therefore reproducible.
        for attempts in range(config.MAX_TRIES):
            rho = secret_key.prf_key.derive_randomness(config, slot, message, Uint64(attempts))
            codeword = target_sum_encode(
                self.poseidon, config, secret_key.parameter, slot, rho, message
            )
            if codeword is not None:
                break
        else:
            raise RuntimeError(
                f"Failed to find a valid message encoding after {config.MAX_TRIES} tries."
            )

        # A valid codeword carries exactly one digit per Winternitz chain.
        if len(codeword) != config.DIMENSION:
            raise RuntimeError("Encoding is broken: returned too many or too few chunks.")

        # Phase 3: release each Winternitz chain at the position its digit selects.
        #
        # Every chain starts from a secret derived from the PRF.
        # Hashing that start forward by the digit gives the value to reveal.
        # The verifier later finishes the remaining steps to reach the chain end.
        released_chain_hashes: list[HashDigestVector] = []
        for chain_index, steps in enumerate(codeword):
            start_digest = secret_key.prf_key.derive_chain_start(config, slot, Uint64(chain_index))
            released_chain_digest = self.poseidon.hash_chain(
                config=config,
                parameter=secret_key.parameter,
                epoch=slot,
                chain_index=chain_index,
                start_step=0,
                num_steps=steps,
                start_digest=start_digest,
            )
            released_chain_hashes.append(released_chain_digest)

        # Phase 4: open this slot's leaf up to the public root.
        #
        # The opening climbs the bottom tree that holds the slot, then the top tree.
        # The slot's side of the prepared window selects which resident bottom tree to climb.
        boundary = prepared.start + config.LEAVES_PER_BOTTOM_TREE
        bottom_tree = (
            secret_key.left_bottom_tree if slot_int < boundary else secret_key.right_bottom_tree
        )
        path = combined_path(secret_key.top_tree, bottom_tree, Uint64(slot))

        # The signature carries the opening, the randomness, and the released chain values.
        # The randomness lets the verifier recompute the same codeword.
        return Signature(path=path, rho=rho, hashes=HashDigestList(data=released_chain_hashes))

    def verify(
        self, public_key: PublicKey, slot: Slot, message: Bytes32, signature: Signature
    ) -> bool:
        """
        Verify a signature against a public key, message, and slot.

        Phase 1: bound-check the slot.
        Phase 1 rejects without raising on bad input.
        Phase 2: recompute the codeword using the randomness carried by the signature.
        Phase 3: reject a wrong number of released hashes or path siblings.
        These list lengths arrive from the wire with only an upper bound.
        An exact-length check rejects the malformed signature before the per-chain loop.
        Phase 4: complete each Winternitz chain from the released hash to its endpoint.
        Phase 5: rebuild the Merkle root from the chain endpoints and the opening.

        Args:
            public_key: Public key.
            slot: Signing slot claimed by the signature.
            message: Message claimed by the signature.
            signature: Signature to verify.

        Returns:
            True when the signature is valid against the public key, false otherwise.
        """
        config = self.config

        # Phase 1: bound check on the slot.
        # The slot is attacker-controlled, so a malformed value returns False
        # rather than panicking deep in the verification routine.
        if int(slot) >= int(config.LIFETIME):
            return False

        # Phase 2: rederive the codeword from the signature's randomness.
        # A failing aborting decode means the signature cannot be valid.
        codeword = target_sum_encode(
            self.poseidon, config, public_key.parameter, slot, signature.rho, message
        )
        if codeword is None:
            return False

        # Phase 3: reject malformed list lengths before iterating over them.
        # The released chain count is recovered from the wire with only an upper bound.
        # An attacker can send fewer than one hash per chain.
        # Reject the malformed length here so the per-chain loop never indexes out of range.
        if len(signature.hashes) != config.DIMENSION:
            return False

        # The authentication path must carry exactly one sibling per tree level.
        # Bound it against this scheme's own height rather than a global default.
        # A mismatched height would have the rebuild climb a tree that does not match this key.
        if len(signature.path.siblings) != config.LOG_LIFETIME:
            return False

        # Phase 4: finish each chain from the released hash to its endpoint.
        chain_ends: list[HashDigestVector] = []
        for chain_index, digit in enumerate(codeword):
            # The signature provides the digest after digit steps along the chain.
            # We hash the remaining BASE - 1 - digit times to reach the endpoint.
            start_digest = signature.hashes[chain_index]
            end_digest = self.poseidon.hash_chain(
                config=config,
                parameter=public_key.parameter,
                epoch=slot,
                chain_index=chain_index,
                start_step=digit,
                num_steps=config.BASE - 1 - digit,
                start_digest=start_digest,
            )
            chain_ends.append(end_digest)

        # Phase 5: rebuild and compare against the trusted root.
        return verify_path(
            poseidon=self.poseidon,
            config=config,
            parameter=public_key.parameter,
            root=public_key.root,
            position=slot,
            leaf_chain_ends=chain_ends,
            opening=signature.path,
        )

    def get_activation_interval(self, secret_key: SecretKey) -> range:
        """
        Return the activation interval as a Python range.

        A signature is only valid for a slot inside this range.
        """
        start = int(secret_key.activation_slot)
        return range(start, start + int(secret_key.num_active_slots))

    def get_prepared_interval(self, secret_key: SecretKey) -> range:
        """
        Return the prepared interval as a Python range.

        The prepared interval is the slot window covered by the two resident bottom trees.
        A signer can sign any slot in this range without paying the cost of
        rebuilding a bottom tree from the PRF.
        """
        leaves_per_bottom_tree = self.config.LEAVES_PER_BOTTOM_TREE
        start = int(secret_key.left_bottom_tree_index) * leaves_per_bottom_tree
        return range(start, start + 2 * leaves_per_bottom_tree)

    def advance_preparation(self, secret_key: SecretKey) -> SecretKey:
        """
        Slide the prepared window one bottom tree forward.

        Phase 1: bail out when the next window would exceed the activation interval.
        Phase 2: regenerate the new right bottom tree from the PRF key.
        Phase 3: shift the previous right tree to the left slot.

        Returning the same key when no advancement is possible keeps callers simple.

        Args:
            secret_key: Secret key whose prepared window should advance.

        Returns:
            A secret key with the window shifted by one bottom tree.
        """
        left_index = int(secret_key.left_bottom_tree_index)

        # Phase 1: no advancement once the activation interval is fully consumed.
        next_prepared_end_slot = (left_index + 3) * self.config.LEAVES_PER_BOTTOM_TREE
        activation_end = int(secret_key.activation_slot) + int(secret_key.num_active_slots)
        if next_prepared_end_slot > activation_end:
            return secret_key

        # Phase 2: rebuild the next bottom tree from the master PRF key.
        new_right_bottom_tree = HashSubTree.from_prf_key(
            poseidon=self.poseidon,
            config=self.config,
            prf_key=secret_key.prf_key,
            bottom_tree_index=Uint64(left_index + 2),
            parameter=secret_key.parameter,
        )

        # Phase 3: rotate the right tree into the left slot, advance the index.
        return secret_key.model_copy(
            update={
                "left_bottom_tree": secret_key.right_bottom_tree,
                "right_bottom_tree": new_right_bottom_tree,
                "left_bottom_tree_index": Uint64(left_index + 1),
            }
        )


PROD_SIGNATURE_SCHEME = GeneralizedXmssScheme(config=PROD_CONFIG, poseidon=POSEIDON)
"""Signature scheme instance with production parameters."""

TEST_SIGNATURE_SCHEME = GeneralizedXmssScheme(config=TEST_CONFIG, poseidon=POSEIDON)
"""Signature scheme instance with test parameters."""

TARGET_SIGNATURE_SCHEME = TEST_SIGNATURE_SCHEME if LEAN_ENV == "test" else PROD_SIGNATURE_SCHEME
"""Active scheme selected at import time from the LEAN_ENV environment variable."""
