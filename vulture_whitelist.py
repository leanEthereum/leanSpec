# Whitelist for vulture dead-code detection.
#
# Each line names a symbol whose use is real but invisible to static analysis:
# framework dispatch, serialization, reflection, or an interpreter protocol.
# Vulture parses every reference here as a use, so the symbol stops being
# reported. A bare name covers a function or variable; the "_." prefix covers a
# method or an attribute.
#
# This file is data for vulture, not executable code, so it is excluded from
# ruff and ty.
#
# Keep it tight. Add a symbol only after confirming its use is genuine but
# unseen by vulture. Genuinely dead code must stay out of this file so vulture
# keeps reporting it. Prefer fixing the dead code over silencing it here.

# Single-dispatch handlers for the hash_tree_root generic function.
# Dispatched by argument type, so they have no direct call site.
_htr_uint
_htr_boolean
_htr_fp
_htr_bytes
_htr_bytearray
_htr_memoryview
_htr_bytevector
_htr_bytelist
_htr_bitvector_base
_htr_bitlist_base
_htr_vector
_htr_list
_htr_container

# Magic methods invoked by the interpreter.
# Flagged only because they are defined as overloaded functions or as an
# attribute rather than a plain method, which the built-in dunder filter misses.
__pow__
__repr__
_.__len__

# pytest hooks, discovered by name from the plugin and conftest modules.
pytest_addoption
pytest_ignore_collect
pytest_configure
pytest_collection_modifyitems
pytest_sessionstart
pytest_sessionfinish
pytest_runtest_makereport
pytest_generate_tests

# pytest autouse fixtures and module markers, applied implicitly.
reset_xmss_signing_state
_reset_registry
_reset_metrics
_reset_observer
pytestmark

# Pydantic validators, invoked by the model during validation.
_.check_lengths
_._coerce_and_validate
_._accept_hex_string
_._validate_byte_list_data
_._validate_decomposition
_.validate_state_length
_.validate_target
_.validate_rejection_is_declared
_.validate_signatures_are_out_of_scope
_._yaml_int_to_hex

# Pydantic serializers, invoked by the model during serialization.
_.serialize_value
_.serialize_block
_._serialize_data
_._serialize_as_hex

# Fork-upgrade protocol method, invoked polymorphically on a fork transition.
# A single-fork tree has no transition yet, so there is no call site.
_.upgrade_state

# Signature parameters mandated by external protocols we cannot rename.
# The pydantic core-schema hook, the pytest session-finish hook, and the
# prometheus metric stub interface.
source_type
exitstatus
amount

# logging.Formatter.format override, invoked by the logging framework.
_.format

# httpx transport hook, invoked by the httpx client through its test doubles.
_.handle_async_request

# unittest.mock attributes, read by the mock library.
_.return_value
_.side_effect

# sqlite3 connection attribute, read by the sqlite3 driver.
_.row_factory

# Enum member resolved from a command-line string through the enum constructor.
# The mode is selected by value, so the member name has no direct reference.
REAL

# XMSS protocol parameter documented in the configuration model.
# The byte length of a signed message, kept for spec fidelity even though the
# computation works from the field-element count.
MESSAGE_LENGTH

# Dataclass field on a peer-subscription event.
# Set from the subscribe flag at construction and compared through dataclass
# equality in tests, neither of which vulture counts as a read.
subscribed

# Validator manifest fields, mirroring an external YAML schema.
# Deserialized and validated by pydantic, not all read back by attribute.
attestation_public_key_hex
proposal_public_key_hex
key_scheme
hash_function
log_num_active_epochs
num_active_epochs

# Field names on test-vector and fixture models.
# Populated from constructor keywords and consumed by serialization or
# comparison, never read by attribute in Python.
description
comment
expected_status_code
expected_content_type
expected_body
to_peer
signature_valid
protobuf_encoded
compressed_length
framed_length
seconds_per_slot
intervals_per_slot
milliseconds_per_interval
state_bytes
step_type
latest_justified_slot
latest_justified_root
latest_finalized_slot
latest_finalized_root
config_genesis_time
latest_block_header_slot
latest_block_header_proposer_index
latest_block_header_parent_root
latest_block_header_state_root
latest_block_header_body_root
historical_block_hashes_count
justifications_roots_count
justifications_validators_count
safe_target_root
safe_target_root_label
attestation_signature_target_slots
latest_new_aggregated_target_slots
latest_known_aggregated_target_slots
participant_sets
block_weights
known_aggregated_payloads
is_justifiable

# SSZ container and model field names declared inside unit tests.
# Serialized by the SSZ codec or set through pydantic, never read by attribute.
A
B
C
y
first_name
slot_number
_.slot_number
