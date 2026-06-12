"""Pytest plugin for generating Lean Ethereum consensus test fixtures."""

import json
import shutil
import sys
from collections import defaultdict
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from consensus_testing.crypto_mode import AggregationProver, CryptoMode
from consensus_testing.forks import FORKS_BY_NAME, BaseFork
from consensus_testing.keys import DEFAULT_MAX_SLOT, XmssKeyManager
from consensus_testing.test_fixtures import (
    FIXTURE_FORMATS,
    PROOF_FAILURE_REJECTION_REASONS,
    FixtureInfo,
    ProofSetting,
)
from lean_spec.spec.forks import Slot, ValidatorIndex
from lean_spec.spec.ssz import Bytes32


class FixtureCollector:
    """Collects generated fixtures and writes them to disk."""

    def __init__(self, output_directory: Path, fork: str):
        """
        Initialize the fixture collector.

        Args:
            output_directory: Root directory for generated fixtures.
            fork: The fork name (e.g., "Lstar").
        """
        self.output_directory = output_directory
        self.fork = fork
        self.fixtures: list[tuple[str, Any, str]] = []

    def fixture_output_file(self, test_nodeid: str, fixture_format: str) -> Path:
        """
        Compute the fixture file for one test function.

        Layout: {output}/consensus/{format}/{test_path}/{function}.json
        The format directory drops the redundant test suffix.

        Args:
            test_nodeid: Complete pytest node ID.
            fixture_format: Format name (e.g., "state_transition_test").

        Returns:
            The path of the JSON file this test function's fixtures land in.

        Raises:
            ValueError: If the test file is not under the consensus spec
                tests, where the output layout is defined.
                Collection normally excludes such paths already;
                this guards against misconfiguration.
        """
        # Split the node ID into the test file path and bare function name.
        # Parametrization suffixes (the bracketed part) are stripped so every
        # parametrized case of one function shares one fixture file.
        nodeid_parts = test_nodeid.split("::")
        test_file_path = nodeid_parts[0]
        function_name_with_params = nodeid_parts[1] if len(nodeid_parts) > 1 else ""
        base_function_name = function_name_with_params.split("[")[0]

        # Extract test path relative to the consensus spec tests
        # e.g., tests/consensus/lstar/... -> lstar/...
        try:
            relative_path = Path(test_file_path).relative_to("tests/consensus")
        except ValueError as exception:
            raise ValueError(
                f"cannot derive a fixture output path for '{test_nodeid}': "
                f"test file '{test_file_path}' is not under tests/consensus"
            ) from exception

        test_path = relative_path.with_suffix("")

        # Build output path: fixtures/consensus/{format}/{test_path}
        format_directory = fixture_format.removesuffix("_test")
        return (
            self.output_directory
            / "consensus"
            / format_directory
            / test_path
            / f"{base_function_name}.json"
        )

    def add_fixture(
        self,
        fixture_format: str,
        fixture: Any,
        test_nodeid: str,
        config: pytest.Config | None = None,
    ) -> None:
        """
        Add a fixture to the collection.

        Args:
            fixture_format: Format name (e.g., "state_transition_test").
            fixture: The fixture object.
            test_nodeid: Complete pytest node ID.
            config: Pytest config object to attach fixture path metadata.
        """
        self.fixtures.append((fixture_format, fixture, test_nodeid))

        if config is not None:
            fixture_path = self.fixture_output_file(test_nodeid, fixture_format)
            config.stash[FIXTURE_PATH_ABSOLUTE_KEY] = str(fixture_path.absolute())
            config.stash[FIXTURE_PATH_RELATIVE_KEY] = str(
                fixture_path.relative_to(self.output_directory)
            )
            config.stash[FIXTURE_FORMAT_KEY] = fixture_format

    def write_fixtures(self) -> None:
        """Write all collected fixtures to disk, grouped by test function."""
        grouped: dict[Path, list[tuple[str, Any, str]]] = defaultdict(list)

        for fixture_format, fixture, test_nodeid in self.fixtures:
            output_file = self.fixture_output_file(test_nodeid, fixture_format)
            grouped[output_file].append((fixture_format, fixture, test_nodeid))

        for output_file, fixtures_list in grouped.items():
            output_file.parent.mkdir(parents=True, exist_ok=True)

            all_tests = {}
            for fixture_format, fixture, test_nodeid in fixtures_list:
                test_id = f"{test_nodeid}[fork_{self.fork}-{fixture_format}]"
                all_tests[test_id] = fixture.json_dict_with_info()

            with open(output_file, "w") as output_handle:
                json.dump(all_tests, output_handle, indent=4)


FIXTURE_COLLECTOR_KEY: pytest.StashKey[FixtureCollector] = pytest.StashKey()
"""Stash key for the session's fixture collector."""

TEST_FORK_CLASS_KEY: pytest.StashKey[type[BaseFork]] = pytest.StashKey()
"""Stash key for the fork class selected by the fork option."""

FIXTURE_PATH_ABSOLUTE_KEY: pytest.StashKey[str] = pytest.StashKey()
"""Stash key for the absolute path of the current test's fixture file."""

FIXTURE_PATH_RELATIVE_KEY: pytest.StashKey[str] = pytest.StashKey()
"""Stash key for the current test's fixture path relative to the output directory."""

FIXTURE_FORMAT_KEY: pytest.StashKey[str] = pytest.StashKey()
"""Stash key for the current test's fixture format name."""


def pytest_addoption(parser: pytest.Parser) -> None:
    """Add command-line options for fixture generation."""
    group = parser.getgroup("fill", "leanSpec fixture generation")
    group.addoption(
        "--output",
        action="store",
        default="fixtures",
        help="Output directory for generated fixtures",
    )
    group.addoption(
        "--fork",
        action="store",
        required=True,
        help="Fork to generate fixtures for",
    )
    group.addoption(
        "--clean",
        action="store_true",
        default=False,
        help="Clean output directory before generating",
    )
    group.addoption(
        "--crypto",
        action="store",
        default="mocked",
        choices=["mocked", "real"],
        help="Aggregation prover mode: mocked (default) or real",
    )


def pytest_ignore_collect(collection_path: Path) -> bool | None:
    """
    Ignore test collection for paths outside the consensus spec tests.

    This prevents pytest from collecting unit tests during fill,
    reducing overhead significantly when there are many tests.
    """
    # Check if path is under tests/ directory
    try:
        relative_path = collection_path.relative_to(Path.cwd() / "tests")
    except ValueError:
        # Not under tests/, let pytest handle it normally
        return None

    # If it's directly under tests/consensus, don't ignore
    if str(relative_path).startswith("consensus"):
        return None

    # Anything else under tests/ (unit, api, interop tests) is skipped during fill
    if relative_path.parts:
        return True

    return None


def pytest_configure(config: pytest.Config) -> None:
    """Setup the fixture generation session."""
    # Register fork validity markers
    config.addinivalue_line(
        "markers",
        "valid_until(fork): specifies until which fork a test case is valid",
    )
    config.addinivalue_line(
        "markers",
        "real_crypto(smoke=False): build and verify with the real prover, never the mock; "
        "smoke=True also keeps it in the fast mocked lane",
    )

    # Crypto mode is chosen explicitly and applies to either scheme.
    AggregationProver.set_mode(CryptoMode(config.getoption("--crypto")))

    # Get options
    output_directory = Path(config.getoption("--output"))
    fork_name = config.getoption("--fork")
    clean = config.getoption("--clean")

    available_fork_names = sorted(fork.name() for fork in FORKS_BY_NAME.values())

    # Validate fork
    if not fork_name:
        print("Error: --fork is required", file=sys.stderr)
        print(
            f"Available forks: {', '.join(available_fork_names)}",
            file=sys.stderr,
        )
        pytest.exit("Missing required --fork option.", returncode=pytest.ExitCode.USAGE_ERROR)

    fork_name_normalized = fork_name.lower()
    if fork_name_normalized not in FORKS_BY_NAME:
        print(
            f"Error: Unsupported fork: {fork_name}\n",
            file=sys.stderr,
        )
        print(
            f"Available forks: {', '.join(available_fork_names)}",
            file=sys.stderr,
        )
        pytest.exit("Invalid fork specified.", returncode=pytest.ExitCode.USAGE_ERROR)

    fork_class = FORKS_BY_NAME[fork_name_normalized]

    # Check output directory
    if output_directory.exists() and any(output_directory.iterdir()):
        if not clean:
            leftover_fixture_paths = list(output_directory.iterdir())
            leftover_names_preview = ", ".join(
                leftover_path.name for leftover_path in leftover_fixture_paths[:5]
            )
            if len(leftover_fixture_paths) > 5:
                leftover_names_preview += ", ..."
            pytest.exit(
                f"Output directory '{output_directory}' is not empty. "
                f"Contains: {leftover_names_preview}. Use --clean to remove all existing files "
                "or specify a different output directory.",
                returncode=pytest.ExitCode.USAGE_ERROR,
            )
        shutil.rmtree(output_directory)

    output_directory.mkdir(parents=True, exist_ok=True)

    config.stash[FIXTURE_COLLECTOR_KEY] = FixtureCollector(output_directory, fork_name)
    config.stash[TEST_FORK_CLASS_KEY] = fork_class


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """
    Deselect tests not valid for the fork, and full real-crypto tests in the mocked lane.

    Real-crypto vectors cannot be mocked, so the fast mocked lane keeps only the
    smoke subset and leaves the rest to the real lane.
    """
    if TEST_FORK_CLASS_KEY not in config.stash:
        return

    fork_class = config.stash[TEST_FORK_CLASS_KEY]
    verbose = config.getoption("verbose")
    mocking = AggregationProver.get_mode() == CryptoMode.MOCKED
    deselected_items = []
    selected_items = []

    for test_item in items:
        markers = list(test_item.iter_markers())
        invalid_for_fork = not _check_markers_valid_for_fork(markers, fork_class)
        real_crypto_markers = [marker for marker in markers if marker.name == "real_crypto"]
        non_smoke_real_crypto = bool(real_crypto_markers) and not any(
            marker.kwargs.get("smoke") for marker in real_crypto_markers
        )

        if (invalid_for_fork and verbose < 2) or (mocking and non_smoke_real_crypto):
            deselected_items.append(test_item)
        else:
            selected_items.append(test_item)

    if deselected_items:
        items[:] = selected_items
        config.hook.pytest_deselected(items=deselected_items)


def _check_markers_valid_for_fork(
    markers: list[Any],
    fork_class: type,
) -> bool:
    """
    Check if test markers indicate validity for the given fork.

    Shared logic for both collection-time and parametrization-time fork filtering.
    """
    has_valid_until = False
    valid_until_forks = []

    for marker in markers:
        if marker.name == "valid_until":
            has_valid_until = True
            for fork_name in marker.args:
                target_fork = FORKS_BY_NAME.get(fork_name.lower())
                if target_fork:
                    valid_until_forks.append(target_fork)

    if not has_valid_until:
        return True

    return any(fork_class <= until_fork for until_fork in valid_until_forks)


def pytest_sessionstart(session: pytest.Session) -> None:
    """
    Fail the session fast if re-signing the same message is not byte-identical.

    A signature must depend only on the key, the slot, and the message.
    Prior signing activity must never influence the bytes.

    A scheme change breaking this invariant must abort the fill.
    Emitting order-dependent vectors would be worse than failing.

    Under sharded runs every worker process probes its own key state.
    """
    probe_message = Bytes32(b"\x07" * 32)
    fresh_signature = XmssKeyManager.shared().sign_block_root(
        ValidatorIndex(0), Slot(1), probe_message
    )

    # Advance the key state to the manager's slot limit, reset, and sign again.
    XmssKeyManager.shared().sign_block_root(ValidatorIndex(0), DEFAULT_MAX_SLOT, probe_message)
    XmssKeyManager.reset_signing_state()
    resigned_signature = XmssKeyManager.shared().sign_block_root(
        ValidatorIndex(0), Slot(1), probe_message
    )

    assert fresh_signature.encode_bytes() == resigned_signature.encode_bytes(), (
        "XMSS re-signing produced different bytes for the same validator, slot, and "
        "message; emitted vectors would depend on test execution order"
    )

    # Restore the manager to a disk-fresh state.
    XmssKeyManager.reset_signing_state()


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Write all collected fixtures at the end of the session."""
    if FIXTURE_COLLECTOR_KEY in session.config.stash:
        session.config.stash[FIXTURE_COLLECTOR_KEY].write_fixtures()


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[None]) -> Any:
    """Make each test's fixture json path available to the test report."""
    outcome = yield
    report = outcome.get_result()

    if call.when == "call":
        stash = item.config.stash
        if FIXTURE_PATH_ABSOLUTE_KEY in stash and FIXTURE_PATH_RELATIVE_KEY in stash:
            report.user_properties.append(
                ("fixture_path_absolute", stash[FIXTURE_PATH_ABSOLUTE_KEY])
            )
            report.user_properties.append(
                ("fixture_path_relative", stash[FIXTURE_PATH_RELATIVE_KEY])
            )
        if FIXTURE_FORMAT_KEY in stash:
            report.user_properties.append(("fixture_format", stash[FIXTURE_FORMAT_KEY]))


@pytest.fixture
def fork(request: pytest.FixtureRequest) -> Any:
    """Placeholder overridden by pytest_generate_tests with the selected fork class."""
    pass


@pytest.fixture
def test_case_description(request: pytest.FixtureRequest) -> str:
    """Extract and combine docstrings from test class and function."""
    description_unavailable = (
        "No description available - add a docstring to the python test class or function."
    )
    test_class_doc = ""
    test_function_doc = ""

    if hasattr(request.node, "cls") and request.cls:
        test_class_doc = f"Test class documentation:\n{request.cls.__doc__}"
    if hasattr(request.node, "function") and request.function.__doc__:
        test_function_doc = f"{request.function.__doc__}"

    if not test_class_doc and not test_function_doc:
        return description_unavailable

    combined_docstring = f"{test_class_doc}\n\n{test_function_doc}".strip()
    return combined_docstring


@pytest.fixture(autouse=True)
def reset_xmss_signing_state() -> Iterator[None]:
    """
    Reset shared XMSS signing state before every test.

    XMSS signing is stateful.
    Each signature consumes a one-time leaf and advances the shared key state.

    Every test must start from the same fresh key state.
    Otherwise emitted vectors could depend on test order or worker sharding.
    """
    XmssKeyManager.reset_signing_state()
    yield


def base_spec_filler_parametrizer(spec_class: Any) -> Any:
    """
    Generate pytest.fixture for a given test spec class.

    Args:
        spec_class: The input spec class to create a filler for.

    Returns:
        A pytest fixture function whose value fills and collects a fixture.
    """

    @pytest.fixture(
        scope="function",
        name=spec_class.format_name,
    )
    def base_spec_filler_parametrizer_func(
        request: pytest.FixtureRequest,
        fork: Any,
        test_case_description: str,
    ) -> Any:
        """Fixture whose value builds the spec, generates, and collects the result."""

        def fill_and_collect(**spec_fields: Any) -> Any:
            test_spec = spec_class(**spec_fields)

            # Mock the prover unless the run is real or the test opted into real crypto.
            mock_prover = AggregationProver.get_mode() == CryptoMode.MOCKED and (
                not request.node.get_closest_marker("real_crypto")
            )
            if mock_prover:
                with AggregationProver.mocked():
                    generated_fixture = test_spec.generate()
            else:
                generated_fixture = test_spec.generate()

            # A mocked proof is never verified.
            # A real proof must fail only when the rejection is itself a proof failure.
            # A non-crypto rejection (such as an unknown parent) still carries a valid proof.
            expected_rejection = test_spec.expected_rejection
            if mock_prover:
                proof_setting = ProofSetting.MOCKED
            elif (
                expected_rejection is not None
                and expected_rejection.reason in PROOF_FAILURE_REJECTION_REASONS
            ):
                proof_setting = ProofSetting.REAL_AND_INVALID
            else:
                proof_setting = ProofSetting.REAL_AND_VALID

            filled_fixture = generated_fixture.with_info(
                info=FixtureInfo(
                    test_id=request.node.nodeid,
                    description=test_case_description,
                    fixture_format=spec_class.format_name,
                    key_set_digest=XmssKeyManager.shared().key_set_digest(),
                ),
                network=fork.name(),
            ).model_copy(update={"proof_setting": proof_setting})

            if FIXTURE_COLLECTOR_KEY in request.config.stash:
                request.config.stash[FIXTURE_COLLECTOR_KEY].add_fixture(
                    fixture_format=spec_class.format_name,
                    fixture=filled_fixture,
                    test_nodeid=request.node.nodeid,
                    config=request.config,
                )
            return filled_fixture

        return fill_and_collect

    return base_spec_filler_parametrizer_func


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    """Pytest hook to dynamically generate test cases for each fork."""
    if "fork" not in metafunc.fixturenames:
        return

    fork_class = metafunc.config.stash[TEST_FORK_CLASS_KEY]

    if not _check_markers_valid_for_fork(list(metafunc.definition.iter_markers()), fork_class):
        verbose = metafunc.config.getoption("verbose")
        if verbose >= 2:
            metafunc.parametrize(
                "fork",
                [
                    pytest.param(
                        None,
                        marks=pytest.mark.skip(
                            reason=f"Test not valid for fork {fork_class.name()}"
                        ),
                    )
                ],
                scope="function",
            )
        return

    metafunc.parametrize(
        "fork",
        [pytest.param(fork_class, id=f"fork_{fork_class.name()}")],
        scope="function",
    )


# Pytest fixtures for every consensus fixture format.
# Each spec test requests one by its format name and calls it to build a test vector.
# Registration iterates the canonical registry.
# A new format needs no edit here.
for fixture_format_class in FIXTURE_FORMATS:
    globals()[fixture_format_class.format_name] = base_spec_filler_parametrizer(
        fixture_format_class
    )
