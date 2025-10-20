"""Pytest plugin for generating consensus test fixtures."""

import json
from pathlib import Path
from typing import Any, List

import pytest

from lean_spec.subspecs.containers import State
from lean_spec.types import Uint64
from lean_spec_tests.base_types import CamelModel
from lean_spec_tests.forks import Fork, get_fork_by_name, get_forks
from lean_spec_tests.test_fixtures import BaseConsensusFixture


class FixtureCollector:
    """Collects generated fixtures and writes them to disk."""

    def __init__(self, output_dir: Path, fork: str):
        """
        Initialize the fixture collector.

        Args:
            output_dir: Root directory for generated fixtures.
            fork: The fork name (e.g., "devnet").
        """
        self.output_dir = output_dir
        self.fork = fork
        self.fixtures: List[tuple[str, str, Any, str]] = []  # (test_name, format, fixture, nodeid)

    def add_fixture(
        self,
        test_name: str,
        fixture_format: str,
        fixture: Any,
        test_nodeid: str,
        config: pytest.Config | None = None,
    ) -> None:
        """
        Add a fixture to the collection.

        Args:
            test_name: Name of the test that generated this fixture.
            fixture_format: Format name (e.g., "vote_processing_test").
            fixture: The fixture object.
            test_nodeid: Complete pytest node ID (e.g., "tests/path/test.py::test_name").
            config: Pytest config object to attach fixture path metadata.
        """
        self.fixtures.append((test_name, fixture_format, fixture, test_nodeid))

        # Set fixture path metadata on config for pytest_runtest_makereport
        if config is not None:
            # Calculate fixture path (will be written later in write_fixtures)
            nodeid_parts = test_nodeid.split("::")
            test_file_path = nodeid_parts[0]
            func_name_with_params = nodeid_parts[1] if len(nodeid_parts) > 1 else ""
            base_func_name = func_name_with_params.split("[")[0]

            test_file = Path(test_file_path)
            relative_path = test_file.relative_to("tests/spec_tests")
            module_path = relative_path.with_suffix("")

            format_dir = fixture_format.replace("_test", "")
            fixture_dir = self.output_dir / format_dir / module_path
            fixture_path = fixture_dir / f"{base_func_name}.json"

            # NOTE: Use str for compatibility with pytest-dist
            config.fixture_path_absolute = str(fixture_path.absolute())  # type: ignore[attr-defined]
            config.fixture_path_relative = str(fixture_path.relative_to(self.output_dir))  # type: ignore[attr-defined]
            config.fixture_format = fixture_format  # type: ignore[attr-defined]

    def write_fixtures(self) -> None:
        """
        Write all collected fixtures to disk.

        Groups fixtures by their base test function (stripping parameters)
        so all parametrized variations end up in the same JSON file.
        """
        from collections import defaultdict

        # Group fixtures by (file_path, base_function_name, format)
        grouped: dict[tuple[str, str, str], list[tuple[str, Any, str]]] = defaultdict(list)

        for test_name, fixture_format, fixture, test_nodeid in self.fixtures:
            # Parse nodeid: "tests/spec_tests/devnet/chain/test_file.py::test_func[params]"
            nodeid_parts = test_nodeid.split("::")
            test_file_path = nodeid_parts[0]

            # Get base function name (strip parameters if present)
            func_name_with_params = nodeid_parts[1] if len(nodeid_parts) > 1 else ""
            base_func_name = func_name_with_params.split("[")[0]  # Remove [params]

            # Group key: (file_path, base_function_name, format)
            group_key = (test_file_path, base_func_name, fixture_format)
            grouped[group_key].append((test_name, fixture, test_nodeid))

        # Write each group to a single JSON file
        for (test_file_path, base_func_name, fixture_format), fixtures_list in grouped.items():
            test_file = Path(test_file_path)

            # Strip "tests/spec_tests/" prefix and ".py" suffix
            # Example: tests/spec_tests/devnet/genesis/test_genesis.py → devnet/genesis/test_genesis
            relative_path = test_file.relative_to("tests/spec_tests")
            module_path = relative_path.with_suffix("")

            # Build fixture path: fixtures/{fixture_type}/{module_path}/
            # Example: fixtures/genesis/devnet/genesis/test_genesis/
            format_dir = fixture_format.replace("_test", "")
            fixture_dir = self.output_dir / format_dir / module_path
            fixture_dir.mkdir(parents=True, exist_ok=True)

            # Single JSON file for all parametrized variations
            output_file = fixture_dir / f"{base_func_name}.json"

            # Collect all test variations into one dict
            all_tests = {}
            for test_name, fixture, test_nodeid in fixtures_list:
                del test_name
                # Create test ID with fork parametrization
                test_id = f"{test_nodeid}[fork_{self.fork}-{fixture_format}]"
                fixture_dict = fixture.json_dict_with_info()
                all_tests[test_id] = fixture_dict

            # Write single JSON with all test variations
            with open(output_file, "w") as f:
                json.dump(
                    all_tests,
                    f,
                    indent=4,
                    default=CamelModel.json_encoder,
                )


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
        help="Fork to generate fixtures for (e.g., devnet)",
    )
    group.addoption(
        "--clean",
        action="store_true",
        default=False,
        help="Clean output directory before generating",
    )


def pytest_configure(config: pytest.Config) -> None:
    """Setup fixture generation session."""
    import sys
    import textwrap

    # Register fork validity markers
    config.addinivalue_line(
        "markers",
        "valid_from(fork): specifies from which fork a test case is valid",
    )
    config.addinivalue_line(
        "markers",
        "valid_until(fork): specifies until which fork a test case is valid",
    )
    config.addinivalue_line(
        "markers",
        "valid_at(fork): specifies at which fork a test case is valid",
    )

    # Get options
    output_dir = Path(config.getoption("--output"))
    fork_name = config.getoption("--fork")
    clean = config.getoption("--clean")

    # Get all available forks dynamically
    available_forks = get_forks()
    available_fork_names = sorted(fork.name() for fork in available_forks)

    # Validate fork
    if not fork_name:
        print(
            "Error: --fork is required",
            file=sys.stderr,
        )
        available_forks_help = textwrap.dedent(
            f"""\
            Available forks:
            {", ".join(available_fork_names)}
            """
        )
        print(available_forks_help, file=sys.stderr)
        pytest.exit("Missing required --fork option.", returncode=pytest.ExitCode.USAGE_ERROR)

    # Get the fork class by name
    fork_class = get_fork_by_name(fork_name)
    if fork_class is None:
        print(
            f"Error: Unsupported fork provided to --fork: {fork_name}\n",
            file=sys.stderr,
        )
        available_forks_help = textwrap.dedent(
            f"""\
            Available forks:
            {", ".join(available_fork_names)}
            """
        )
        print(available_forks_help, file=sys.stderr)
        pytest.exit("Invalid fork specified.", returncode=pytest.ExitCode.USAGE_ERROR)

    # Check if output directory exists and is not empty
    if output_dir.exists() and any(output_dir.iterdir()):
        if not clean:
            # Get summary of what's in the directory
            contents = list(output_dir.iterdir())[:5]  # Show first 5 items
            summary = ", ".join(item.name for item in contents)
            if len(list(output_dir.iterdir())) > 5:
                summary += ", ..."

            pytest.exit(
                f"Output directory '{output_dir}' is not empty. "
                f"Contains: {summary}. Use --clean to remove all existing files "
                "or specify a different output directory.",
                returncode=pytest.ExitCode.USAGE_ERROR,
            )
        # Clean if requested
        import shutil

        shutil.rmtree(output_dir)

    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)

    # Create collector
    config.fixture_collector = FixtureCollector(output_dir, fork_name)  # type: ignore[attr-defined]

    # Store fork class for use in fixtures
    config.consensus_fork_class = fork_class  # type: ignore[attr-defined]


def pytest_collection_modifyitems(config: pytest.Config, items: List[pytest.Item]) -> None:
    """
    Modify collected test items to deselect tests not valid for the selected fork.

    This hook runs after test collection and removes tests that aren't valid
    for the fork specified via --fork.
    """
    if not hasattr(config, "consensus_fork_class"):
        return

    fork_class = config.consensus_fork_class
    verbose = config.getoption("verbose")
    deselected = []
    selected = []

    for item in items:
        # Check if this test has fork validity markers
        if not _is_test_item_valid_for_fork(item, fork_class):
            # If verbose >= 2, keep as skipped (already marked in pytest_generate_tests)
            # Otherwise, deselect it entirely
            if verbose < 2:
                deselected.append(item)
            else:
                selected.append(item)
        else:
            selected.append(item)

    if deselected:
        items[:] = selected
        config.hook.pytest_deselected(items=deselected)


def _is_test_item_valid_for_fork(item: pytest.Item, fork_class: Fork) -> bool:
    """
    Check if a test item is valid for the given fork based on validity markers.

    Similar to _is_test_valid_for_fork but works on pytest.Item instead of Metafunc.
    """
    # Get all markers on the test
    markers = list(item.iter_markers())

    # Track which validity markers we've seen
    has_valid_from = False
    has_valid_until = False
    has_valid_at = False

    valid_from_forks = []
    valid_until_forks = []
    valid_at_forks = []

    # Process each marker
    for marker in markers:
        if marker.name == "valid_from":
            has_valid_from = True
            for fork_name in marker.args:
                target_fork = get_fork_by_name(fork_name)
                if target_fork:
                    valid_from_forks.append(target_fork)

        elif marker.name == "valid_until":
            has_valid_until = True
            for fork_name in marker.args:
                target_fork = get_fork_by_name(fork_name)
                if target_fork:
                    valid_until_forks.append(target_fork)

        elif marker.name == "valid_at":
            has_valid_at = True
            for fork_name in marker.args:
                target_fork = get_fork_by_name(fork_name)
                if target_fork:
                    valid_at_forks.append(target_fork)

    # If no markers, test is valid for all forks
    if not (has_valid_from or has_valid_until or has_valid_at):
        return True

    # If valid_at is specified, ONLY those forks are valid
    if has_valid_at:
        return fork_class in valid_at_forks

    # Check valid_from constraint (fork_class >= any of the from forks)
    from_valid = True
    if has_valid_from:
        from_valid = any(fork_class >= from_fork for from_fork in valid_from_forks)

    # Check valid_until constraint (fork_class <= any of the until forks)
    until_valid = True
    if has_valid_until:
        until_valid = any(fork_class <= until_fork for until_fork in valid_until_forks)

    # Test is valid if it passes both constraints
    return from_valid and until_valid


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Write all collected fixtures at the end of the session."""
    if hasattr(session.config, "fixture_collector"):
        session.config.fixture_collector.write_fixtures()


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[None]) -> Any:
    """
    Make each test's fixture json path available to the test report via
    user_properties.

    This hook is called when each test is run and a report is being made.
    """
    outcome = yield
    report = outcome.get_result()

    if call.when == "call":
        if hasattr(item.config, "fixture_path_absolute") and hasattr(
            item.config, "fixture_path_relative"
        ):
            report.user_properties.append(
                ("fixture_path_absolute", item.config.fixture_path_absolute)
            )
            report.user_properties.append(
                ("fixture_path_relative", item.config.fixture_path_relative)
            )
        if hasattr(item.config, "fixture_format"):
            report.user_properties.append(("fixture_format", item.config.fixture_format))


@pytest.fixture
def fork(request: pytest.FixtureRequest) -> Fork:  # type: ignore[empty-body]
    """
    Parametrize test cases by fork.

    This fixture is parametrized by pytest_generate_tests() and receives
    the fork class as a parameter value.

    Note: Not marked autouse=True because tests explicitly request fork
    via their fixture parameters (genesis_test, consensus_chain_test, etc.).
    """
    pass


@pytest.fixture
def test_case_description(request: pytest.FixtureRequest) -> str:
    """
    Extract and combine docstrings from test class and function.

    Returns:
        str: Combined docstring or a default message if no docstring is found.
    """
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


@pytest.fixture(scope="function")
def genesis(request: pytest.FixtureRequest) -> State:
    """
    Default genesis state for consensus tests.

    This fixture provides a standard genesis state with sensible defaults.
    Tests can override parameters by using pytest's indirect parametrization.

    Returns:
        State: Genesis state with default configuration.
    """
    # Check if the fixture was parametrized indirectly
    if hasattr(request, "param"):
        # Indirect parametrization - param should be a dict of kwargs
        return State.generate_genesis(**request.param)

    # Default genesis state
    return State.generate_genesis(
        genesis_time=Uint64(0),
        num_validators=Uint64(4),
    )


def base_spec_filler_parametrizer(
    fixture_class: type[BaseConsensusFixture],
) -> Any:
    """
    Generate pytest.fixture for a given BaseConsensusFixture subclass.
    All spec fixtures are scoped at the function level to avoid leakage between tests.

    Args:
        fixture_class: The fixture class to create a parametrizer for.

    Returns:
        A pytest fixture function that creates wrapper instances.
    """

    @pytest.fixture(
        scope="function",
        name=fixture_class.format_name,
    )
    def base_spec_filler_parametrizer_func(
        request: pytest.FixtureRequest,
        fork: Fork,
        test_case_description: str,
    ) -> Any:
        """
        Fixture used to instantiate an auto-fillable BaseConsensusFixture object.

        Every test that defines a test filler must explicitly specify its
        parameter name in its function arguments (e.g., genesis_test, consensus_chain_test).
        """

        class FixtureWrapper(fixture_class):  # type: ignore[misc,valid-type]
            """Wrapper class that auto-fills and collects fixtures on instantiation."""

            def __init__(self, **kwargs: Any) -> None:
                super().__init__(**kwargs)

                # Run make_fixture() to fill it (runs the spec)
                filled_fixture = self.make_fixture()

                # Fill metadata information
                filled_fixture.fill_info(
                    test_id=request.node.nodeid,
                    description=test_case_description,
                    fork=fork,
                )

                # Add to collector if we're in fill mode
                if hasattr(request.config, "fixture_collector"):
                    request.config.fixture_collector.add_fixture(
                        test_name=request.node.name,
                        fixture_format=filled_fixture.format_name,
                        fixture=filled_fixture,
                        test_nodeid=request.node.nodeid,
                        config=request.config,
                    )

        return FixtureWrapper

    return base_spec_filler_parametrizer_func


# Dynamically generate a pytest fixture for each consensus spec fixture format.
for format_name, fixture_class in BaseConsensusFixture.formats.items():
    # Fixture needs to be defined in the global scope so pytest can detect it.
    globals()[format_name] = base_spec_filler_parametrizer(fixture_class)


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    """
    Pytest hook used to dynamically generate test cases for each fork.

    This hook parametrizes the 'fork' fixture with the fork class specified
    via the --fork command-line option, but only if the test is valid for
    that fork based on validity markers (valid_from, valid_until, valid_at).
    """
    # Only parametrize if the test uses the fork fixture
    if "fork" not in metafunc.fixturenames:
        return

    # Get the fork class from config (validated in pytest_configure)
    fork_class = metafunc.config.consensus_fork_class  # type: ignore[attr-defined]

    # Check fork validity markers on the test
    if not _is_test_valid_for_fork(metafunc, fork_class):
        # - High verbosity (>=2): Show skipped tests explicitly
        # - Normal/low verbosity: Don't parametrize at all (tests aren't collected)
        verbose = metafunc.config.getoption("verbose")
        if verbose >= 2:
            # Create a visible skipped test
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
        # else: Don't parametrize - test won't be collected at all
        return

    # Parametrize the fork fixture with the selected fork
    metafunc.parametrize(
        "fork",
        [pytest.param(fork_class, id=f"fork_{fork_class.name()}")],
        scope="function",
    )


def _is_test_valid_for_fork(metafunc: pytest.Metafunc, fork_class: Fork) -> bool:
    """
    Check if a test is valid for the given fork based on validity markers.

    Args:
        metafunc: pytest Metafunc object containing test information.
        fork_class: The fork class to check validity against.

    Returns:
        True if the test should run for this fork, False otherwise.
    """
    # Get all markers on the test
    markers = list(metafunc.definition.iter_markers())

    # Track which validity markers we've seen
    has_valid_from = False
    has_valid_until = False
    has_valid_at = False

    valid_from_forks = []
    valid_until_forks = []
    valid_at_forks = []

    # Process each marker
    for marker in markers:
        if marker.name == "valid_from":
            has_valid_from = True
            # Marker args are fork names as strings
            for fork_name in marker.args:
                target_fork = get_fork_by_name(fork_name)
                if target_fork:
                    valid_from_forks.append(target_fork)

        elif marker.name == "valid_until":
            has_valid_until = True
            for fork_name in marker.args:
                target_fork = get_fork_by_name(fork_name)
                if target_fork:
                    valid_until_forks.append(target_fork)

        elif marker.name == "valid_at":
            has_valid_at = True
            for fork_name in marker.args:
                target_fork = get_fork_by_name(fork_name)
                if target_fork:
                    valid_at_forks.append(target_fork)

    # If no markers, test is valid for all forks
    if not (has_valid_from or has_valid_until or has_valid_at):
        return True

    # If valid_at is specified, ONLY those forks are valid
    if has_valid_at:
        return fork_class in valid_at_forks

    # Check valid_from constraint (fork_class >= any of the from forks)
    from_valid = True
    if has_valid_from:
        from_valid = any(fork_class >= from_fork for from_fork in valid_from_forks)

    # Check valid_until constraint (fork_class <= any of the until forks)
    until_valid = True
    if has_valid_until:
        until_valid = any(fork_class <= until_fork for until_fork in valid_until_forks)

    # Test is valid if it passes both constraints
    return from_valid and until_valid
