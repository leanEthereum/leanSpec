"""Layer-agnostic pytest plugin for generating Ethereum test fixtures."""

import importlib
import json
import shutil
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, List

import pytest

# Layer configuration mapping
LAYER_MODULES = {
    "consensus": {
        "forks": "consensus_testing.forks",
        "fixtures": "consensus_testing.test_fixtures",
        "genesis_builder": "lean_spec.subspecs.containers.State",
    },
    "execution": {
        # Future execution layer modules
        "forks": "execution_testing.forks",
        "fixtures": "execution_testing.test_fixtures",
        "genesis_builder": None,  # TBD
    },
}


class FixtureCollector:
    """Collects generated fixtures and writes them to disk."""

    def __init__(self, output_dir: Path, fork: str, layer: str):
        """
        Initialize the fixture collector.

        Args:
            output_dir: Root directory for generated fixtures.
            fork: The fork name (e.g., "Devnet", "Shanghai").
            layer: The Ethereum layer (e.g., "consensus", "execution").
        """
        self.output_dir = output_dir
        self.fork = fork
        self.layer = layer
        self.fixtures: List[tuple[str, str, Any, str]] = []

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
            fixture_format: Format name (e.g., "state_transition_test").
            fixture: The fixture object.
            test_nodeid: Complete pytest node ID.
            config: Pytest config object to attach fixture path metadata.
        """
        self.fixtures.append((test_name, fixture_format, fixture, test_nodeid))

        if config is not None:
            nodeid_parts = test_nodeid.split("::")
            test_file_path = nodeid_parts[0]
            func_name_with_params = nodeid_parts[1] if len(nodeid_parts) > 1 else ""
            base_func_name = func_name_with_params.split("[")[0]

            test_file = Path(test_file_path)
            # Extract test path relative to tests/{layer}
            # e.g., tests/consensus/devnet/... -> devnet/...
            layer = config.test_layer if hasattr(config, "test_layer") else "consensus"

            try:
                relative_path = test_file.relative_to(f"tests/{layer}")
            except ValueError:
                # Fallback: try to extract from full path
                relative_path = test_file

            test_path = relative_path.with_suffix("")

            # Build output path: fixtures/{layer}/{format}/{test_path}
            format_dir = fixture_format.replace("_test", "")
            fixture_dir = self.output_dir / layer / format_dir / test_path
            fixture_path = fixture_dir / f"{base_func_name}.json"

            config.fixture_path_absolute = str(fixture_path.absolute())  # type: ignore[attr-defined]
            config.fixture_path_relative = str(fixture_path.relative_to(self.output_dir))  # type: ignore[attr-defined]
            config.fixture_format = fixture_format  # type: ignore[attr-defined]

    def write_fixtures(self) -> None:
        """Write all collected fixtures to disk, grouped by test function."""
        grouped: dict[tuple[str, str, str], list[tuple[str, Any, str]]] = defaultdict(list)

        for test_name, fixture_format, fixture, test_nodeid in self.fixtures:
            nodeid_parts = test_nodeid.split("::")
            test_file_path = nodeid_parts[0]
            func_name_with_params = nodeid_parts[1] if len(nodeid_parts) > 1 else ""
            base_func_name = func_name_with_params.split("[")[0]

            group_key = (test_file_path, base_func_name, fixture_format)
            grouped[group_key].append((test_name, fixture, test_nodeid))

        for (test_file_path, base_func_name, fixture_format), fixtures_list in grouped.items():
            test_file = Path(test_file_path)

            # Extract test path relative to tests/{layer}
            # e.g., tests/consensus/devnet/... -> devnet/...
            try:
                relative_path = test_file.relative_to(f"tests/{self.layer}")
            except ValueError:
                # Fallback: use full path
                relative_path = test_file

            test_path = relative_path.with_suffix("")

            # Build output path: fixtures/{layer}/{format}/{test_path}
            format_dir = fixture_format.replace("_test", "")
            fixture_dir = self.output_dir / self.layer / format_dir / test_path
            fixture_dir.mkdir(parents=True, exist_ok=True)

            output_file = fixture_dir / f"{base_func_name}.json"

            all_tests = {}
            for test_name, fixture, test_nodeid in fixtures_list:
                del test_name
                test_id = f"{test_nodeid}[fork_{self.fork}-{fixture_format}]"
                fixture_dict = fixture.json_dict_with_info()
                all_tests[test_id] = fixture_dict

            with open(output_file, "w") as f:
                json.dump(all_tests, f, indent=4)


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
        "--layer",
        action="store",
        default="consensus",
        help="Ethereum layer (consensus or execution, default: consensus)",
    )
    group.addoption(
        "--clean",
        action="store_true",
        default=False,
        help="Clean output directory before generating",
    )


def pytest_ignore_collect(collection_path: Path, config: pytest.Config) -> bool | None:
    """
    Ignore test collection for paths not in the current layer.

    This prevents pytest from collecting tests from other layers,
    reducing overhead significantly when there are many tests.
    """
    if not hasattr(config, "test_layer"):
        return None

    layer = config.test_layer

    # Check if path is under tests/ directory
    try:
        relative_path = collection_path.relative_to(Path.cwd() / "tests")
    except ValueError:
        # Not under tests/, let pytest handle it normally
        return None

    # If it's directly under tests/{layer}, don't ignore
    if str(relative_path).startswith(layer):
        return None

    # Check if it's a different layer directory or unit tests
    parts = relative_path.parts
    if parts and parts[0] in LAYER_MODULES:
        # It's a different layer, ignore it
        return True

    # It's probably unit tests (tests/lean_spec), ignore during fill
    if parts and parts[0] not in LAYER_MODULES:
        return True

    return None


def pytest_configure(config: pytest.Config) -> None:
    """Setup fixture generation session with layer-specific modules."""
    # Get layer and validate
    layer = config.getoption("--layer", default="consensus").lower()
    if layer not in LAYER_MODULES:
        pytest.exit(
            f"Invalid layer: {layer}. Must be one of: {', '.join(LAYER_MODULES.keys())}",
            returncode=pytest.ExitCode.USAGE_ERROR,
        )

    # Store layer for later use (needed by pytest_ignore_collect hook)
    config.test_layer = layer  # type: ignore[attr-defined]

    # Dynamically import layer-specific modules
    layer_config = LAYER_MODULES[layer]

    try:
        forks_module = importlib.import_module(layer_config["forks"])  # type: ignore[index]
        config.forks_module = forks_module  # type: ignore[attr-defined]
    except ImportError as e:
        pytest.exit(
            f"Failed to import {layer} layer forks module: {e}",
            returncode=pytest.ExitCode.USAGE_ERROR,
        )

    # Register layer-specific test fixture formats
    _register_layer_fixtures(config, layer)

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

    # Get available forks from layer-specific module
    get_forks = forks_module.get_forks
    get_fork_by_name = forks_module.get_fork_by_name

    available_forks = get_forks()
    available_fork_names = sorted(fork.name() for fork in available_forks)

    # Validate fork
    if not fork_name:
        print("Error: --fork is required", file=sys.stderr)
        print(
            f"Available {layer} forks: {', '.join(available_fork_names)}",
            file=sys.stderr,
        )
        pytest.exit("Missing required --fork option.", returncode=pytest.ExitCode.USAGE_ERROR)

    fork_class = get_fork_by_name(fork_name)
    if fork_class is None:
        print(
            f"Error: Unsupported fork for {layer} layer: {fork_name}\n",
            file=sys.stderr,
        )
        print(
            f"Available {layer} forks: {', '.join(available_fork_names)}",
            file=sys.stderr,
        )
        pytest.exit("Invalid fork specified.", returncode=pytest.ExitCode.USAGE_ERROR)

    # Check output directory
    if output_dir.exists() and any(output_dir.iterdir()):
        if not clean:
            contents = list(output_dir.iterdir())[:5]
            summary = ", ".join(item.name for item in contents)
            if len(list(output_dir.iterdir())) > 5:
                summary += ", ..."
            pytest.exit(
                f"Output directory '{output_dir}' is not empty. "
                f"Contains: {summary}. Use --clean to remove all existing files "
                "or specify a different output directory.",
                returncode=pytest.ExitCode.USAGE_ERROR,
            )
        shutil.rmtree(output_dir)

    output_dir.mkdir(parents=True, exist_ok=True)

    # Create collector with layer info
    config.fixture_collector = FixtureCollector(output_dir, fork_name, layer)  # type: ignore[attr-defined]
    config.test_fork_class = fork_class  # type: ignore[attr-defined]


def pytest_collection_modifyitems(config: pytest.Config, items: List[pytest.Item]) -> None:
    """Modify collected test items to deselect tests not valid for the selected fork."""
    if not hasattr(config, "test_fork_class"):
        return

    fork_class = config.test_fork_class
    forks_module = config.forks_module  # type: ignore[attr-defined]
    get_fork_by_name = forks_module.get_fork_by_name
    verbose = config.getoption("verbose")
    deselected = []
    selected = []

    for item in items:
        if not _is_test_item_valid_for_fork(item, fork_class, get_fork_by_name):
            if verbose < 2:
                deselected.append(item)
            else:
                selected.append(item)
        else:
            selected.append(item)

    if deselected:
        items[:] = selected
        config.hook.pytest_deselected(items=deselected)


def _is_test_item_valid_for_fork(item: pytest.Item, fork_class: Any, get_fork_by_name: Any) -> bool:
    """Check if a test item is valid for the given fork based on validity markers."""
    markers = list(item.iter_markers())

    has_valid_from = False
    has_valid_until = False
    has_valid_at = False

    valid_from_forks = []
    valid_until_forks = []
    valid_at_forks = []

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

    if not (has_valid_from or has_valid_until or has_valid_at):
        return True

    if has_valid_at:
        return fork_class in valid_at_forks

    from_valid = True
    if has_valid_from:
        from_valid = any(fork_class >= from_fork for from_fork in valid_from_forks)

    until_valid = True
    if has_valid_until:
        until_valid = any(fork_class <= until_fork for until_fork in valid_until_forks)

    return from_valid and until_valid


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Write all collected fixtures at the end of the session."""
    if hasattr(session.config, "fixture_collector"):
        session.config.fixture_collector.write_fixtures()


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[None]) -> Any:
    """Make each test's fixture json path available to the test report."""
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
def fork(request: pytest.FixtureRequest) -> Any:
    """Parametrize test cases by fork (dynamically loaded based on layer)."""
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


@pytest.fixture(scope="function")
def genesis(request: pytest.FixtureRequest) -> Any:
    """
    Default genesis state (layer-specific).

    For consensus layer, returns a State.
    For execution layer, returns appropriate genesis config.
    """
    layer = request.config.test_layer  # type: ignore[attr-defined]

    if layer == "consensus":
        # Import consensus-specific genesis
        from lean_spec.subspecs.containers import State
        from lean_spec.types import Uint64

        if hasattr(request, "param"):
            return State.generate_genesis(**request.param)

        return State.generate_genesis(
            genesis_time=Uint64(0),
            num_validators=Uint64(4),
        )
    elif layer == "execution":
        # Future: execution layer genesis
        raise NotImplementedError("Execution layer genesis not yet implemented")
    else:
        raise ValueError(f"Unknown layer: {layer}")


def base_spec_filler_parametrizer(fixture_class: Any) -> Any:
    """
    Generate pytest.fixture for a given fixture class.

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
        fork: Any,
        test_case_description: str,
    ) -> Any:
        """Fixture used to instantiate an auto-fillable fixture object."""

        class FixtureWrapper(fixture_class):  # type: ignore[misc]
            """Wrapper class that auto-fills and collects fixtures on instantiation."""

            def __init__(self, **kwargs: Any) -> None:
                super().__init__(**kwargs)

                filled_fixture = self.make_fixture()
                filled_fixture.fill_info(
                    test_id=request.node.nodeid,
                    description=test_case_description,
                    fork=fork,
                )

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


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    """Pytest hook to dynamically generate test cases for each fork."""
    if "fork" not in metafunc.fixturenames:
        return

    fork_class = metafunc.config.test_fork_class  # type: ignore[attr-defined]
    forks_module = metafunc.config.forks_module  # type: ignore[attr-defined]
    get_fork_by_name = forks_module.get_fork_by_name

    if not _is_test_valid_for_fork(metafunc, fork_class, get_fork_by_name):
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


def _is_test_valid_for_fork(
    metafunc: pytest.Metafunc, fork_class: Any, get_fork_by_name: Any
) -> bool:
    """Check if a test is valid for the given fork based on validity markers."""
    markers = list(metafunc.definition.iter_markers())

    has_valid_from = False
    has_valid_until = False
    has_valid_at = False

    valid_from_forks = []
    valid_until_forks = []
    valid_at_forks = []

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

    if not (has_valid_from or has_valid_until or has_valid_at):
        return True

    if has_valid_at:
        return fork_class in valid_at_forks

    from_valid = True
    if has_valid_from:
        from_valid = any(fork_class >= from_fork for from_fork in valid_from_forks)

    until_valid = True
    if has_valid_until:
        until_valid = any(fork_class <= until_fork for until_fork in valid_until_forks)

    return from_valid and until_valid


def _register_layer_fixtures(config: pytest.Config, layer: str) -> None:
    """Register layer-specific test fixture formats during configuration."""
    layer_config = LAYER_MODULES.get(layer, {})
    fixtures_module_name = layer_config.get("fixtures")  # type: ignore[attr-defined]

    if not fixtures_module_name:
        return

    try:
        # Import the fixtures module to trigger registration
        fixtures_module = importlib.import_module(fixtures_module_name)

        # Get the base fixture class
        if layer == "consensus":
            base_fixture_class = fixtures_module.BaseConsensusFixture
        elif layer == "execution":
            base_fixture_class = fixtures_module.BaseExecutionFixture
        else:
            return

        # Register all fixture formats globally so pytest can discover them
        # This must happen during pytest_configure, before fixture discovery
        for format_name, fixture_class in base_fixture_class.formats.items():
            fixture_func = base_spec_filler_parametrizer(fixture_class)
            # Add to module globals so pytest can discover them
            globals()[format_name] = fixture_func
    except (ImportError, AttributeError) as e:
        pytest.exit(
            f"Failed to load {layer} layer test fixtures: {e}",
            returncode=pytest.ExitCode.USAGE_ERROR,
        )
