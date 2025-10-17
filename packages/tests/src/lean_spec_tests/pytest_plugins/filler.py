"""Pytest plugin for generating consensus test fixtures."""

import json
from pathlib import Path
from typing import Any, List

import pytest

from lean_spec_tests.base_types import CamelModel
from lean_spec_tests.forks import Devnet, Fork
from lean_spec_tests.spec_fixtures import BaseConsensusFixture


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
    ) -> None:
        """
        Add a fixture to the collection.

        Args:
            test_name: Name of the test that generated this fixture.
            fixture_format: Format name (e.g., "vote_processing_test").
            fixture: The fixture object.
            test_nodeid: Complete pytest node ID (e.g., "tests/path/test.py::test_name").
        """
        self.fixtures.append((test_name, fixture_format, fixture, test_nodeid))

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

    # Get options
    output_dir = Path(config.getoption("--output"))
    fork_name = config.getoption("--fork")
    clean = config.getoption("--clean")

    # Map of supported forks
    supported_forks = {
        "devnet": Devnet,
    }

    # Validate fork
    if not fork_name:
        print(
            "Error: --fork is required",
            file=sys.stderr,
        )
        available_forks_help = textwrap.dedent(
            f"""\
            Available forks:
            {", ".join(supported_forks.keys())}
            """
        )
        print(available_forks_help, file=sys.stderr)
        pytest.exit("Missing required --fork option.", returncode=pytest.ExitCode.USAGE_ERROR)

    if fork_name.lower() not in supported_forks:
        print(
            f"Error: Unsupported fork provided to --fork: {fork_name}\n",
            file=sys.stderr,
        )
        available_forks_help = textwrap.dedent(
            f"""\
            Available forks:
            {", ".join(supported_forks.keys())}
            """
        )
        print(available_forks_help, file=sys.stderr)
        pytest.exit("Invalid fork specified.", returncode=pytest.ExitCode.USAGE_ERROR)

    # Get the fork class
    fork_class = supported_forks[fork_name.lower()]

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


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Write all collected fixtures at the end of the session."""
    if hasattr(session.config, "fixture_collector"):
        session.config.fixture_collector.write_fixtures()


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[None]) -> Any:
    """Skip test failures during fixture generation."""
    outcome = yield
    report = outcome.get_result()

    # During fixture generation, we don't care about test results
    # We only care about generating fixtures
    if call.when == "call":
        # Mark as passed regardless of actual result
        report.outcome = "passed"

    return report


@pytest.fixture(autouse=True)
def fork(request: pytest.FixtureRequest) -> Fork:  # type: ignore[empty-body]
    """
    Parametrize test cases by fork.

    This fixture is parametrized by pytest_generate_tests() and receives
    the fork class as a parameter value.
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
    via the --fork command-line option. This follows the execution-spec-tests
    pattern for fork parametrization.
    """
    # Only parametrize if the test uses the fork fixture
    if "fork" not in metafunc.fixturenames:
        return

    # Get the fork class from config (validated in pytest_configure)
    fork_class = metafunc.config.consensus_fork_class  # type: ignore[attr-defined]

    # Parametrize the fork fixture with the selected fork
    metafunc.parametrize(
        "fork",
        [pytest.param(fork_class, id=f"fork_{fork_class.name()}")],
        scope="function",
    )
