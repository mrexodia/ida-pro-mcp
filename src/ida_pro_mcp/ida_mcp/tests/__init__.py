"""IDA Pro MCP Test Package.

This package contains test modules for each API module.
Tests are registered via the @test decorator from the framework module.
"""

# Import all test modules to register tests when the package is imported
from . import test_api_core
from . import test_api_analysis
from . import test_api_memory
from . import test_api_modify
from . import test_api_types
from . import test_api_stack
from . import test_api_resources
from . import test_api_python
from . import test_framework_helpers
from . import test_typed_fixture
from . import test_utils
from . import test_api_analysis_internals
from . import test_profile
