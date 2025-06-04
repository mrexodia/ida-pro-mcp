from pathlib import Path
import sys

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from ida_pro_mcp import server


def test_server_wrapper():
    """Verify that the helper script exposes the offline core."""
    assert server.main is server.core.main
