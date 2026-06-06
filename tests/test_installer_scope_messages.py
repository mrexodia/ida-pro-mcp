import io
import unittest
from contextlib import redirect_stdout

from ida_pro_mcp.installer import install_mcp_servers


class InstallerScopeMessageTests(unittest.TestCase):
    def test_project_scope_client_available_globally_has_scope_hint(self):
        output = io.StringIO()

        with redirect_stdout(output):
            install_mcp_servers(
                transport="streamable-http",
                only=["codex"],
                project=True,
            )

        message = output.getvalue()
        self.assertIn("Client 'Codex' is not supported for --scope project", message)
        self.assertIn("Use --scope global for this target", message)
        self.assertNotIn("Unknown client", message)

    def test_unknown_client_still_reports_unknown(self):
        output = io.StringIO()

        with redirect_stdout(output):
            install_mcp_servers(
                transport="streamable-http",
                only=["definitely-not-a-client"],
                project=True,
            )

        self.assertIn("Unknown client: 'definitely-not-a-client'", output.getvalue())


if __name__ == "__main__":
    unittest.main()
