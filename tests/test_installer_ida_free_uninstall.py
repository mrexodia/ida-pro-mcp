import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout

from ida_pro_mcp import installer


class InstallerIdaFreeUninstallTests(unittest.TestCase):
    def _make_ida_dir(self, tmp_dir: str) -> str:
        """Return a fake IDA user dir holding a plugin and an IDA Free license.

        The plugins folder is returned so each test can inspect the result.
        """
        ida_folder = os.path.join(tmp_dir, "ida")
        plugins = os.path.join(ida_folder, "plugins")
        os.makedirs(plugins)
        with open(os.path.join(plugins, "ida_mcp.py"), "w") as file:
            file.write("# installed plugin loader\n")
        with open(os.path.join(ida_folder, "idafree_9.2.hexlic"), "w") as file:
            file.write("")
        return plugins

    def _with_ida_dir(self, tmp_dir: str):
        """Point ``_get_ida_user_dir`` at ``tmp_dir`` for one call."""
        path = os.path.join(tmp_dir, "ida")
        original = installer._get_ida_user_dir
        installer._get_ida_user_dir = lambda: path
        return original

    def test_uninstall_removes_the_plugin_despite_ida_free(self) -> None:
        """``--uninstall`` works while an IDA Free license file is present."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            plugins = self._make_ida_dir(tmp_dir)
            original = self._with_ida_dir(tmp_dir)
            try:
                with redirect_stdout(io.StringIO()):
                    installer.install_ida_plugin(uninstall=True)
            finally:
                installer._get_ida_user_dir = original

            self.assertFalse(
                os.path.lexists(os.path.join(plugins, "ida_mcp.py")),
                "uninstall must remove the plugin even when IDA Free is "
                "installed",
            )

    def test_install_still_refuses_ida_free_without_the_flag(self) -> None:
        """Control: the license guard keeps protecting installation."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            plugins = self._make_ida_dir(tmp_dir)
            original = self._with_ida_dir(tmp_dir)
            output = io.StringIO()
            try:
                with redirect_stdout(output), self.assertRaises(
                    SystemExit
                ) as raised:
                    installer.install_ida_plugin()
            finally:
                installer._get_ida_user_dir = original

            self.assertEqual(raised.exception.code, 1)
            self.assertIn(
                "IDA Free does not support plugins",
                output.getvalue(),
            )
            self.assertTrue(
                os.path.lexists(os.path.join(plugins, "ida_mcp.py")),
                "a refused install must not touch the installed plugin",
            )

    def test_run_install_command_uninstall_reaches_client_targets(self) -> None:
        """``--uninstall <client>`` continues past the plugin step."""

        class _Args:
            allow_ida_free = False
            scope = None
            transport = None
            project = False
            all_users = False

        with tempfile.TemporaryDirectory() as tmp_dir:
            self._make_ida_dir(tmp_dir)
            original_user_dir = self._with_ida_dir(tmp_dir)
            original_apply = installer._apply_client_install
            reached: list[bool] = []
            installer._apply_client_install = (
                lambda **kwargs: reached.append(kwargs["uninstall"]) or None
            )
            try:
                with redirect_stdout(io.StringIO()):
                    installer.run_install_command(
                        uninstall=True,
                        targets_str="cursor",
                        args=_Args(),
                    )
            finally:
                installer._get_ida_user_dir = original_user_dir
                installer._apply_client_install = original_apply

            self.assertEqual(reached, [True])


if __name__ == "__main__":
    unittest.main()
