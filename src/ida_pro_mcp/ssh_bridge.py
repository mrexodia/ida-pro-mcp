"""SSH bridge for using a local IDA Pro from a remote AI agent.

Scenario: IDA Pro (with the ida-pro-mcp plugin) runs on a *local* workstation,
while the MCP client (Claude Code, etc.) runs on a *remote* SSH server. The
remote agent cannot reach the local IDA RPC server on 127.0.0.1.

This subcommand runs on the *local* workstation and establishes an SSH reverse
tunnel (the connection is initiated outbound from local -> remote, so it works
even when local is behind NAT / on an intranet). Two modes:

  sse  (default, zero remote install)
      Start a local SSE MCP server next to IDA and reverse-forward only that
      SSE port. The remote agent points its MCP client at the tunneled URL;
      nothing needs to be installed on the remote server.

  rpc  (remote runs `server.py`)
      Reverse-forward the IDA RPC port(s) directly. The remote must have
      `ida-pro-mcp` installed and connects with `--ida-rpc http://127.0.0.1:PORT`.
"""

import argparse
import os
import socket
import subprocess
import sys
import time

try:
    from .ida_mcp.discovery import discover_instances
except ImportError:
    try:
        from ida_mcp.discovery import discover_instances
    except ImportError:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ida_mcp"))
        from discovery import discover_instances

        sys.path.pop(0)

DEFAULT_IDA_PORT = 13337
DEFAULT_SSE_PORT = 8744


def _log(msg: str) -> None:
    print(f"[ssh-bridge] {msg}", file=sys.stderr, flush=True)


def _ssh_base(args) -> list[str]:
    """Common ssh invocation: keepalive + fail-fast on broken forwards."""
    cmd = [
        "ssh",
        "-N",  # do not run a remote command; we only want the tunnel
        "-o", f"ServerAliveInterval={args.keepalive}",
        "-o", "ServerAliveCountMax=3",
        "-o", "ExitOnForwardFailure=yes",
        "-o", "ConnectTimeout=10",
    ]
    if args.identity:
        cmd += ["-i", os.path.expanduser(args.identity)]
    if args.port_ssh:
        cmd += ["-p", str(args.port_ssh)]
    return cmd


def _reverse_forward(remote_bind: str, port: int) -> list[str]:
    """Reverse-forward remote `remote_bind:port` -> local `127.0.0.1:port`."""
    return ["-R", f"{remote_bind}:{port}:127.0.0.1:{port}"]


def _wait_for_local_port(port: int, timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def _resolve_rpc_ports(args) -> list[int]:
    """Determine which local IDA RPC ports to forward in rpc mode."""
    if args.port:
        return sorted(set(args.port))

    if args.all_instances:
        instances = discover_instances()
        ports = sorted({int(i["port"]) for i in instances})
        if ports:
            _log(f"discovered {len(ports)} IDA instance(s): {ports}")
            return ports
        _log(f"no running IDA instances found, falling back to {DEFAULT_IDA_PORT}")
        return [DEFAULT_IDA_PORT]

    # Default: single instance, prefer a discovered one, else the default port.
    instances = discover_instances()
    if instances:
        return [int(instances[0]["port"])]
    return [DEFAULT_IDA_PORT]


def _run_ssh_forever(ssh_cmd: list[str], verbose: bool) -> None:
    """Run ssh, auto-reconnecting with exponential backoff until interrupted."""
    if verbose:
        _log("ssh command: " + " ".join(ssh_cmd))
    backoff = 1.0
    proc = None
    try:
        while True:
            started = time.monotonic()
            proc = subprocess.Popen(ssh_cmd)
            ret = proc.wait()
            proc = None
            uptime = time.monotonic() - started
            # A long-lived connection means the tunnel was healthy: reset backoff.
            if uptime > 30:
                backoff = 1.0
            _log(
                f"ssh exited (code {ret}, up {uptime:.0f}s); "
                f"reconnecting in {backoff:.0f}s"
            )
            time.sleep(backoff)
            backoff = min(backoff * 2, 30.0)
    except KeyboardInterrupt:
        _log("interrupted, shutting down tunnel")
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


def _start_local_sse_server(sse_port: int, ida_rpc: str | None, verbose: bool):
    """Spawn a local SSE MCP server next to IDA. Returns the Popen handle."""
    cmd = [
        sys.executable,
        "-m",
        "ida_pro_mcp.server",
        "--transport",
        f"http://127.0.0.1:{sse_port}/sse",
    ]
    if ida_rpc:
        cmd += ["--ida-rpc", ida_rpc]
    if verbose:
        _log("local SSE server: " + " ".join(cmd))
    # server.py serves in a background thread and blocks the main thread on
    # input(). We keep an open (never-written) stdin pipe so that input()
    # blocks instead of hitting EOF, which would make the server exit
    # immediately. The pipe stays open for the process lifetime.
    return subprocess.Popen(cmd, stdin=subprocess.PIPE)


def _run_sse_mode(args) -> None:
    sse_port = args.sse_port
    _log(f"mode=sse: starting local SSE server on 127.0.0.1:{sse_port}")
    server = _start_local_sse_server(sse_port, args.ida_rpc, args.verbose)
    try:
        if not _wait_for_local_port(sse_port):
            _log(
                f"local SSE server did not start listening on {sse_port}; "
                "check that IDA is running with the MCP plugin started."
            )
            return
        _log("local SSE server is up")

        ssh_cmd = _ssh_base(args)
        ssh_cmd += _reverse_forward(args.remote_bind, sse_port)
        ssh_cmd += [args.target]

        remote_url = f"http://{args.remote_bind}:{sse_port}/sse"
        _log(f"reverse tunnel: remote {args.remote_bind}:{sse_port} -> local 127.0.0.1:{sse_port}")
        _log("=" * 60)
        _log("On the remote server, configure your MCP client with URL:")
        _log(f"    {remote_url}")
        _log("(No ida-pro-mcp install needed on the remote.)")
        _log("=" * 60)

        _run_ssh_forever(ssh_cmd, args.verbose)
    finally:
        if server.poll() is None:
            _log("stopping local SSE server")
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()


def _run_rpc_mode(args) -> None:
    ports = _resolve_rpc_ports(args)
    _log(f"mode=rpc: forwarding IDA RPC port(s) {ports}")

    ssh_cmd = _ssh_base(args)
    for port in ports:
        ssh_cmd += _reverse_forward(args.remote_bind, port)
    ssh_cmd += [args.target]

    _log("=" * 60)
    _log("On the remote server, ida-pro-mcp must be installed. Configure it with:")
    for port in ports:
        _log(f"    ida-pro-mcp --ida-rpc http://{args.remote_bind}:{port}")
    _log("=" * 60)

    _run_ssh_forever(ssh_cmd, args.verbose)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="ida-pro-mcp ssh-bridge",
        description="Bridge a local IDA Pro to a remote MCP client over an SSH "
        "reverse tunnel (run this on the machine where IDA is running).",
    )
    parser.add_argument(
        "target",
        help="SSH target, e.g. user@remote-server or a Host alias from ~/.ssh/config",
    )
    parser.add_argument(
        "--mode",
        choices=["sse", "rpc"],
        default="sse",
        help="sse: start a local SSE server and forward only its port "
        "(no remote install, default). rpc: forward the IDA RPC port(s) "
        "(remote needs ida-pro-mcp).",
    )
    parser.add_argument(
        "--sse-port",
        type=int,
        default=DEFAULT_SSE_PORT,
        help=f"sse mode: local SSE server port (default {DEFAULT_SSE_PORT})",
    )
    parser.add_argument(
        "--port",
        type=int,
        action="append",
        help="rpc mode: local IDA RPC port to forward (repeatable)",
    )
    parser.add_argument(
        "--all-instances",
        action="store_true",
        help="rpc mode: discover and forward all running local IDA instances",
    )
    parser.add_argument(
        "--ida-rpc",
        type=str,
        default=None,
        help="sse mode: explicit IDA RPC target for the local SSE server "
        "(default: auto-discover)",
    )
    parser.add_argument(
        "--remote-bind",
        type=str,
        default="127.0.0.1",
        help="Address the tunnel binds to on the remote (default 127.0.0.1, "
        "loopback-only). Using 0.0.0.0 exposes IDA to other users on the "
        "remote host and requires sshd GatewayPorts.",
    )
    parser.add_argument(
        "--identity",
        type=str,
        default=None,
        help="SSH private key file (passed to ssh -i)",
    )
    parser.add_argument(
        "--port-ssh",
        type=int,
        default=None,
        help="SSH port of the remote server (passed to ssh -p)",
    )
    parser.add_argument(
        "--keepalive",
        type=int,
        default=30,
        help="ServerAliveInterval seconds (default 30)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the ssh command(s) that would be run and exit",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose logging (print ssh/server commands)",
    )
    args = parser.parse_args(argv)

    if args.remote_bind not in ("127.0.0.1", "localhost", "::1"):
        _log(
            f"WARNING: --remote-bind {args.remote_bind} exposes the tunnel to "
            "other users/hosts on the remote. Ensure sshd has 'GatewayPorts "
            "yes' (or 'clientspecified') and that this is intended."
        )

    if args.dry_run:
        if args.mode == "sse":
            ssh_cmd = _ssh_base(args) + _reverse_forward(args.remote_bind, args.sse_port) + [args.target]
            sse_cmd = [
                sys.executable, "-m", "ida_pro_mcp.server",
                "--transport", f"http://127.0.0.1:{args.sse_port}/sse",
            ]
            if args.ida_rpc:
                sse_cmd += ["--ida-rpc", args.ida_rpc]
            print("local SSE server: " + " ".join(sse_cmd))
            print("ssh tunnel: " + " ".join(ssh_cmd))
        else:
            ports = _resolve_rpc_ports(args)
            ssh_cmd = _ssh_base(args)
            for port in ports:
                ssh_cmd += _reverse_forward(args.remote_bind, port)
            ssh_cmd += [args.target]
            print("ssh tunnel: " + " ".join(ssh_cmd))
        return

    if args.mode == "sse":
        _run_sse_mode(args)
    else:
        _run_rpc_mode(args)


if __name__ == "__main__":
    main()
