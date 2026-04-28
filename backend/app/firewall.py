import os
import shlex
from contextlib import contextmanager
from pathlib import Path


class FirewallError(RuntimeError):
    pass


class FirewallConfigError(FirewallError):
    pass


class FirewallConnectionError(FirewallError):
    pass


class FirewallCommandError(FirewallError):
    pass


def _load_env_if_present():
    env_path = Path(__file__).resolve().parents[1] / ".env"
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("export "):
            line = line[len("export ") :].strip()

        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue

        # Strip inline comments only when separated by whitespace.
        if value and value[0] not in ("'", '"') and " #" in value:
            value = value.split(" #", 1)[0].rstrip()

        # Strip surrounding quotes.
        if len(value) >= 2 and value[0] in ("'", '"') and value[-1] == value[0]:
            value = value[1:-1]

        os.environ.setdefault(key, value)


def _get_ssh_config():
    _load_env_if_present()

    ip = os.getenv("BASE_IP")
    user = os.getenv("BASE_USER")
    password = os.getenv("BASE_PASS")

    if not ip or not user or not password:
        raise FirewallConfigError(
            "Remote firewall is not configured. Set BASE_IP, BASE_USER, BASE_PASS in backend/.env"
        )

    return ip, user, password


def _get_paramiko():
    try:
        import paramiko  # type: ignore
    except ImportError as exc:
        raise FirewallConfigError(
            "SSH support isn't installed. Install it with: pip install paramiko"
        ) from exc
    return paramiko


@contextmanager
def _ssh_client():
    paramiko = _get_paramiko()
    ip, user, password = _get_ssh_config()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            ip,
            username=user,
            password=password,
            timeout=10,
            banner_timeout=10,
            auth_timeout=10,
        )
        yield client
    except paramiko.AuthenticationException as exc:
        raise FirewallConnectionError(
            "SSH authentication failed. Check BASE_USER/BASE_PASS and SSH settings on the Raspberry Pi."
        ) from exc
    except (paramiko.SSHException, OSError) as exc:
        raise FirewallConnectionError(
            "SSH connection failed. Check BASE_IP and make sure the Raspberry Pi is reachable and SSH is enabled."
        ) from exc
    finally:
        try:
            client.close()
        except Exception:
            pass


def _run_remote(client, args):
    command = " ".join(shlex.quote(str(a)) for a in args)
    stdin, stdout, stderr = client.exec_command(command)
    exit_code = stdout.channel.recv_exit_status()
    out = stdout.read().decode(errors="replace").strip()
    err = stderr.read().decode(errors="replace").strip()

    if exit_code != 0:
        message = err or out or f"exit status {exit_code}"
        raise FirewallCommandError(
            "Remote firewall command failed. Ensure nftables is installed on the Raspberry Pi and the SSH user has permission to run nft. "
            f"({message})"
        )


def _build_add_rule_args(rule):
    action = "accept" if rule.action == "allow" else "drop"
    return [
        "nft",
        "add",
        "rule",
        "inet",
        "myfw",
        "input",
        "ip",
        "saddr",
        rule.ip,
        action,
    ]


def _build_flush_chain_args():
    return ["nft", "flush", "chain", "inet", "myfw", "input"]


def apply_rule(rule):
    """Apply a single rule on the Raspberry Pi via SSH."""

    with _ssh_client() as client:
        _run_remote(client, _build_add_rule_args(rule))
    rule.applied = True


def flush_rules():
    """Flush the target nftables chain on the Raspberry Pi via SSH."""

    with _ssh_client() as client:
        _run_remote(client, _build_flush_chain_args())


def apply_rules(rules):
    """Flush then apply all rules on the Raspberry Pi via SSH (single SSH session)."""

    with _ssh_client() as client:
        _run_remote(client, _build_flush_chain_args())
        for rule in rules:
            _run_remote(client, _build_add_rule_args(rule))
            rule.applied = True
