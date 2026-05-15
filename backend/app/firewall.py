import json
import os
import shlex
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Optional


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
    out, err, exit_code = _run_remote_raw(client, args)

    if exit_code != 0:
        message = err or out or f"exit status {exit_code}"
        raise FirewallCommandError(
            "Remote firewall command failed. Ensure nftables is installed on the Raspberry Pi and the SSH user has permission to run nft. "
            f"({message})"
        )
    return out, err, exit_code


def _run_remote_raw(client, args):
    command = " ".join(shlex.quote(str(a)) for a in args)
    stdin, stdout, stderr = client.exec_command(command)
    exit_code = stdout.channel.recv_exit_status()
    out = stdout.read().decode(errors="replace").strip()
    err = stderr.read().decode(errors="replace").strip()

    return out, err, exit_code


def _ensure_table_and_chain(client) -> None:
    # Create the table/chain if they don't exist.
    # This avoids confusing errors like "No such file or directory" when applying rules.
    _, _, table_code = _run_remote_raw(client, ["sudo", "nft", "list", "table", "inet", "myfw"])
    if table_code != 0:
        _run_remote(client, ["sudo", "nft", "add", "table", "inet", "myfw"])

    _, _, chain_code = _run_remote_raw(client, ["sudo", "nft", "list", "chain", "inet", "myfw", "input"])
    if chain_code != 0:
        # Base chain with safe default policy.
        _run_remote(
            client,
            [
                "sudo",
                "nft",
                "add",
                "chain",
                "inet",
                "myfw",
                "input",
                "{",
                "type",
                "filter",
                "hook",
                "input",
                "priority",
                "0",
                ";",
                "policy",
                "accept",
                ";",
                "}",
            ],
        )


def _build_add_rule_args(rule):
    action = "accept" if rule.action == "allow" else "drop"

    def _nft_string_literal(value: str) -> str:
        # nft expects quoted strings in its rule syntax (e.g. comment "a b").
        # Passing a single argv token that contains spaces is not sufficient because
        # nft re-parses the command line into its own lexer.
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'

    raw_comment = f"netmonitor rule_id={getattr(rule, 'id', 'unknown')} ip={rule.ip}"
    comment = _nft_string_literal(raw_comment)

    args = [
        "sudo",
        "nft",
        "add",
        "rule",
        "inet",
        "myfw",
        "input",
        "ip",
        "saddr",
        rule.ip,
    ]

    # Optional port match (TCP). The UI already captures `port`, so honoring it here
    # prevents surprises when users enter a port.
    port = getattr(rule, "port", "") or ""
    if str(port).strip():
        args.extend(["tcp", "dport", str(port).strip()])

    # nft rule grammar expects the verdict (accept/drop) before trailing modifiers like `comment`.
    # Putting `comment` last avoids parse errors such as: "unexpected accept".
    args.extend(["counter", action, "comment", comment])
    return args


def _build_flush_chain_args():
    # TODO: after flushing, reset all rules to applied = false.
    return ["sudo", "nft", "flush", "chain", "inet", "myfw", "input"]


def _nft_list_table_with_handles(client) -> dict[str, Any]:
    _ensure_table_and_chain(client)
    out, _, _ = _run_remote(client, ["sudo", "nft", "-j", "-a", "list", "table", "inet", "myfw"])
    if not out:
        return {}
    try:
        return json.loads(out)
    except json.JSONDecodeError as exc:
        raise FirewallCommandError(
            "Remote firewall returned invalid JSON for `nft -j -a list table`."
        ) from exc


def _expr_comment(expr: Any) -> Optional[str]:
    if not isinstance(expr, dict):
        return None
    if "comment" in expr and isinstance(expr["comment"], str):
        return expr["comment"]
    return None


def _expr_matches_ip(expr: Any, ip: str) -> bool:
    # Matches expressions like:
    # {"match": {"left": {"payload": {"protocol": "ip", "field": "saddr"}}, "op": "==", "right": "1.2.3.4"}}
    if not isinstance(expr, dict) or "match" not in expr:
        return False
    match = expr.get("match")
    if not isinstance(match, dict):
        return False
    right = match.get("right")
    if right != ip:
        return False
    left = match.get("left")
    if not isinstance(left, dict) or "payload" not in left:
        return False
    payload = left.get("payload")
    if not isinstance(payload, dict):
        return False
    return payload.get("protocol") == "ip" and payload.get("field") == "saddr"


def _find_handle_for_rule(nft_json: dict[str, Any], rule) -> Optional[int]:
    if not nft_json:
        return None

    wanted_comment = f"netmonitor rule_id={getattr(rule, 'id', 'unknown')} ip={rule.ip}"
    wanted_ip = getattr(rule, "ip", None)

    items = nft_json.get("nftables")
    if not isinstance(items, list):
        return None

    candidates: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict) or "rule" not in item:
            continue
        r = item.get("rule")
        if not isinstance(r, dict):
            continue
        if r.get("family") != "inet" or r.get("table") != "myfw" or r.get("chain") != "input":
            continue
        candidates.append(r)

    # 1) Prefer exact comment match (reliable even with duplicate IPs).
    for r in candidates:
        expr = r.get("expr")
        if not isinstance(expr, list):
            continue
        for e in expr:
            if _expr_comment(e) == wanted_comment:
                handle = r.get("handle")
                return int(handle) if isinstance(handle, int) else None

    # 2) Fallback to matching by IP (best-effort).
    if wanted_ip:
        for r in candidates:
            expr = r.get("expr")
            if not isinstance(expr, list):
                continue
            if any(_expr_matches_ip(e, wanted_ip) for e in expr):
                handle = r.get("handle")
                return int(handle) if isinstance(handle, int) else None

    return None


def _apply_rule_in_session(client, rule) -> None:
    _ensure_table_and_chain(client)
    _run_remote(client, _build_add_rule_args(rule))

    # `nft add rule` doesn't consistently print the handle; 
    # explicitly list the table with handles.
    nft_json = _nft_list_table_with_handles(client)
    handle = _find_handle_for_rule(nft_json, rule)
    if handle is not None:
        rule.handle = handle
    rule.applied = True


def apply_rule(rule):
    """Apply a single rule on the Raspberry Pi via SSH."""
    with _ssh_client() as client:
        _apply_rule_in_session(client, rule)


def flush_rules():
    """Flush the target nftables chain on the Raspberry Pi via SSH."""

    with _ssh_client() as client:
        _ensure_table_and_chain(client)
        _run_remote(client, _build_flush_chain_args())


def apply_rules(rules):
    """Flush then apply all rules on the Raspberry Pi via SSH (single SSH session)."""

    with _ssh_client() as client:
        _ensure_table_and_chain(client)
        _run_remote(client, _build_flush_chain_args())
        for rule in rules:
            _apply_rule_in_session(client, rule)

            # Small delay to reduce chance of racing the ruleset listing on slower devices.
            time.sleep(0.02)

def delete_rule(rule):
    """Delete a single rule on the Raspberry Pi via SSH."""

    # If the rule was never applied, it won't exist remotely; just delete from DB.
    if not getattr(rule, "applied", False):
        return

    with _ssh_client() as client:
        handle = getattr(rule, "handle", 0) or 0
        if not handle:
            nft_json = _nft_list_table_with_handles(client)
            resolved = _find_handle_for_rule(nft_json, rule)
            if resolved is not None:
                handle = resolved
                rule.handle = resolved

        if not handle:
            raise FirewallCommandError(
                "Can't delete rule because its nft handle could not be determined. Try applying the rule again, or ensure the nftables table/chain exists."
            )

        _run_remote(
            client,
            [
                "sudo",
                "nft",
                "delete",
                "rule",
                "inet",
                "myfw",
                "input",
                "handle",
                str(handle),
            ],
        )


def _rule_counter(rule_json: dict[str, Any]) -> tuple[int, int]:
    # Returns (packets, bytes) for a given nft rule JSON.
    packets = 0
    bytes_ = 0

    direct = rule_json.get("counter")
    if isinstance(direct, dict):
        p = direct.get("packets")
        b = direct.get("bytes")
        if isinstance(p, int):
            packets = p
        if isinstance(b, int):
            bytes_ = b

    expr = rule_json.get("expr")
    if isinstance(expr, list):
        for e in expr:
            if not isinstance(e, dict) or "counter" not in e:
                continue
            c = e.get("counter")
            if not isinstance(c, dict):
                continue
            p = c.get("packets")
            b = c.get("bytes")
            if isinstance(p, int):
                packets = p
            if isinstance(b, int):
                bytes_ = b
            break

    return packets, bytes_


def _rule_verdict_kind(rule_json: dict[str, Any]) -> Optional[str]:
    expr = rule_json.get("expr")
    if not isinstance(expr, list):
        return None
    for e in expr:
        if not isinstance(e, dict) or "verdict" not in e:
            continue
        v = e.get("verdict")
        if isinstance(v, dict):
            kind = v.get("kind")
            if isinstance(kind, str):
                return kind
    return None


def get_netmonitor_counters() -> dict[str, int]:
    """Return aggregated counters for netmonitor rules.

    Uses `nft -j -a list table inet myfw` and sums rule counters.
    """

    with _ssh_client() as client:
        nft_json = _nft_list_table_with_handles(client)

    items = nft_json.get("nftables")
    if not isinstance(items, list):
        return {"blocked_packets_total": 0, "blocked_bytes_total": 0}

    blocked_packets_total = 0
    blocked_bytes_total = 0

    for item in items:
        if not isinstance(item, dict) or "rule" not in item:
            continue
        rule = item.get("rule")
        if not isinstance(rule, dict):
            continue
        if rule.get("family") != "inet" or rule.get("table") != "myfw" or rule.get("chain") != "input":
            continue

        expr = rule.get("expr")
        if not isinstance(expr, list):
            continue

        comment = None
        for e in expr:
            c = _expr_comment(e)
            if c:
                comment = c
                break

        # Only count rules created by netmonitor.
        if not (isinstance(comment, str) and comment.startswith("netmonitor ")):
            continue

        verdict = _rule_verdict_kind(rule)
        if verdict != "drop":
            continue

        packets, bytes_ = _rule_counter(rule)
        blocked_packets_total += int(packets)
        blocked_bytes_total += int(bytes_)

    return {
        "blocked_packets_total": blocked_packets_total,
        "blocked_bytes_total": blocked_bytes_total,
    }