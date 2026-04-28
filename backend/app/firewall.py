import subprocess

def apply_rule(rule):
    action = "accept" if rule.action == "allow" else "drop"
    cmd = [
        "nft", "add", "rule", "inet", "myfw", "input",
        "ip", "saddr", rule.ip, action
    ]
    subprocess.run(cmd, check=False)
