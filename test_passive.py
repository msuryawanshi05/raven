"""Self-check for the passive classifier - the --mode auto security boundary."""
from agent.tools import is_passive

WL = ["reconftw", "subfinder", "httpx", "curl", "whois", "dig", "nslookup"]


def check():
    passive = [
        ("run_reconftw", "-d example.com -p"),
        ("run_command", "subfinder -d example.com"),
        ("run_command", "httpx -silent -title"),
        ("run_command", "curl https://example.com"),
        ("run_command", "whois example.com"),
        ("run_command", "dig example.com"),
    ]
    active = [
        ("run_reconftw", "-d example.com -a"),        # active recon flag
        ("run_reconftw", "-d example.com"),           # no -p
        ("run_command", "curl -X POST https://x/api"),# write method
        ("run_command", "curl -d user=1 https://x"),  # data
        ("run_command", "httpx -fuzz /FUZZ"),         # fuzzing
        ("run_command", "nmap -sV example.com"),      # not whitelisted
        ("run_command", "sqlmap -u https://x"),       # not whitelisted
        ("run_command", ""),                          # empty
    ]
    for a, i in passive:
        assert is_passive(a, i, WL), f"should be passive: {a} {i!r}"
    for a, i in active:
        assert not is_passive(a, i, WL), f"should NOT be passive: {a} {i!r}"
    print(f"OK: {len(passive)} passive + {len(active)} active cases pass")


if __name__ == "__main__":
    check()
