import argparse

from domain_guardian import run_batch, run_domain_audit


def _idna_encode(domain: str) -> str:
    """Encode an internationalized domain name (IDN) to its ASCII-compatible
    encoding (ACE/punycode) form so downstream tools (DNS queries, TLS
    handshakes, socket calls) never receive raw Unicode.

    Examples
    --------
    über.de  →  xn--ber-goa.de
    münchen.de  →  xn--mnchen-3ya.de
    already-ascii.com  →  already-ascii.com  (unchanged)
    """
    try:
        return domain.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return domain

def main():
    p = argparse.ArgumentParser(description="Domain & Website Guardian -- multi-agent audit system")
    p.add_argument("domain", nargs="?", help="domain to audit, e.g. example.com")
    p.add_argument("--batch", help="path to a text file with one domain per line")
    p.add_argument("--repeats", type=int, default=1, help="repeat each domain N times (completion-rate testing)")
    p.add_argument("--auto-approve", action="store_true", help="skip the interactive approval prompt (approve)")
    p.add_argument("--auto-deny", action="store_true", help="skip the interactive approval prompt (deny)")
    p.add_argument("--max-steps", type=int, default=12)
    p.add_argument("--max-seconds", type=float, default=25.0)
    args = p.parse_args()

    auto_decision = None
    if args.auto_approve:
        auto_decision = True
    if args.auto_deny:
        auto_decision = False

    if args.batch:
        domains = [line.strip() for line in open(args.batch) if line.strip()]
        domains = [_idna_encode(d) for d in domains]
        run_batch(domains, repeats=args.repeats, auto_decision=auto_decision if auto_decision is not None else False,
                  max_steps=args.max_steps, max_seconds=args.max_seconds)
    elif args.domain:
        domain = _idna_encode(args.domain)
        run_domain_audit(domain, auto_decision=auto_decision,
                         max_steps=args.max_steps, max_seconds=args.max_seconds, verbose=True)
    else:
        p.print_help()


if __name__ == "__main__":
    main()
