"""Command-line interface for Ghost."""

from __future__ import annotations

import argparse
import os
import textwrap

from ghost.config import COMMAND, TOOL_NAME, VERSION
from ghost.logger import crit, info
from ghost.models import AttackResult, EngagementContext
from ghost.modules import (
    AMSIBypassModule,
    AVEvasionModule,
    EDRFingerprintModule,
    LOLBaSModule,
    ProcessInjectionModule,
    ShellcodeModule,
)
from ghost.output import dump_results, print_banner, print_legal

MODULE_REGISTRY = {
    "amsi": AMSIBypassModule,
    "av": AVEvasionModule,
    "inject": ProcessInjectionModule,
    "lolbas": LOLBaSModule,
    "shellcode": ShellcodeModule,
    "edr": EDRFingerprintModule,
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=COMMAND,
        description=f"{TOOL_NAME} v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(f"""\
            examples:
              {COMMAND} --modules all --target-os windows --arch x64
              {COMMAND} --modules amsi,av --lhost 10.10.14.5 --lport 443
              {COMMAND} --modules edr --output edr_report.json
              {COMMAND} --modules lolbas,inject --output-dir ./artifacts
              {COMMAND} --modules shellcode,av --iterations 5
        """),
    )
    p.add_argument("--modules", required=True,
                   help="Comma-separated: amsi,av,inject,lolbas,shellcode,edr,all")
    p.add_argument("--target-os", choices=["windows", "linux"], default="windows")
    p.add_argument("--arch", choices=["x86", "x64"], default="x64")
    p.add_argument("--lhost", default="0.0.0.0")
    p.add_argument("--lport", type=int, default=4444)
    p.add_argument("--iterations", type=int, default=3,
                   help="Multi-layer encoding iterations")
    p.add_argument("--output", "-o", default=None, help="JSON report output")
    p.add_argument("--output-dir", default="./ghost_output")
    p.add_argument("--yes", "-y", action="store_true")
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} v{VERSION}")
    return p


def main() -> int:
    print_banner()
    args = build_parser().parse_args()

    if not print_legal(args.yes):
        print("\n  Aborted.\n")
        return 1

    ctx = EngagementContext(
        target_os=args.target_os,
        arch=args.arch,
        output_dir=args.output_dir,
        lhost=args.lhost,
        lport=args.lport,
        encoding_iterations=args.iterations,
        output_file=args.output,
    )

    os.makedirs(ctx.output_dir, exist_ok=True)
    info(f"Target OS: {ctx.target_os} | Arch: {ctx.arch}")
    info(f"LHOST: {ctx.lhost} | LPORT: {ctx.lport}")
    info(f"Output: {os.path.abspath(ctx.output_dir)}")

    requested = [m.strip().lower() for m in args.modules.split(",")]
    if "all" in requested:
        requested = list(MODULE_REGISTRY.keys())

    invalid = [m for m in requested if m not in MODULE_REGISTRY]
    if invalid:
        print(f"  Unknown module(s): {', '.join(invalid)}")
        print(f"  Available: {', '.join(MODULE_REGISTRY.keys())}")
        return 1

    info(f"Modules: {', '.join(requested)}")

    for mod_name in requested:
        mod = MODULE_REGISTRY[mod_name]()
        try:
            mod.run(ctx)
        except Exception as e:
            crit(f"Module {mod_name} failed: {e}")
            ctx.results.append(AttackResult(
                module=mod_name, action="execution",
                status="fail", severity="critical",
                notes=f"Module crashed: {e}",
            ))

    dump_results(ctx)
    return 0
