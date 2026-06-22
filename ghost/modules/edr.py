"""EDR detection and fingerprinting module.

Maps to MITRE T1497 — Virtualization/Sandbox Evasion (reconnaissance).
"""

from __future__ import annotations

from datetime import datetime

from rich.table import Table
from rich import box

from ghost.logger import console, info, ok, warn, crit, section
from ghost.models import AttackResult, EngagementContext
from ghost.utils.artifacts import save_artifact
from ghost.modules.base import BaseModule


class EDRFingerprintModule(BaseModule):
    """EDR detection and fingerprinting.
    Maps to MITRE T1497 — Virtualization/Sandbox Evasion (reconnaissance).
    """

    name = "EDR Fingerprinting"

    EDR_SIGNATURES = {
        "CrowdStrike Falcon": {
            "processes": ["csfalconservice", "CSFalconContainer", "csagent", "falconhost"],
            "services": ["CSFalconService", "csagent"],
            "drivers": ["csdevicecontrol", "csboot", "csagent"],
            "evasion_notes": "Kernel-level visibility — userland unhooking insufficient. "
                            "Consider direct syscalls + sleep obfuscation + indirect syscalls."
        },
        "Carbon Black": {
            "processes": ["CbDefense", "CbDefenseSensor", "RepMgr", "repux", "cbcomms"],
            "services": ["CbDefenseSensor", "CarbonBlack"],
            "drivers": ["carbonblackk", "cbk7", "cbstream"],
            "evasion_notes": "Heavy behavioral analysis — avoid common injection patterns. "
                            "Process hollowing is well-detected. Use thread pool injection."
        },
        "SentinelOne": {
            "processes": ["SentinelAgent.exe", "SentinelServiceHost", "SentinelStaticEngine",
                         "SentinelUI"],
            "services": ["SentinelAgent", "SentinelStaticEngineScanner"],
            "drivers": ["sentinelmonitor"],
            "evasion_notes": "AI-based static analysis — polymorphic payloads recommended. "
                            "Strong userland hooks — direct syscalls needed."
        },
        "Cylance": {
            "processes": ["CylanceSvc", "CylanceUI", "CylanceProtectSetup"],
            "services": ["CylanceSvc"],
            "drivers": ["cyoptics", "cyprotectdrv"],
            "evasion_notes": "ML-based pre-execution analysis — focus on in-memory execution. "
                            "Fileless techniques are more effective."
        },
        "Microsoft Defender": {
            "processes": ["MsMpEng.exe", "MsSense.exe", "SenseIR.exe", "SenseCncProxy.exe",
                         "SecurityHealthService.exe"],
            "services": ["WinDefend", "WdNisSvc", "Sense"],
            "drivers": ["WdFilter", "WdNisDrv", "WdBoot"],
            "evasion_notes": "AMSI integration — bypass AMSI first. Cloud-connected analysis — "
                            "air-gapped payloads may bypass cloud lookups. Tamper protection "
                            "prevents service stopping."
        },
        "Sophos": {
            "processes": ["SophosAgent", "SophosClean", "SophosHealth", "sopaborern",
                         "SophosFileScanner"],
            "services": ["Sophos Agent", "Sophos AutoUpdate Service", "Sophos MCS Agent"],
            "drivers": ["sophosed", "sophosel"],
            "evasion_notes": "Intercept X has behavioral detection — avoid known injection chains. "
                            "Deep learning engine requires novel payload structures."
        },
        "Symantec / Broadcom": {
            "processes": ["ccSvcHst.exe", "SMC.exe", "SmcGui.exe", "SepMasterService"],
            "services": ["SepMasterService", "SmcService"],
            "drivers": ["symevent", "srtsp"],
            "evasion_notes": "Signature-heavy — encoding and packing are effective. "
                            "Behavioral engine is weaker than CrowdStrike/SentinelOne."
        },
        "Palo Alto Cortex XDR": {
            "processes": ["CortexXDR.exe", "Traps.exe", "cyserver.exe", "CETASvc.exe"],
            "services": ["CortexXDR", "Traps"],
            "drivers": ["tdevflt", "cyverak"],
            "evasion_notes": "Strong kernel visibility — behavioral IoC correlation. "
                            "Analytics module correlates across endpoints — isolated testing advised."
        },
        "Elastic Security": {
            "processes": ["elastic-agent", "winlogbeat", "filebeat", "elastic-endpoint"],
            "services": ["ElasticAgent", "ElasticEndpoint"],
            "drivers": [],
            "evasion_notes": "Rule-based + ML. Open detection rules — review elastic/detection-rules "
                            "on GitHub to understand coverage gaps."
        },
        "Trend Micro": {
            "processes": ["TMBMSRV.exe", "TmCCSF.exe", "NTRtScan.exe", "PccNTMon.exe",
                         "TmListen.exe"],
            "services": ["TrendMicro", "TMBMSRV", "TMBMServer"],
            "drivers": ["tmevtmgr", "tmtdi", "tmactmon"],
            "evasion_notes": "Virtual patching via IPS — check network-level blocking. "
                            "Behavioral monitoring can be evaded with staged execution."
        },
    }

    def run(self, ctx: EngagementContext) -> None:
        section("Module 6 — EDR Fingerprinting [T1497]")

        # -- Process-based Detection --
        info("Scanning for known EDR processes...")
        detected_edrs = []

        if ctx.target_os == "windows":
            try:
                import subprocess
                result = subprocess.run(
                    ["tasklist", "/FO", "CSV", "/NH"],
                    capture_output=True, text=True, timeout=10
                )
                running = result.stdout.lower()
            except Exception:
                running = ""
                warn("Could not enumerate processes — generating offline reference instead")
        else:
            running = ""
            info("Non-Windows target — generating offline EDR reference database")

        for vendor, sig in self.EDR_SIGNATURES.items():
            found_procs = [p for p in sig["processes"] if p.lower() in running]
            if found_procs:
                detected_edrs.append((vendor, found_procs))
                crit(f"DETECTED: {vendor} — processes: {', '.join(found_procs)}")
            else:
                info(f"Not detected: {vendor}")

        # -- Service-based Detection --
        info("Checking for EDR services...")
        if ctx.target_os == "windows":
            try:
                import subprocess
                result = subprocess.run(
                    ["sc", "query", "type=", "service", "state=", "all"],
                    capture_output=True, text=True, timeout=10
                )
                services = result.stdout.lower()
            except Exception:
                services = ""

            for vendor, sig in self.EDR_SIGNATURES.items():
                found_svcs = [s for s in sig["services"] if s.lower() in services]
                if found_svcs:
                    crit(f"SERVICE: {vendor} — {', '.join(found_svcs)}")

        # -- Driver-based Detection --
        info("Checking for EDR filter drivers...")
        if ctx.target_os == "windows":
            try:
                import subprocess
                result = subprocess.run(
                    ["fltMC"], capture_output=True, text=True, timeout=10
                )
                drivers = result.stdout.lower()
            except Exception:
                drivers = ""

            for vendor, sig in self.EDR_SIGNATURES.items():
                found_drvs = [d for d in sig["drivers"] if d.lower() in drivers]
                if found_drvs:
                    crit(f"DRIVER: {vendor} — {', '.join(found_drvs)}")

        # -- DLL Hook Detection Concept --
        info("Generating ntdll hook detection concept...")
        hook_detection_concept = (
            "# ntdll.dll Userland Hook Detection Concept\n"
            "# Compare .text section of in-memory ntdll against clean copy from disk\n\n"
            "# Steps:\n"
            "# 1. Read clean ntdll.dll from C:\\Windows\\System32\\ntdll.dll\n"
            "# 2. Parse PE headers to locate .text section (RVA + size)\n"
            "# 3. Get base address of loaded ntdll via GetModuleHandle\n"
            "# 4. Compare byte-by-byte: disk .text vs memory .text\n"
            "# 5. Any differences indicate hooks (JMP/CALL patches by EDR)\n"
            "# 6. To unhook: overwrite hooked bytes with clean copy from disk\n\n"
            "# Detection signatures:\n"
            "# - 0xE9 (JMP rel32) at function start = trampoline hook\n"
            "# - 0xFF 0x25 (JMP [addr]) = IAT-style redirect\n"
            "# - Modified syscall stubs (mov eax, SSN changed or removed)\n"
        )
        save_artifact(ctx, "hook_detection_concept.txt", hook_detection_concept)
        ok("Hook detection concept documented")

        # -- ETW Provider Enumeration --
        info("Documenting ETW security providers...")
        etw_providers = [
            ("Microsoft-Windows-Security-Auditing", "Security event log — logon, privilege use, object access"),
            ("Microsoft-Windows-Sysmon", "Sysmon — process create, network, registry, file events"),
            ("Microsoft-Windows-PowerShell", "PowerShell script block logging, module logging"),
            ("Microsoft-Antimalware-Scan-Interface", "AMSI scan events — content inspection"),
            ("Microsoft-Windows-Threat-Intelligence", "ETW TI — memory allocation/protection monitoring (kernel)"),
            ("Microsoft-Windows-Kernel-Process", "Kernel process creation/termination events"),
            ("Microsoft-Windows-DNS-Client", "DNS query logging"),
        ]

        table = Table(title="ETW Security Providers", box=box.ROUNDED)
        table.add_column("Provider", style="cyan")
        table.add_column("Coverage")
        for etw_name, desc in etw_providers:
            table.add_row(etw_name, desc)
        console.print(table)

        # -- EDR Reference Table --
        table = Table(title="EDR Vendor Reference", box=box.ROUNDED)
        table.add_column("Vendor", style="cyan", width=22)
        table.add_column("Key Processes", width=30)
        table.add_column("Evasion Guidance")

        for vendor, sig in self.EDR_SIGNATURES.items():
            procs = ", ".join(sig["processes"][:3])
            if len(sig["processes"]) > 3:
                procs += f" (+{len(sig['processes'])-3})"
            table.add_row(vendor, procs, sig["evasion_notes"][:70] + "...")
        console.print(table)

        # -- Evasion Recommendations --
        if detected_edrs:
            section("Evasion Recommendations")
            for vendor, procs in detected_edrs:
                crit(f"{vendor} detected — evasion guidance:")
                console.print(f"    {self.EDR_SIGNATURES[vendor]['evasion_notes']}", style="yellow")
        else:
            info("No EDR detected on local system (or running in offline mode)")

        # -- Save full report --
        report = "# EDR Fingerprint Report\n"
        report += f"# Generated: {datetime.now().isoformat()}\n"
        report += f"# Target OS: {ctx.target_os}\n\n"

        if detected_edrs:
            report += "## Detected EDR Products\n"
            for vendor, procs in detected_edrs:
                report += f"\n### {vendor}\n"
                report += f"Processes: {', '.join(procs)}\n"
                report += f"Guidance: {self.EDR_SIGNATURES[vendor]['evasion_notes']}\n"
        else:
            report += "## No EDR Detected (offline mode)\n"

        report += "\n## Full Vendor Database\n"
        for vendor, sig in self.EDR_SIGNATURES.items():
            report += f"\n### {vendor}\n"
            report += f"Processes: {', '.join(sig['processes'])}\n"
            report += f"Services: {', '.join(sig['services'])}\n"
            report += f"Drivers: {', '.join(sig['drivers']) if sig['drivers'] else 'N/A'}\n"
            report += f"Guidance: {sig['evasion_notes']}\n"

        path = save_artifact(ctx, "edr_fingerprint_report.txt", report)
        ok(f"Full EDR fingerprint report saved to {path}")

        ctx.results.append(AttackResult(
            module="edr_fingerprint", action="fingerprint_edr", status="ok",
            severity="critical",
            notes=f"Scanned {len(self.EDR_SIGNATURES)} vendors, detected {len(detected_edrs)} on local system"
        ))
