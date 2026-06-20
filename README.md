# Ghost — Evasion & Payload Crafting Framework

**Automate the gap between "payload compiles" and "payload lands" — AMSI bypass generation, AV evasion encoding, process injection templates, LOLBaS command synthesis, shellcode staging, and EDR fingerprinting in a single operator-focused toolkit.**

---

## Threat Model

Ghost is built against a specific defensive landscape. Every module targets a real barrier that blocks payload delivery in mature environments:

| Defensive Layer | What It Blocks | Ghost Module | MITRE Technique |
|---|---|---|---|
| AMSI (Antimalware Scan Interface) | PowerShell payloads scanned in-memory before execution | `amsi` | T1562.001 |
| AV Signature Engine | Known shellcode patterns, static byte signatures, entropy-based heuristics | `av` | T1027 |
| EDR Userland Hooks | ntdll.dll syscall interception — CreateRemoteThread, NtAllocateVirtualMemory, etc. | `inject`, `shellcode` | T1055, T1106 |
| Process Protection (PPL/CFG) | Blocks cross-process memory writes and thread creation | `inject` | T1055 |
| Sysmon / LOLBaS Monitoring | Execution of system binaries with suspicious arguments | `lolbas` | T1218 |
| EDR Behavioral Analysis | Correlates process chains, API call sequences, and memory patterns | `edr` | T1497 |

### ATT&CK Coverage

**Tactics:** TA0005 (Defense Evasion), TA0002 (Execution)

**Techniques:**
- **T1055** — Process Injection (Classic, APC, Hollowing, DLL, Thread Hijack)
- **T1027** — Obfuscated Files or Information (XOR, AES-256-CBC, Base64, Dead Code)
- **T1218** — System Binary Proxy Execution (9 LOLBaS binaries with command synthesis)
- **T1562** — Impair Defenses (5 AMSI bypass variants with obfuscation)
- **T1497** — Virtualization/Sandbox Evasion (EDR fingerprinting and evasion mapping)
- **T1106** — Native API (Direct syscall stubs bypassing ntdll hooks)

**CWE Mapping:** CWE-693 (Protection Mechanism Failure), CWE-116 (Improper Encoding), CWE-94 (Code Injection)

---

## Why This Exists

The gap between "payload works in the lab" and "payload lands on a production endpoint" is where most red team engagements fail. You generate shellcode with msfvenom, it works on your test VM, you drop it on the target — and Defender eats it before it touches disk.

So you XOR-encode it. Works for a week until the SOC updates signatures. You switch to AES, but the entropy profile triggers heuristic detection. You try process injection, but CrowdStrike hooks every ntdll function you call. You pivot to LOLBaS, but Sysmon Event ID 1 lights up the SIEM before your command finishes.

Ghost consolidates the entire evasion workflow. Instead of maintaining separate scripts for AMSI bypass, payload encoding, injection templates, and LOLBaS lookups, you run one tool that generates everything together — with detection surface analysis for each technique, so you know what will trigger before you trigger it.

This is not a C2 framework. It does not phone home. It generates artifacts: bypass scripts, encoded payloads, injection templates, LOLBaS commands, and EDR reports. You take those artifacts and integrate them into your engagement workflow.

---

## Capabilities

### Module 1 — AMSI Bypass Generator (`amsi`)

Generates five AMSI bypass variants with detection risk ratings:

| Variant | Technique | Detection Risk |
|---|---|---|
| amsiInitFailed Patch | Set `amsiInitFailed` field to `True` via reflection | Medium |
| AmsiScanBuffer Patch | Overwrite return value to force `AMSI_RESULT_CLEAN` | High |
| Reflection Context Null | Null the `amsiContext` pointer via reflection | Medium |
| CLM Bypass (Runspace) | Escape Constrained Language Mode via custom runspace | Low |
| XOR Obfuscated One-Liner | Full bypass XOR-encoded with random key, decoded at runtime | Low |

Each bypass is output as a ready-to-use PowerShell one-liner. String obfuscation is applied to `AmsiUtils`, `amsiInitFailed`, and related identifiers using concatenation, Base64, and XOR. A test payload (EICAR-style harmless trigger) is included to verify bypass activation.

### Module 2 — AV Evasion Encoder (`av`)

Eight encoding and obfuscation techniques with decoder stub generation:

- **XOR Encoding** — single-byte and multi-byte key with random key generation
- **AES-256-CBC Encryption** — full encryption wrapper with embedded decryption stub
- **Base64 Multi-layer** — configurable double/triple encoding
- **String Reversal** — reversed hex with runtime reconstruction
- **Variable Name Randomization** — random alphanumeric identifiers to break pattern matching
- **Dead Code Insertion** — random if/else blocks, unused calculations
- **Control Flow Obfuscation** — opaque predicates, loop unrolling patterns
- **Entropy Analysis** — flags output with entropy > 7.5 (heuristic detection threshold)

Decoder stubs are generated in four languages: **PowerShell**, **Python**, **C#**, and **C**.

### Module 3 — Process Injection Templates (`inject`)

Five injection techniques with complete code templates and EDR hook analysis:

| Technique | MITRE | API Chain | Detection Surface |
|---|---|---|---|
| Classic Injection | T1055.003 | OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread | High — every EDR hooks these |
| APC Injection | T1055.004 | OpenProcess → VirtualAllocEx → WriteProcessMemory → QueueUserAPC | Medium — requires alertable thread |
| Process Hollowing | T1055.012 | CreateProcess(SUSPENDED) → NtUnmapViewOfSection → Write → Resume | High — suspended creation is a signal |
| DLL Injection | T1055.001 | OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread(LoadLibrary) | High — LoadLibrary from remote thread |
| Thread Hijacking | T1055.003 | SuspendThread → GetThreadContext → SetThreadContext(RIP) → ResumeThread | Medium — no new thread created |

Each technique outputs code templates in C and PowerShell, lists the exact API calls used, identifies which ntdll functions EDRs hook for that technique, and provides the specific Sysmon event IDs generated.

### Module 4 — LOLBaS Command Generator (`lolbas`)

Database of Windows system binaries organized by operational category:

**Execution Binaries:**

| Binary | MITRE | Sysmon Events | EDR Visibility |
|---|---|---|---|
| mshta.exe | T1218.005 | 1, 7 | High — child process spawning flagged |
| rundll32.exe | T1218.011 | 1, 7, 11 | High — script execution well-signatured |
| regsvr32.exe | T1218.010 | 1, 3 | High — Squiblydoo network connection |
| certutil.exe | T1218 | 1, 3, 11 | High — download detection primary vector |
| msiexec.exe | T1218.007 | 1, 3 | Medium — MSI from network URL |
| wmic.exe | T1218 | 1, 20 | High — process creation heavily logged |
| cmstp.exe | T1218.003 | 1, 12 | Low — less commonly monitored |
| forfiles.exe | T1218 | 1 | Low — rarely monitored directly |
| pcalua.exe | T1218 | 1 | Low — Program Compatibility Assistant |

**Download:** certutil, bitsadmin, PowerShell IWR, Start-BitsTransfer
**Compile/Execute:** csc.exe, MSBuild.exe, InstallUtil.exe
**UAC Bypass:** fodhelper.exe, eventvwr.exe, computerdefaults.exe, sdclt.exe
**Persistence:** schtasks, reg Run key, sc create, wmic startup

Each binary includes a ready-to-use command line with payload placeholders, MITRE technique mapping, Sysmon event IDs that fire, and detection notes per binary.

### Module 5 — Shellcode Staging & Transformation (`shellcode`)

- **Format Converters** — raw bytes to: hex string, C array, Python bytes, PowerShell byte array, C# byte array, Base64
- **XOR Encoder** — configurable key with null-byte avoidance (single-byte and multi-byte key search)
- **Stager Generation** — download-and-execute stubs in PowerShell and C (HTTP fetch, memory allocation, execution)
- **Meterpreter Staging URLs** — URL generation for use with msfvenom staged payloads
- **Direct Syscall Stubs** — x64/x86 assembly stubs for NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx, NtProtectVirtualMemory (bypasses ntdll userland hooks)
- **Shellcode Analysis** — null byte detection, bad character identification, entropy calculation, size estimation

### Module 6 — EDR Fingerprinting (`edr`)

Identifies 10 EDR vendors through process, service, and driver enumeration:

| Vendor | Key Processes | Detection Method |
|---|---|---|
| CrowdStrike Falcon | csfalconservice, CSFalconContainer | Process + Service + Driver (csdevicecontrol) |
| Carbon Black | CbDefense, RepMgr | Process + Driver (carbonblackk) |
| SentinelOne | SentinelAgent, SentinelServiceHost | Process + Service + Driver |
| Cylance | CylanceSvc, CylanceUI | Process + Driver (cyoptics) |
| Microsoft Defender | MsMpEng, MsSense | Process + Service (WinDefend) + Driver (WdFilter) |
| Sophos | SophosAgent, SophosClean | Process + Service |
| Symantec / Broadcom | ccSvcHst, SMC | Process + Service + Driver (symevent) |
| Palo Alto Cortex XDR | CortexXDR, Traps | Process + Service + Driver |
| Elastic Security | elastic-agent, winlogbeat | Process + Service |
| Trend Micro | TMBMSRV, NTRtScan | Process + Service + Driver (tmactmon) |

Additional capabilities:
- **DLL Hook Detection** — conceptual guide for comparing ntdll.dll .text section against clean disk copy to identify userland hooks
- **ETW Provider Enumeration** — lists active ETW providers logging security events (Security-Auditing, Sysmon, PowerShell, AMSI, Threat-Intelligence, Kernel-Process, DNS-Client)
- **Evasion Recommendations** — vendor-specific guidance generated based on detected EDR

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    ghost.py CLI                         │
│                                                         │
│   argparse ──→ EngagementContext ──→ Module Router      │
└───────────────────────┬─────────────────────────────────┘
                        │
        ┌───────────────┼───────────────┐
        │               │               │
        ▼               ▼               ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│ AMSIBypass   │ │ AVEvasion    │ │ ProcessInj.  │
│ Module       │ │ Module       │ │ Module       │
│              │ │              │ │              │
│ • 5 bypass   │ │ • XOR/AES    │ │ • Classic    │
│   variants   │ │ • Base64     │ │ • APC        │
│ • String obf │ │ • Dead code  │ │ • Hollowing  │
│ • Test payld │ │ • Entropy    │ │ • DLL inject │
│              │ │ • 4 decoders │ │ • Thread hij │
└──────────────┘ └──────────────┘ └──────────────┘
        │               │               │
        ▼               ▼               ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│ LOLBaS       │ │ Shellcode    │ │ EDRFingerpr. │
│ Module       │ │ Module       │ │ Module       │
│              │ │              │ │              │
│ • 9 exec     │ │ • 6 formats  │ │ • 10 vendors │
│ • 4 download │ │ • XOR encode │ │ • Process    │
│ • 3 compile  │ │ • Stager gen │ │ • Service    │
│ • 4 UAC byp  │ │ • Syscalls   │ │ • Driver     │
│ • 4 persist  │ │ • Analysis   │ │ • ETW / Hook │
└──────────────┘ └──────────────┘ └──────────────┘
        │               │               │
        └───────────────┼───────────────┘
                        │
                        ▼
              ┌──────────────────┐
              │ AttackResult[]   │
              │ → Rich Console   │
              │ → JSON Report    │
              │ → File Artifacts │
              └──────────────────┘
```

Each module receives an `EngagementContext` dataclass, appends `AttackResult` entries, and writes artifacts to the output directory. Modules are independent — you can run any combination without dependencies.

---

## Attack Flow

1. **Reconnaissance** — Run `edr` module to fingerprint the target's defensive stack. Identify which EDR is present, what hooks are in place, and which ETW providers are active.

2. **Bypass Selection** — Based on EDR fingerprint, run `amsi` to generate AMSI bypasses appropriate for the detection level. Use the test payload to verify bypass activation.

3. **Payload Encoding** — Run `av` to encode your payload through the evasion pipeline. Check entropy analysis — if output entropy exceeds 7.5, switch from AES to XOR or add dead code to normalize the entropy profile.

4. **Shellcode Staging** — Run `shellcode` to convert your encoded payload into the right format for your injection technique. Generate stagers if using staged delivery. Use direct syscall stubs if EDR hooks ntdll.

5. **Injection Selection** — Run `inject` to generate the injection template that matches your target's protection level. Cross-reference the EDR hook analysis — if CreateRemoteThread is hooked, use APC injection or thread hijacking instead.

6. **Execution via LOLBaS** — Run `lolbas` to generate system binary commands for execution, download, or persistence. Choose binaries with low Sysmon visibility for the initial execution, then establish persistence through a less-monitored vector.

7. **Report Generation** — Use `--output report.json` to save the full engagement results with timestamps, module status, and severity ratings.

---

## Usage

```bash
# Install dependencies
pip install -r requirements.txt

# Run all modules against a Windows x64 target
python ghost.py --modules all --target-os windows --arch x64

# AMSI bypass + AV encoding with custom listener
python ghost.py --modules amsi,av --lhost 10.10.14.5 --lport 443

# EDR fingerprint only, save JSON report
python ghost.py --modules edr --output edr_report.json

# LOLBaS + process injection with custom output directory
python ghost.py --modules lolbas,inject --output-dir ./engagement_artifacts

# Shellcode staging with 5 encoding iterations
python ghost.py --modules shellcode,av --iterations 5 --lhost 192.168.1.100

# Skip legal warning for automated pipelines
python ghost.py --modules all --yes --output full_report.json
```

### CLI Reference

| Flag | Default | Description |
|---|---|---|
| `--target-os` | `windows` | Target OS: `windows` or `linux` |
| `--arch` | `x64` | Architecture: `x86` or `x64` |
| `--modules` | `all` | Comma-separated: `amsi,av,inject,lolbas,shellcode,edr,all` |
| `--output` / `-o` | — | Save results to JSON file |
| `--yes` / `-y` | — | Skip legal warning prompt |
| `--lhost` | `0.0.0.0` | Listener host for stagers |
| `--lport` | `4444` | Listener port for stagers |
| `--iterations` | `3` | Multi-layer encoding iterations |
| `--output-dir` | `./ghost_output` | Artifact output directory |

---

## Output

```
       ________               __
      / ____/ /_  ____  _____/ /_
     / / __/ __ \/ __ \/ ___/ __/
    / /_/ / / / / /_/ (__  ) /_
    \____/_/ /_/\____/____/\__/

  Ghost Framework v1.0.0
  Evasion & Payload Crafting Framework
  MITRE ATT&CK: T1055 | T1027 | T1218 | T1562 | T1497 | T1106

  [INFO]  Target OS: windows | Arch: x64
  [INFO]  LHOST: 10.10.14.5 | LPORT: 443
  [INFO]  Output directory: ./ghost_output
  [INFO]  Selected modules: amsi, av, inject, lolbas, shellcode, edr

  ╭──────────────────────────────────────────────────────────╮
  │         Module 1 — AMSI Bypass Generator [T1562.001]     │
  ╰──────────────────────────────────────────────────────────╯
  [INFO]  Generating amsiInitFailed patch variant...
  [ OK ]  amsiInitFailed patch generated (detection risk: MEDIUM)
  [INFO]  Generating AmsiScanBuffer memory patch...
  [ OK ]  AmsiScanBuffer patch generated (detection risk: HIGH)
  [INFO]  Generating reflection-based amsiContext null...
  [ OK ]  Reflection context null generated (detection risk: MEDIUM)
  [INFO]  Generating CLM bypass via custom runspace...
  [ OK ]  CLM bypass generated (detection risk: LOW)
  [INFO]  Generating XOR-obfuscated bypass one-liner...
  [ OK ]  XOR one-liner generated (key=0x8F, detection risk: LOW)
  [INFO]  Generating AMSI test payload (EICAR-style)...
  [ OK ]  Test payload generated

  ┌──────────────────────────────────────────────────────────┐
  │                   AMSI Bypass Variants                   │
  ├──────────────────────┬────────────────┬──────────────────┤
  │ Technique            │ Detection Risk │ Target           │
  ├──────────────────────┼────────────────┼──────────────────┤
  │ amsiInitFailed Patch │    MEDIUM      │ Widely signat... │
  │ AmsiScanBuffer Patch │    HIGH        │ Modifies memo... │
  │ Reflection Ctx Null  │    MEDIUM      │ Effective on ... │
  │ CLM Bypass           │    LOW         │ Works when Ap... │
  │ XOR One-Liner        │    LOW         │ Evades static... │
  │ AMSI Test Payload    │    INFO        │ If this execu... │
  └──────────────────────┴────────────────┴──────────────────┘
  [ OK ]  All AMSI bypasses saved to ghost_output/amsi_bypasses.ps1

  ╭──────────────────────────────────────────────────────────╮
  │          Module 6 — EDR Fingerprinting [T1497]           │
  ╰──────────────────────────────────────────────────────────╯
  [INFO]  Scanning for known EDR processes...
  [CRIT]  DETECTED: Microsoft Defender — processes: MsMpEng.exe
  [INFO]  Not detected: CrowdStrike Falcon
  [INFO]  Not detected: SentinelOne
  ...
  [CRIT]  Microsoft Defender detected — evasion guidance:
          AMSI integration — bypass AMSI first. Cloud-connected
          analysis — air-gapped payloads may bypass cloud lookups.

  ╭──────────────────────────────────────────────────────────╮
  │                   Engagement Summary                     │
  ╰──────────────────────────────────────────────────────────╯
  ┌──────────────┬───────────────┬────────┬──────────┬───────┐
  │ Module       │ Action        │ Status │ Severity │ Notes │
  ├──────────────┼───────────────┼────────┼──────────┼───────┤
  │ amsi         │ gen_bypasses  │   OK   │   HIGH   │ 6 ... │
  │ av_evasion   │ encode_obf    │   OK   │   HIGH   │ 8 ... │
  │ process_inj  │ gen_templates │   OK   │   CRIT   │ 5 ... │
  │ lolbas       │ gen_commands  │   OK   │   HIGH   │ 24... │
  │ shellcode    │ stage_transf  │   OK   │   HIGH   │ 6 ... │
  │ edr_fingerpr │ fingerprint   │   OK   │   CRIT   │ 1 ... │
  └──────────────┴───────────────┴────────┴──────────┴───────┘
  [INFO]  Completed in 1.84s — 6 succeeded, 0 failed
  [INFO]  Artifacts saved to: /home/operator/ghost_output
```

---

## Legal Notice

Ghost Framework is provided strictly for authorized security testing and red team operations within large-scale enterprise environments. Users must possess explicit written authorization (Rules of Engagement) before deploying any technique generated by this tool.

Unauthorized access to computer systems is a criminal offense under the Computer Fraud and Abuse Act (18 U.S.C. Section 1030), the Computer Misuse Act 1990, and equivalent legislation in other jurisdictions. The author disclaims all liability for unauthorized or illegal use.

This tool generates technique templates and evasion artifacts. It does not establish command-and-control channels, exfiltrate data, or maintain persistence autonomously. Responsibility for lawful use rests entirely with the operator.
