"""Boundary tests for all Ghost modules — ensures no crash on edge inputs."""

import os
import tempfile

from ghost.models import EngagementContext
from ghost.modules.amsi import AMSIBypassModule
from ghost.modules.av_evasion import AVEvasionModule
from ghost.modules.injection import ProcessInjectionModule
from ghost.modules.lolbas import LOLBaSModule
from ghost.modules.shellcode import ShellcodeModule
from ghost.modules.edr import EDRFingerprintModule


def _ctx(**kw) -> EngagementContext:
    d = tempfile.mkdtemp()
    defaults = dict(target_os="windows", arch="x64", output_dir=d,
                    lhost="0.0.0.0", lport=4444, encoding_iterations=1)
    defaults.update(kw)
    return EngagementContext(**defaults)


# ── AMSIBypassModule ───────────────────────────────────────────────────────

def test_amsi_run_default():
    ctx = _ctx()
    AMSIBypassModule().run(ctx)
    assert len(ctx.results) > 0


def test_amsi_run_linux_target():
    ctx = _ctx(target_os="linux")
    AMSIBypassModule().run(ctx)
    assert isinstance(ctx.results, list)


def test_amsi_run_x86_arch():
    ctx = _ctx(arch="x86")
    AMSIBypassModule().run(ctx)
    assert isinstance(ctx.results, list)


def test_amsi_obfuscate_empty():
    result = AMSIBypassModule._obfuscate_string("")
    assert isinstance(result, str)


def test_amsi_obfuscate_special_chars():
    result = AMSIBypassModule._obfuscate_string("AmsiUtils<>&\"'")
    assert isinstance(result, str)


# ── AVEvasionModule ────────────────────────────────────────────────────────

def test_av_run_default():
    ctx = _ctx()
    AVEvasionModule().run(ctx)
    assert len(ctx.results) > 0


def test_av_run_many_iterations():
    ctx = _ctx(encoding_iterations=10)
    AVEvasionModule().run(ctx)
    assert isinstance(ctx.results, list)


def test_av_run_zero_iterations():
    ctx = _ctx(encoding_iterations=0)
    AVEvasionModule().run(ctx)
    assert isinstance(ctx.results, list)


def test_av_gen_dead_code_zero():
    result = AVEvasionModule._generate_dead_code(0)
    assert result == []


def test_av_gen_dead_code_large():
    result = AVEvasionModule._generate_dead_code(100)
    assert len(result) == 100


def test_av_gen_opaque_predicates_zero():
    result = AVEvasionModule._generate_opaque_predicates(0)
    assert result == []


def test_av_gen_opaque_predicates():
    result = AVEvasionModule._generate_opaque_predicates(5)
    assert len(result) == 5


def test_av_xor_decoder_ps():
    result = AVEvasionModule._gen_xor_decoder_ps(b"\xaa")
    assert "xor" in result.lower() or "$" in result


def test_av_xor_decoder_c():
    result = AVEvasionModule._gen_xor_decoder_c(b"\xbb")
    assert isinstance(result, str)


def test_av_xor_decoder_empty_key():
    result = AVEvasionModule._gen_xor_decoder_ps(b"")
    assert isinstance(result, str)


# ── ProcessInjectionModule ─────────────────────────────────────────────────

def test_injection_run_default():
    ctx = _ctx()
    ProcessInjectionModule().run(ctx)
    assert len(ctx.results) > 0


def test_injection_run_x86():
    ctx = _ctx(arch="x86")
    ProcessInjectionModule().run(ctx)
    assert isinstance(ctx.results, list)


def test_injection_classic_c():
    ctx = _ctx()
    result = ProcessInjectionModule._classic_inject_c(ctx)
    assert "OpenProcess" in result or "VirtualAlloc" in result


def test_injection_classic_ps():
    ctx = _ctx()
    result = ProcessInjectionModule._classic_inject_ps(ctx)
    assert isinstance(result, str)


def test_injection_apc_c():
    ctx = _ctx()
    result = ProcessInjectionModule._apc_inject_c(ctx)
    assert isinstance(result, str)


# ── LOLBaSModule ───────────────────────────────────────────────────────────

def test_lolbas_run_default():
    ctx = _ctx()
    LOLBaSModule().run(ctx)
    assert len(ctx.results) > 0


def test_lolbas_run_linux():
    ctx = _ctx(target_os="linux")
    LOLBaSModule().run(ctx)
    assert isinstance(ctx.results, list)


def test_lolbas_run_x86():
    ctx = _ctx(arch="x86")
    LOLBaSModule().run(ctx)
    assert isinstance(ctx.results, list)


def test_lolbas_run_custom_lhost():
    ctx = _ctx(lhost="10.10.14.5", lport=443)
    LOLBaSModule().run(ctx)
    assert isinstance(ctx.results, list)


def test_lolbas_run_zero_port():
    ctx = _ctx(lport=0)
    LOLBaSModule().run(ctx)
    assert isinstance(ctx.results, list)


# ── ShellcodeModule ────────────────────────────────────────────────────────

def test_shellcode_run_default():
    ctx = _ctx()
    ShellcodeModule().run(ctx)
    assert len(ctx.results) > 0


def test_shellcode_run_x86():
    ctx = _ctx(arch="x86")
    ShellcodeModule().run(ctx)
    assert isinstance(ctx.results, list)


def test_shellcode_find_safe_xor_key():
    key = ShellcodeModule._find_safe_xor_key(b"\x00\x01\x02\x03")
    assert 1 <= key <= 255


def test_shellcode_find_safe_xor_key_all_same():
    key = ShellcodeModule._find_safe_xor_key(b"\xaa" * 100)
    assert isinstance(key, int)


def test_shellcode_find_bad_chars():
    result = ShellcodeModule._find_bad_chars(b"\x00\x0a\x0d\x41\x42")
    assert isinstance(result, list)


def test_shellcode_find_bad_chars_clean():
    result = ShellcodeModule._find_bad_chars(b"\x41\x42\x43")
    assert isinstance(result, list)


def test_shellcode_stager_ps():
    ctx = _ctx(lhost="10.0.0.1", lport=443)
    result = ShellcodeModule._gen_stager_ps(ctx)
    assert "10.0.0.1" in result


def test_shellcode_stager_c():
    ctx = _ctx(lhost="10.0.0.1", lport=443)
    result = ShellcodeModule._gen_stager_c(ctx)
    assert "10.0.0.1" in result


def test_shellcode_syscall_stubs_x64():
    ctx = _ctx(arch="x64")
    result = ShellcodeModule._gen_syscall_stubs(ctx)
    assert isinstance(result, str)


def test_shellcode_syscall_stubs_x86():
    ctx = _ctx(arch="x86")
    result = ShellcodeModule._gen_syscall_stubs(ctx)
    assert isinstance(result, str)


# ── EDRFingerprintModule ───────────────────────────────────────────────────

def test_edr_run_default():
    ctx = _ctx()
    EDRFingerprintModule().run(ctx)
    assert len(ctx.results) > 0


def test_edr_run_linux():
    ctx = _ctx(target_os="linux")
    EDRFingerprintModule().run(ctx)
    assert isinstance(ctx.results, list)


def test_edr_run_x86():
    ctx = _ctx(arch="x86")
    EDRFingerprintModule().run(ctx)
    assert isinstance(ctx.results, list)


def test_edr_run_custom_output():
    ctx = _ctx()
    EDRFingerprintModule().run(ctx)
    assert any("edr" in r.module.lower() or "EDR" in r.module for r in ctx.results)


def test_edr_run_twice():
    ctx = _ctx()
    EDRFingerprintModule().run(ctx)
    count1 = len(ctx.results)
    EDRFingerprintModule().run(ctx)
    assert len(ctx.results) > count1
