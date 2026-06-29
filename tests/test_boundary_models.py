"""Boundary tests for ghost.models dataclasses."""

from ghost.models import AttackResult, EngagementContext


# ── AttackResult ────────────────────────────────────────────────────────────

def test_result_empty_fields():
    r = AttackResult(module="", action="", status="", severity="", notes="")
    assert r.timestamp


def test_result_long_notes():
    r = AttackResult(module="av", action="encode", status="ok", severity="high", notes="N" * 50000)
    assert len(r.notes) == 50000


def test_result_unicode():
    r = AttackResult(module="تست", action="عمل", status="ok", severity="info", notes="یادداشت")
    assert r.module == "تست"


def test_result_special_chars():
    r = AttackResult(module="<script>", action="'; DROP TABLE", status="ok", severity="info", notes="")
    assert "<script>" in r.module


def test_result_none_equivalent():
    r = AttackResult(module="test", action="test", status="ok", severity="info", notes="")
    assert r.notes == ""


# ── EngagementContext ───────────────────────────────────────────────────────

def test_ctx_defaults():
    ctx = EngagementContext()
    assert ctx.target_os == "windows"
    assert ctx.arch == "x64"
    assert ctx.lport == 4444
    assert ctx.encoding_iterations == 3


def test_ctx_linux_x86():
    ctx = EngagementContext(target_os="linux", arch="x86")
    assert ctx.target_os == "linux"


def test_ctx_zero_port():
    ctx = EngagementContext(lport=0)
    assert ctx.lport == 0


def test_ctx_max_port():
    ctx = EngagementContext(lport=65535)
    assert ctx.lport == 65535


def test_ctx_empty_lhost():
    ctx = EngagementContext(lhost="")
    assert ctx.lhost == ""


def test_ctx_long_output_dir():
    ctx = EngagementContext(output_dir="A" * 500)
    assert len(ctx.output_dir) == 500


def test_ctx_negative_iterations():
    ctx = EngagementContext(encoding_iterations=-1)
    assert ctx.encoding_iterations == -1


def test_ctx_results_list():
    ctx = EngagementContext()
    assert ctx.results == []
    ctx.results.append(AttackResult("x", "y", "ok", "info", "z"))
    assert len(ctx.results) == 1


def test_ctx_results_empty():
    ctx = EngagementContext()
    assert ctx.output_file is None


def test_ctx_ipv6_lhost():
    ctx = EngagementContext(lhost="::1")
    assert ctx.lhost == "::1"
