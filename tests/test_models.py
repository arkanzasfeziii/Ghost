"""Tests for data models."""

from ghost.models import AttackResult, EngagementContext


def test_attack_result_fields():
    r = AttackResult(module="amsi", action="gen", status="ok",
                     severity="high", notes="test")
    assert r.module == "amsi"
    assert r.status == "ok"
    assert r.timestamp


def test_engagement_context_defaults():
    ctx = EngagementContext()
    assert ctx.target_os == "windows"
    assert ctx.arch == "x64"
    assert ctx.lport == 4444
    assert ctx.encoding_iterations == 3
    assert ctx.results == []


def test_engagement_context_custom():
    ctx = EngagementContext(target_os="linux", arch="x86", lport=443)
    assert ctx.target_os == "linux"
    assert ctx.lport == 443
