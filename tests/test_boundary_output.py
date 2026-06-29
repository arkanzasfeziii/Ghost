"""Boundary tests for ghost.output, ghost.logger, ghost.exceptions, ghost.cli."""

import tempfile

from ghost.cli import build_parser
from ghost.exceptions import DependencyError, EncodingError, GhostError, ModuleError
from ghost.logger import crit, info, ok, section, warn
from ghost.models import AttackResult, EngagementContext
from ghost.output import dump_results
from ghost.utils.artifacts import save_artifact


# ── logger ──────────────────────────────────────────────────────────────────

def test_info_empty():
    info("")


def test_ok_long():
    ok("X" * 5000)


def test_warn_special():
    warn("test <>&\"'\\n")


def test_crit_unicode():
    crit("تست فارسی")


def test_section_empty():
    section("")


# ── dump_results ────────────────────────────────────────────────────────────

def test_dump_empty():
    ctx = EngagementContext()
    dump_results(ctx)


def test_dump_with_results():
    ctx = EngagementContext()
    ctx.results = [AttackResult("amsi", "bypass", "ok", "high", "generated")]
    dump_results(ctx)


def test_dump_many_results():
    ctx = EngagementContext()
    ctx.results = [AttackResult(f"mod{i}", f"act{i}", "ok", "info", f"note{i}") for i in range(100)]
    dump_results(ctx)


def test_dump_to_file():
    ctx = EngagementContext()
    ctx.results = [AttackResult("test", "test", "ok", "info", "test")]
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        ctx.output_file = f.name
    dump_results(ctx)
    import os, json
    with open(ctx.output_file) as fh:
        data = json.load(fh)
    assert "results" in data
    os.unlink(ctx.output_file)


def test_dump_long_notes():
    ctx = EngagementContext()
    ctx.results = [AttackResult("mod", "act", "ok", "info", "N" * 10000)]
    dump_results(ctx)


# ── save_artifact ───────────────────────────────────────────────────────────

def test_save_artifact_basic():
    ctx = EngagementContext(output_dir=tempfile.mkdtemp())
    path = save_artifact(ctx, "test.txt", "hello world")
    import os
    assert os.path.exists(path)
    with open(path) as f:
        assert f.read() == "hello world"


def test_save_artifact_empty_content():
    ctx = EngagementContext(output_dir=tempfile.mkdtemp())
    path = save_artifact(ctx, "empty.txt", "")
    import os
    assert os.path.getsize(path) == 0


def test_save_artifact_large_content():
    ctx = EngagementContext(output_dir=tempfile.mkdtemp())
    path = save_artifact(ctx, "large.txt", "A" * 1_000_000)
    import os
    assert os.path.getsize(path) == 1_000_000


def test_save_artifact_unicode():
    ctx = EngagementContext(output_dir=tempfile.mkdtemp())
    path = save_artifact(ctx, "uni.txt", "日本語テスト")
    with open(path, encoding="utf-8") as f:
        assert "日本語" in f.read()


def test_save_artifact_special_filename():
    ctx = EngagementContext(output_dir=tempfile.mkdtemp())
    path = save_artifact(ctx, "test-file_v2.0.ps1", "content")
    assert path.endswith(".ps1")


# ── build_parser ────────────────────────────────────────────────────────────

def test_parser_minimal():
    p = build_parser()
    args = p.parse_args(["--modules", "all"])
    assert args.modules == "all"


def test_parser_custom_lhost():
    p = build_parser()
    args = p.parse_args(["--modules", "amsi", "--lhost", "10.10.14.5", "--lport", "443"])
    assert args.lhost == "10.10.14.5"
    assert args.lport == 443


def test_parser_iterations():
    p = build_parser()
    args = p.parse_args(["--modules", "av", "--iterations", "20"])
    assert args.iterations == 20


def test_parser_linux_x86():
    p = build_parser()
    args = p.parse_args(["--modules", "all", "--target-os", "linux", "--arch", "x86"])
    assert args.target_os == "linux"
    assert args.arch == "x86"


def test_parser_output():
    p = build_parser()
    args = p.parse_args(["--modules", "edr", "-o", "report.json"])
    assert args.output == "report.json"


# ── exceptions ──────────────────────────────────────────────────────────────

def test_ghost_error():
    e = GhostError("test")
    assert str(e) == "test"


def test_module_error_inherits():
    assert isinstance(ModuleError("x"), GhostError)


def test_encoding_error():
    assert isinstance(EncodingError("x"), GhostError)


def test_dependency_error_msg():
    e = DependencyError("pycryptodome")
    assert "pycryptodome" in str(e)
    assert e.package == "pycryptodome"


def test_dependency_error_inherits():
    assert isinstance(DependencyError("x"), GhostError)
