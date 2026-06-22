"""Tests for CLI argument parsing."""

from ghost.cli import build_parser, MODULE_REGISTRY


def test_all_modules_registered():
    expected = {"amsi", "av", "inject", "lolbas", "shellcode", "edr"}
    assert set(MODULE_REGISTRY.keys()) == expected


def test_default_target_os():
    p = build_parser()
    args = p.parse_args(["--modules", "all"])
    assert args.target_os == "windows"


def test_arch_choices():
    p = build_parser()
    args = p.parse_args(["--modules", "all", "--arch", "x86"])
    assert args.arch == "x86"


def test_lhost_lport():
    p = build_parser()
    args = p.parse_args(["--modules", "amsi", "--lhost", "10.0.0.1", "--lport", "443"])
    assert args.lhost == "10.0.0.1"
    assert args.lport == 443


def test_iterations_default():
    p = build_parser()
    args = p.parse_args(["--modules", "av"])
    assert args.iterations == 3
