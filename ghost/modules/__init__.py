"""Evasion and payload crafting modules."""

from ghost.modules.amsi import AMSIBypassModule
from ghost.modules.av_evasion import AVEvasionModule
from ghost.modules.injection import ProcessInjectionModule
from ghost.modules.lolbas import LOLBaSModule
from ghost.modules.shellcode import ShellcodeModule
from ghost.modules.edr import EDRFingerprintModule

__all__ = [
    "AMSIBypassModule",
    "AVEvasionModule",
    "ProcessInjectionModule",
    "LOLBaSModule",
    "ShellcodeModule",
    "EDRFingerprintModule",
]
