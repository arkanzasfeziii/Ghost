# Architecture

## Package Structure

```
ghost/
├── cli.py               # Argument parsing, module dispatch
├── config.py            # Tool metadata, legal warning
├── models.py            # AttackResult, EngagementContext
├── logger.py            # Rich-based colored output
├── output.py            # Banner, results table, JSON export
├── exceptions.py        # Typed exception hierarchy
│
├── modules/             # One file per evasion technique
│   ├── base.py          # BaseModule ABC
│   ├── amsi.py          # AMSI bypass generator (5 variants)
│   ├── av_evasion.py    # AV evasion encoder (XOR, AES, dead code)
│   ├── injection.py     # Process injection templates (5 techniques)
│   ├── lolbas.py        # LOLBaS command generator
│   ├── shellcode.py     # Shellcode staging & transformation
│   └── edr.py           # EDR fingerprinting (10 vendors)
│
├── utils/
│   ├── crypto.py        # XOR, entropy, random variables
│   └── artifacts.py     # Write files to output directory
│
└── data/                # Static data
```

## Data Flow

```
CLI → EngagementContext (target_os, arch, lhost, lport)
         │
         ▼
    Module.run(ctx)
         ├── Generate evasion artifacts
         ├── save_artifact(ctx, filename, content)
         └── ctx.results.append(AttackResult)
         │
         ▼
    output.dump_results(ctx) → Rich table + JSON
```

## Adding a New Module

1. Create `ghost/modules/your_technique.py` extending `BaseModule`
2. Implement `run(self, ctx: EngagementContext) -> None`
3. Register in `ghost/cli.py: MODULE_REGISTRY`
4. Update `ghost/modules/__init__.py`
