# rea-toolkit

Point REA at any URL. Stdlib-only Python.

    pip install -e .
    rea-toolkit analyze https://example.com/app.js      # web: endpoints, URLs, source maps, secret patterns
    rea-toolkit analyze https://example.com/tool.bin    # binary: saved non-executable, triaged, REA config emitted
    rea-toolkit proxy -- rea-server                      # MCP proxy exposing only the 10-tool allowlist
    rea-toolkit allowlist                                # show/override groups (--allowlist custom.json)

- **Routing:** content is sniffed (ELF/PE/Mach-O/wasm vs HTML/text), not trusted from the extension.
- **Allowlist:** session, procedures, strings, xrefs (10 tools). The proxy filters `tools/list` and rejects other `tools/call`s. Names are regexes, so adjust them to your REA build.
- **Safety:** http(s) only, private/loopback hosts refused (including after redirects) unless `--allow-private`, 200 MB cap, nothing is executed.

Inspired by a community experiment (32K local model, 3/3 on one small binary); not an official REA project.

## Prompts

`rea-toolkit prompts` lists a few general-purpose investigation prompts adapted from
[REA-Prompts](https://github.com/JoasASantos/REA-Prompts) (MIT, (c) 2025 Joas Antonio dos Santos),
for example `rea-toolkit prompts trace --set TARGET=./app --set FEATURE=export`.
They are short enough for a 32K model. The rest of that pack is not included.
