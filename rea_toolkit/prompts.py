"""Investigation prompts adapted from REA-Prompts (MIT, (c) 2025 Joas Antonio dos Santos):
https://github.com/JoasASantos/REA-Prompts

Only the general-purpose ones are included. Each is short enough for a 32K window.
Fill <PLACEHOLDERS> with --set KEY=VALUE.
"""
import re

EVIDENCE = ("For every conclusion give file, function or address as evidence, and separate "
            "confirmed facts, inferences and unknowns. Static analysis first; do not execute the target.")

PROMPTS = {
    "map": "Use REA to give me a map of <TARGET>: its main parts, entry points and the three "
           "features worth investigating first. Keep it short and point to evidence for each claim.",
    "understand": "Analyze <TARGET> with REA. Identify format, architecture, runtime, libraries, "
                  "relevant strings and possible entry points. Map the main components and explain "
                  "their responsibilities with evidence. State which analysis engine is available "
                  "and its limitations. Start with static analysis.",
    "trace": "Use REA to investigate how <FEATURE> works in <TARGET>. Identify the entry point, the "
             "functions involved, the data flow, the dependencies and the observable effects. "
             "Do not execute the application in this step.",
    "function": "Use REA on <TARGET>. Pick the function that handles <FEATURE> and produce: "
                "decompiled pseudocode, its callers and callees, the data structures it reads or "
                "writes, and every string/global it touches. Annotate each finding with the "
                "address range that proves it.",
    "triage": "Use REA on <TARGET>. Produce a triage map: file format and architecture, section "
              "layout, linked libraries and imports grouped by capability, interesting strings "
              "with their addresses, and the top candidate entry points for <FEATURE>. Flag any "
              "signs of packing or obfuscation.",
    "format": "Use REA on <TARGET> to work out how it reads and writes <FILETYPE>. Describe the "
              "structure field by field, show where each field is parsed, and write a small reader "
              "that prints a sample file.",
    "resume": "Review the evidence and notes of this investigation. List what has not been "
              "demonstrated yet, prioritize the next analyses by how much they reduce uncertainty, "
              "and update INVESTIGATION.md with findings, evidence, discarded hypotheses and next steps.",
}


def render(name, values):
    text = PROMPTS[name] + " " + EVIDENCE
    text = re.sub(r"<([A-Z]+)>", lambda m: values.get(m.group(1), m.group(0)), text)
    return text
