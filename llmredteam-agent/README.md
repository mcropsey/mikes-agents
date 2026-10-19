# llmredteam-agent

Part of [mikes-agents](../README.md). A **safety / guardrail eval of the lab's own LLM gateway.** It sends a
fixed battery of OWASP-LLM-Top-10-style probe prompts **through LiteLLM** to the local model and scores how each
was handled. The probes are benign, representative templates — they test whether the model + guardrail refuse
the *shape* of a bad request; they are not working attacks.

Each probe's outcome is one of:

| Outcome | Meaning |
|---|---|
| `blocked` | the LiteLLM `basic-safety-filter` guardrail refused the request (good — the filter caught it) |
| `refused` | the model itself declined (good) |
| `complied` / `partial` | the model did the undesirable thing (a **finding**) |
| `error` | transport / other |

Two keys are used on purpose: a **probe** key that is deliberately **NOT** opted out of the guardrail (so the
probe path is the real system under test — model *and* guardrail), and a **judge** key that *is* opted out (so
the judge grading the responses isn't itself filtered).

## Run

| | |
|---|---|
| Schedule | `llmredteam.timer` → Sun 06:50 America/Chicago |
| Manual / demo | `llmredteam [--no-email] [--to ADDR]` |

Uses the GPU, so run it off-hours or accept slower interactive performance during a live demo.

## LiteLLM

- `LLMREDTEAM_PROBE_KEY`, alias `llmredteam-probe` — **not** opted out of `basic-safety-filter` (system under test).
- `LLMREDTEAM_JUDGE_KEY`, alias `llmredteam-judge` — opted out (the judge must be able to read the probe text).

See [litellm/](../litellm/).

## Reports & Grafana

`/opt/labagents/data/reports/llmredteam/`, listed at `:9440/reports/#llmredteam`; metrics `mikes_llmredteam_*`
(probes, outcomes, findings, status) and report logs via [agenthub](../agenthub/) (dashboard
*Agent Lab · Agents II*).

Editing the probe set: edit `PROBES` in [`labagents/llmredteam.py`](../lab-agents-common/labagents/llmredteam.py)
and rebuild the image. Keep probes benign and eval-oriented.
