# Exact next local-model proposal — not approved or executed

Use the already installed llama.cpp **0.4.0**, build **10809**, commit
**5266f24da**, ARM64 CLI. Its current local help confirms the flags below.
No model server, Python stack, LM Studio repair, subscription or paid API is
needed for this proposal. Model performance and load compatibility are untested.

Proposed first candidate: official **Qwen2.5-Coder-7B-Instruct Q4_K_M GGUF**.
This is a conservative qualification candidate, not a claim of best available
model quality. The [pinned model card](https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct-GGUF/blob/13fb94bfda8c8cf22497dc57b78f391a9acb426a/README.md)
declares Apache-2.0. The official pinned API metadata was rechecked on 2026-10-18:

- Revision: `13fb94bfda8c8cf22497dc57b78f391a9acb426a`
- File: `qwen2.5-coder-7b-instruct-q4_k_m.gguf`
- Size: **4,683,073,536 bytes (4.36 GiB)**
- SHA-256: `509287f78cb4d4cf6b3843734733b914b2c158e43e22a7f4bf5e963800894d3c`
- Exact URL and metadata receipt: `evidence/next-model-proposal.json`

At 23:11:31 UTC the host had **121.05 GiB free pages**, **56.27 GiB inactive
pages**, no compression/swap, and **349.6 GiB available disk**. These are separate
measures, not reserved capacity. The task used about **1.80 GiB** of private
storage. The model alone would push total storage beyond the existing **5 GiB**
analyzer approval: approve an **additional 6 GiB disk envelope** before download.
Do not delete existing tools, models or another workload to fit it.

Download one file to a task-local partial path, verify its size/hash, then rename
within the same directory to avoid a duplicate cache copy. No repository-wide
download and no automatic alternate quantization/model fallback.

Proposed single supervised qualification command, after approval:

```sh
llama-cli --offline --model "$APPROVED_GGUF" --device none --n-gpu-layers 0 \
  --threads 4 --threads-batch 4 --ctx-size 4096 --n-predict 2048 \
  --seed 1 --temp 0 --single-turn --no-warmup --file "$SYNTHETIC_PROMPT"
```

The wrapper must use the verified executable path, explicit arguments and a
clean child environment, redirect outputs locally, impose **120 seconds**,
monitor the owned process family and stop above **8 GiB RSS**. Recheck headroom
immediately before starting. No GPU offload, network access, tool execution,
listener, shell-profile edit or shared-server changes. A timeout or budget
overrun is a failed qualification; do not silently enlarge the budget.

First prompt: only our original fixture, asking for widths, signedness, stack
convention evidence, invalid cases and uncertainties. Grade against the known
source and 14 explicit cases plus the 2,880-combination comparison. Require an
independent discriminating test and rejection of unsupported ABI/type claims.
Record model/file hash, runtime, prompt hash, settings, elapsed time, peak RSS,
complete local output and the score. Only a later reviewed local-only packet may
contain retail pseudocode; a fluent answer is not a qualification or recovery.

The concrete reviewable input and scoring requirements are saved as
`qualification/local-model-prompt.txt` and `qualification/local-model-rubric.json`.
The proposal receipt records their hashes. No prompt has been sent to a local
model, and no retail context belongs in this first qualification.

**Pending decision:** authorize exactly this download, the additional 6 GiB
storage envelope and one bounded synthetic run. Until then, analyzer-only static
discovery and cloud work on original/public material continue independently.
