# Input and publication provenance

The user explicitly authorized analysis/recovery of their owned Bully:
Scholarship Edition PC copy and creation of this separate public repository.
The actual Steam installation was located locally under CrossOver. Its app
manifest and exact executable hash were recorded without reading account data.
This is user-provided ownership authorization plus installation evidence, not
independent certification of licensing or a grant to redistribute retail content.

The installation was read-only. No original executable, asset, save, patch,
account, security setting or unrelated project was changed. Private outputs are
under `local-private/`; no retail file was staged. The exact source path remains
in the private provenance record rather than public documentation.

Public original files: PE metadata reader; synthetic PE fixtures; invented C
handle/ABI fixture; tests and qualification runner; exact-build entry audit
driver; bounded import-table mapper; independently written graph/dependency
queries, synthetic graph fixtures and validation tests; documentation and evidence schemas. These were written for this project.
No bully-re implementation, generated skeleton or proprietary decompiler text
was copied or adapted. No original source recovery claim is made.

## Research sources

- User-requested [decompilation skill at 97eba9c](https://github.com/oh-ashen-one/decompiling-games-skill/tree/97eba9c15d7cbb1b863c4e3fc1962f70bec2c35f).
  Verified repository default branch `research-skill`; read the pinned skill,
  decision guide, Bully, local/cloud and validation references. Method reference;
  no code copied.
- Official [Ghidra 12.1.4 release](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build)
  and pinned setup/native-build documentation: approved task-local installation
  and native build completed. No tool archive/source is tracked publicly.
- Official [REA release source](https://github.com/morluto/rea/tree/27dc42d10249f0410904a75c0997842eb03b931c),
  MIT, corresponding to installed npm 6.7.0; task-local CLI only. See analyzer receipts.
- Official Qwen [7B](https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct-GGUF)
  and [14B](https://huggingface.co/Qwen/Qwen2.5-Coder-14B-Instruct-GGUF) model cards
  and metadata: exact optional download proposals only; no weights downloaded.
- [Microsoft PE/COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).
  Public format reference for independently written metadata reader.
- [LiquidSnake0/bully-re at dce485b](https://github.com/LiquidSnake0/bully-re/tree/dce485bf29117edca4d04b802a169f0a909da432).
  GPL-3.0 research lead as documented in the pinned skill. Its addresses,
  inferred layouts and progress numbers are not independently reproduced here.
  Any future code reuse requires per-file license review and compatible notices.
- [BullyRecomp at 856b4cd](https://github.com/coole42-pixel/BullyRecomp/tree/856b4cd98fb591a67b7a312c6c6b6b90da12a66e).
  Different Xbox 360 target, referenced to avoid cross-platform conflation.
- [Separate bully-remake project](https://github.com/oh-ashen-one/bully-remake/tree/92163805ea0d49596138330da758344f227d8b7f).
  Existing importer/remake research context only; no files or processes modified.

Shared operating rules were verified against their current published commit
`737736129b771e6e6b8cb168e00406e407dc18fd` before repository creation. Before the
first push, the newly published `e282a0f93617e5ac1c7ccd9f453ddaf1d2518ffc` and its
diff were verified: the new mandatory decompilation route uses the unchanged
skill pin above. The installed catalog resolves that same exact skill revision.

## Publication review

Review all staged paths and full text, then inspect Git history. Allow only
original/compatible source, synthetic fixtures, non-sensitive metadata and
documentation. Reject binary game payloads, generated game code, raw analysis,
databases, private local paths, secrets, saves, model weights and toolchain files.
No automatic whole-directory staging. An ignore rule is not proof of safe content.
