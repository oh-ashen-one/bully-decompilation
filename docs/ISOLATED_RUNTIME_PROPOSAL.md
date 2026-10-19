# Concrete isolated baseline proposal — approval pending

Read-only inspection found the existing **CrossOver 26.3** application at
`~/Applications/CrossOver.app`, bundle build **26.3.0.39832**, identifier
`com.codeweavers.CrossOver`. This corrects the previous unresolved application
path. The existing Steam bottle records that same build, `win64`, and template
`win10_64`. No CrossOver, Wine, installer or game process was launched.

The installed launcher is
`~/Applications/CrossOver.app/Contents/SharedSupport/CrossOver/bin/wine`;
the adjacent `cxbottle` manages bottles. Source inspection confirms explicit
`--bottle` selection and `CX_BOTTLE_PATH` support, including an absolute private
bottle path. The native Wine loader/wineserver are x86_64; Rosetta runtime files
are present. Rosetta execution and this game's compatibility have not been tested.
An unrestricted `codesign --verify --deep --strict` check passed. The same check
inside the restricted execution context failed; retain that discrepancy without
claiming the application is damaged or changing its signature/security settings.

CodeWeavers lists release 26.3.0 and describes the 26 series as Wine 11 based.
Its current compatibility table includes macOS 27, but the retrieved text omitted
the support icons, so this inspection does not certify the exact 26.3/macOS
27.0.1/title combination. A baseline attempt is a compatibility test, not a
guarantee. [Vendor release history](https://www.codeweavers.com/crossover/changelog),
[platform requirements](https://www.codeweavers.com/crossover).

## Proposed approval choice A: fresh environment and one menu observation

Approve creation of one task-owned Windows 10 64-bit bottle, one ordinary copy
of the owned game directory, normal official launcher/dependency setup, and
**one uninstrumented startup/menu observation of at most 120 seconds**, followed
by **up to 60 seconds of shutdown grace** (up to 180 seconds from game creation
to forced task shutdown, not a 120-second process-lifetime guarantee). Reserve
**16 GiB additional disk**, **2 GiB maximum new downloads**, **8 GiB aggregate
process RSS**, and one renderer slot. No purchase, subscription, model download,
existing-bottle modification, debugger attachment or binary patch is included.

The concrete destination would be `local-private/runtime-baseline-v1/`, with
separate `bottles/bully-reference-v1`, `fresh-user`, `logs`, and `receipts`
directories. This is additional to the existing 5 GiB analyzer budget (21 GiB combined ceiling). The path
does not exist and nothing has been staged there. Refuse an existing destination.
These clarified time/accounting terms remain approval-pending. If an owner reply
approves a strict 120-second lifetime or a narrower disk scope, surface the
difference before proceeding; do not infer an expanded allowance.

### Isolation and input preparation

1. Create a fresh `win10_64` bottle using the installed `cxbottle`, selecting its
   absolute path on every command and a process-local `CX_BOTTLE_PATH` containing
   only the task bottle parent. Do not select a new global default bottle or
   change CrossOver's shared preferences. No terminal window or Ghostty control.
2. Before Steam, redistributables or Bully run, stop the fresh bottle's setup
   processes and replace only its host-linked user folders with fresh directories.
   Set its Documents/shell-folder mapping to its own C: user Documents, and map
   Y: and Z: only within the task environment. Remove its generated mappings to
   production home, root and external drives. Verify canonical destinations,
   registry shell-folder values and a harmless marker inside the fresh Documents
   directory. Recheck mappings after any bottle update and immediately before
   game launch. App-bundle runtime references may remain read-only dependencies.
3. Copy only the game directory into the new bottle, without hardlinks or symlinks
   back to the source. Verify the copy against the exact target SHA-256 and a
   private full file manifest. Never copy the existing bottle's registry, user
   directory, Steam authentication/configuration, cloud-save metadata or saves.
   The old manifest's account fields are not needed or copied.
4. Install a fresh [official Windows Steam client](https://store.steampowered.com/about/) in the new bottle and let the
   owner authenticate there. Let Steam recognize the copied game. Do not run
   verification/repair against the production installation. If Steam updates the
   copied executable away from the approved hash, stop; do not silently retarget,
   defeat an update requirement, or restore bytes to evade launcher checks.
5. The owned directory includes `DirectX/DXSETUP.exe` (528,392 bytes) and
   `VCRedist/vcredist_x86.exe` (2,723,264 bytes); its install recipe names both.
   Approve their normal installation only into the fresh bottle after owner EULA
   steps. The existing bottle has i386 d3dx9_38, vcomp and XInput1_3 DLLs, but their
   presence is not permission to transplant runtime DLLs or licensing state.

The production bottle has a Documents link into the host home and host-access
drive mappings. Thus a whole-bottle clone would preserve unsafe save destinations
and account state. A fresh bottle with checked mappings protects expected save
paths; **a Wine bottle is not an OS security sandbox**. Stronger isolation would
require a separately approved OS user or VM and is outside this choice.

### Owner launch prerequisites

- Confirm a valid existing CrossOver entitlement or usable trial through its
  normal UI; no license files, keys or purchase flow are inspected by this task.
- Sign in to the owned Steam account in the new client, perform Steam Guard if
  requested, and handle Rockstar account authorization/linking and EULAs. The
  current Steam listing explicitly states a Rockstar account and third-party
  EULA requirement. No new account, payment or bypass is assumed.
  [Official game listing](https://store.steampowered.com/app/12200/Bully_Scholarship_Edition/).
- Before first game launch, inspect title-specific synchronization controls in
  this fresh client. The store page does not advertise Steam Cloud, but that is
  not proof that no launcher can synchronize saves. The owner must decline save
  import or permit disabling synchronization for this title/test context only.
  No global Steam/cloud setting is changed. If safe title-specific isolation
  cannot be established, stop before launching.
- Be present for setup dialogs and the observation. Pause at any unexpected
  account, installer, firewall or OS permission prompt; do not run this unattended.
  Confirm an available renderer slot under the shared two-engine ceiling without
  stopping dragon, Pocket Planet, another game/editor, or any unrelated workload.

The required new client/dependency setup is not currently authorized. CrossOver
itself is installed; no new CrossOver package or paid runtime is presently needed.
A Rockstar launcher prompt, if this build requires one, is a separate concrete
dependency to identify and approve before installation. No such package is
assumed installed or silently added to this approval.

### Size and bounded process plan

| Item | Measured or proposed amount |
|---|---:|
| Owned game, 3,836 regular files / no symlinks | 5,329,415,078 bytes (4.96 GiB) |
| Existing whole bottle, metadata-only count / 12 symlinks not followed | 9,540,374,360 bytes (8.89 GiB) |
| Whole-bottle clone | Not proposed |
| Expected fresh game + Steam + prefix/dependencies | Approximately 8–12 GiB; estimate, not measured |
| Additional total write-growth ceiling, task directory plus attributed native outputs | 16 GiB |
| New download ceiling; stop before a game redownload | 2 GiB |
| Available disk at inspection | 373,145,600,000 bytes (347.52 GiB) |

Do not rely on APFS copy-on-write savings to meet the ceiling. Steam's changing
client size and temporary installer expansion make the estimate uncertain. Count
new downloaded payload using installer-reported totals and task download files;
pause if the amount cannot be bounded. This is not a system-wide network cap.

The 16 GiB ceiling also includes this task's native CrossOver cache/temp files,
installer downloads, launcher caches, generated app integration and receipts
outside the bottle. Before launch, inventory and baseline these destinations
during synthetic setup, use a task-specific TMPDIR where supported, and measure
the sum of attributable growth plus the task tree. Suppress only this bottle's
optional menu/association integration; do not change global CrossOver settings.
Do not assume all writes are inside WINEPREFIX or delete a shared cache. If native
writes cannot be identified/accounted for without inspecting unrelated private
contents, the environment is not ready and the game remains unlaunched. The same
ceiling applies; this clarification adds no disk allowance.

Before any real run, qualify a task-owned watchdog on original synthetic child
processes, including reparenting, over-limit, stalled-sampler and shutdown cases.
Do not launch the game until those checks and native-write accounting succeed.
Track launcher descendants by PID plus creation time and fresh-bottle
identity; Wine helpers can reparent, so lineage alone is insufficient. Poll at
0.5-second target intervals with a **1.0-second maximum permitted gap** between
successful process/memory samples. A detected larger gap aborts the run rather
than claiming continuous coverage. Stop this task's run if aggregate RSS exceeds
8 GiB, total attributed write growth reaches 16 GiB, or ownership cannot be
established. These are monitoring
stop thresholds, not kernel-enforced reservations. No hard CPU quota is claimed;
start the launcher at lowered scheduling priority and stop if the owned family
exceeds 400% CPU for ten consecutive seconds. Do not change system scheduling.

Bound active installation work to 20 minutes, pausing automation for owner login
or agreement decisions. The observation timer starts at game process creation;
at 120 seconds stop observations and begin shutdown. The separate 60-second grace
is for exit/sign-out/termination, not further observation or another attempt.
Monitor ownership/memory/disk throughout the grace; total game lifetime must not
exceed 180 seconds. Allow one attempt; a crash, timeout, hash change or unresolved
permission ends it. Use the fresh bottle's default graphics backend, record it,
and do not install graphics overrides or edit the executable. Request 1280×720
windowed only if offered by the game's normal menu; otherwise record the actual
mode and stop if it disrupts the desktop. Do not load/start a game or create a
progression save; a startup configuration write is permitted only in the fresh
environment.

### Exact observation and cleanup

Record only: input executable hash, runtime/build/OS, task-owned PID identities,
elapsed time, peak sampled aggregate RSS, exit status, whether startup reached the menu,
observed graphics mode, fixed input sequence (launch, dismiss ordinary splash if
needed, menu idle, normal Quit), and created/changed paths inside the task root.
No credentials, typed account data, screenshots of login UI, save contents or
memory dumps. Limit diagnostic logs to 10 MiB; overflow stops capture/run. At
most one game-window-only menu image may remain private if approved; no whole
desktop capture or public game assets.

Try the game's normal Quit first; then have the owner sign out of the fresh Steam
and any authorized launcher **before** shutting down their processes. Complete
that sequence within the same 60-second grace. If normal exit fails, signal only
verified task-owned processes and use the remaining grace for termination; force
termination at its deadline only for owned processes still stuck. A stalled
sign-out is recorded as unconfirmed, never falsely reported successful. Never
invoke a global Wine/Steam kill command or touch the production bottle. Verify
zero surviving task processes and unchanged source executable hash, then save
the minimized receipt. Remove only the newly created disposable environment
after the receipt is retained; do not archive authentication state. Preserve
existing analysis evidence and all production files.

This observation can establish whether the exact build reaches a menu under
this runtime. It cannot identify candidate 2's return value or resolve the
computed transfer by itself. No function oracle or decompilation completion is
earned by a menu screenshot.

## Choice B: keep execution deferred

Continue static/public-reference work with the existing tools. A source-assisted
7B pilot remains optional, unapproved, and is **not qualified decompilation
capability**. No model download is part of this proposal.

Actual register/memory observation is a separate future approval: first qualify
a 32-bit observation method under this CrossOver/Rosetta combination with our
synthetic program, specify exact private sites/fields and maximum captures, and
compare an uninstrumented baseline. CrossOver bundles i386 and x86_64 winedbg
payloads, but their presence does not establish a working or non-perturbing
debugger. No debugger was launched, attached or exposed.

## Inspection receipt and limits

[runtime-proposal.json](../evidence/runtime-proposal.json) contains minimized
metadata; actual source paths and diagnostics stay private. Inspection read app
plists/signature metadata, selected bottle template/version fields, file sizes,
symlink destinations, three dependency DLL headers/hashes, and the two installer
names. It did not read credentials, registry contents, saves, unrelated project
contents or launch-time account state. CodeWeavers's
[guide](https://support.codeweavers.com/crossover-mac-user-guide) documents fresh
bottles and keeping 32-bit applications in 64-bit bottles. The exact isolation,
monitoring and deletion procedure above is this project's proposal, not a claim
of vendor-certified containment.
