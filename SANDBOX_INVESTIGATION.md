# OpenCode Sandbox Investigation

## Executive Summary

**OpenCode does NOT have a true sandbox.** The project explicitly states this in `SECURITY.md`:

> OpenCode does **not** sandbox the agent. The permission system exists as a UX feature to help users stay aware of what actions the agent is taking - it prompts for confirmation before executing commands, writing files, etc. However, it is not designed to provide security isolation.

What OpenCode calls "sandbox" is actually a **project boundary concept** — the git repository root and working directory that define the scope of the project. It is not a security isolation mechanism.

---

## Architecture Overview

OpenCode's "sandbox" is built from several interconnected layers:

```
┌─────────────────────────────────────────────────────┐
│                 User / Terminal                      │
├─────────────────────────────────────────────────────┤
│          Permission System (UX Layer)                │
│  ┌───────────┐  ┌────────────┐  ┌────────────────┐  │
│  │ ask/reply  │  │  wildcard  │  │  arity-based   │  │
│  │  prompts   │  │  matching  │  │  cmd grouping  │  │
│  └───────────┘  └────────────┘  └────────────────┘  │
├─────────────────────────────────────────────────────┤
│          Project Boundary Detection                  │
│  ┌───────────┐  ┌────────────┐  ┌────────────────┐  │
│  │  .git dir  │  │  worktree  │  │ containsPath() │  │
│  │  discovery │  │  tracking  │  │    checks      │  │
│  └───────────┘  └────────────┘  └────────────────┘  │
├─────────────────────────────────────────────────────┤
│          Execution Layer (No Isolation)               │
│  ┌───────────┐  ┌────────────┐  ┌────────────────┐  │
│  │  bash via  │  │  PTY for   │  │  file ops via  │  │
│  │  spawn()   │  │  terminals │  │  Node.js fs    │  │
│  └───────────┘  └────────────┘  └────────────────┘  │
├─────────────────────────────────────────────────────┤
│          Host Operating System (full access)          │
└─────────────────────────────────────────────────────┘
```

---

## Detailed Component Analysis

### 1. Project Boundary ("Sandbox" Definition)

**File:** `packages/opencode/src/project/project.ts`

The term "sandbox" in OpenCode refers to the **git repository root directory**. It is determined by:

1. Walking up the directory tree looking for `.git`
2. Using `git rev-parse --show-toplevel` to find the repo root
3. Using `git rev-parse --git-common-dir` for worktree support

```typescript
// project.ts:90-204 - fromDirectory()
const matches = Filesystem.up({ targets: [".git"], start: directory })
const dotgit = await matches.next().then((x) => x.value)
if (dotgit) {
  let sandbox = path.dirname(dotgit)
  // ...
  const top = await git(["rev-parse", "--show-toplevel"], { cwd: sandbox })
  sandbox = top
  // ...
}
```

**Key behaviors:**
- If a `.git` directory is found, the sandbox = repo root
- If no `.git` is found, sandbox = `"/"` (the entire filesystem)
- Multiple sandboxes are tracked in the project's `sandboxes: string[]` array (for submodules, etc.)
- Sandboxes are persisted in a SQLite database

### 2. Path Containment Check

**File:** `packages/opencode/src/project/instance.ts`

```typescript
// instance.ts:59-65
containsPath(filepath: string) {
  if (Filesystem.contains(Instance.directory, filepath)) return true
  if (Instance.worktree === "/") return false
  return Filesystem.contains(Instance.worktree, filepath)
}
```

This is a **detection-only** mechanism. It determines whether a path is inside the project boundary. When a path is outside, it triggers an `external_directory` permission prompt — but this is just a UX confirmation, not a security enforcement.

### 3. Permission System

**File:** `packages/opencode/src/permission/index.ts`

The permission system is an in-memory, session-scoped approval tracker:

- **States:** `"once"` | `"always"` | `"reject"`
- **Pattern matching:** Uses wildcard glob patterns (e.g., `git *`, `rm *`)
- **No persistence:** Approvals reset each session
- **Plugin hook:** `permission.ask` allows plugins to auto-allow or auto-deny

```typescript
// permission/index.ts:100-153
export async function ask(input: { type, message, pattern, sessionID, ... }) {
  const approvedForSession = approved[input.sessionID] || {}
  const keys = toKeys(input.pattern, input.type)
  if (covered(keys, approvedForSession)) return  // Already approved

  // Check plugin-based auto-allow/deny
  switch (await Plugin.trigger("permission.ask", info, { status: "ask" }).then(x => x.status)) {
    case "deny": throw new RejectedError(...)
    case "allow": return
  }

  // Otherwise, prompt user and wait
  return new Promise<void>((resolve, reject) => {
    pending[input.sessionID][info.id] = { info, resolve, reject }
    Bus.publish(Event.Updated, info)
  })
}
```

**Configurable permissions** (via `opencode.json`):
```json
{
  "permission": {
    "bash": {
      "*": "ask",
      "git *": "allow",
      "rm *": "deny"
    }
  }
}
```

### 4. Command Execution (Bash Tool)

**File:** `packages/opencode/src/tool/bash.ts`

Commands are executed via standard `child_process.spawn()` with **no isolation**:

```typescript
// bash.ts:172-181
const proc = spawn(params.command, {
  shell,
  cwd,
  env: {
    ...process.env,       // Full host environment
    ...shellEnv.env,      // Plugin-injected env vars
  },
  stdio: ["ignore", "pipe", "pipe"],
  detached: process.platform !== "win32",
})
```

**Before execution**, the bash tool does:
1. Parses the command using Tree-Sitter (bash grammar) to extract command structure
2. Detects external directory access for commands like `cd`, `rm`, `cp`, `mv`, etc.
3. Requests `external_directory` permission if paths are outside the project
4. Requests `bash` permission for the command pattern
5. Applies arity-based grouping (e.g., `git checkout` → `git *`) for pattern matching

**Protections (process-level only):**
- Timeout: 2 minutes default (configurable via `OPENCODE_EXPERIMENTAL_BASH_DEFAULT_TIMEOUT_MS`)
- SIGTERM → 200ms delay → SIGKILL kill tree
- Abort signal support for user cancellation

### 5. Command Arity System

**File:** `packages/opencode/src/permission/arity.ts`

Maps 150+ command prefixes to semantic groupings so users can approve command classes:

```typescript
const ARITY: Record<string, number> = {
  git: 2,           // "git checkout" → approve "git *"
  npm: 2,           // "npm install" → approve "npm *"
  "npm run": 3,     // "npm run dev" → approve "npm run *"
  docker: 2,        // "docker run" → approve "docker *"
  kubectl: 2,       // "kubectl get" → approve "kubectl *"
  // ...150+ more
}
```

### 6. Shell Selection

**File:** `packages/opencode/src/shell/shell.ts`

- Blacklists `fish` and `nu` shells (unsupported syntax)
- Falls back to: `$SHELL` → `bash` → `/bin/sh` (Linux), `/bin/zsh` (macOS)
- On Windows: Git Bash → `cmd.exe`
- Kill tree: SIGTERM → 200ms → SIGKILL (Unix), `taskkill /f /t` (Windows)

### 7. Docker Image (Distribution Only)

**File:** `packages/opencode/Dockerfile`

```dockerfile
FROM alpine AS base
RUN apk add libgcc libstdc++ ripgrep
COPY dist/opencode-linux-x64-baseline-musl/bin/opencode /usr/local/bin/opencode
ENTRYPOINT ["opencode"]
```

This is purely a distribution container. There is no security isolation, seccomp profiles, or capability dropping. The Dockerfile packages the binary for deployment — any sandboxing would come from how the user runs this container.

---

## What OpenCode Does NOT Have

| Mechanism | Present? | Notes |
|-----------|----------|-------|
| Container isolation (namespaces) | No | Docker image is for distribution only |
| seccomp/AppArmor profiles | No | No syscall filtering |
| chroot / pivot_root | No | Full filesystem access |
| User namespaces | No | Runs as invoking user |
| Network isolation | No | Full network access |
| Resource limits (cgroups) | No | Only timeout on commands |
| Capability dropping | No | Inherits all user capabilities |
| Read-only filesystem mounts | No | Full write access |
| ptrace restrictions | No | No tracing restrictions |

---

## Summary

OpenCode's "sandbox" is a **project boundary concept**, not a security boundary:

1. **Project discovery:** Finds the git repo root and calls it the "sandbox"
2. **Path detection:** Checks if file operations target paths inside/outside the project
3. **Permission prompting:** Asks the user for approval before executing commands or accessing external paths
4. **No enforcement:** All execution happens with full host access via `spawn()`

The entire system is designed for **user awareness** — helping users understand what the AI agent is doing — not for security isolation. True sandboxing requires running OpenCode inside a Docker container or VM, as the project's own security documentation recommends.

---
---

# Comparison: OpenCode Sandbox vs. OmicVerse OvAgent Sandbox

## Executive Comparison

Neither system provides true OS-level sandboxing (containers, namespaces, seccomp). However, **OpenCode's approach is significantly more mature, intentional, and well-engineered** compared to OmicVerse's OvAgent. OpenCode builds a sophisticated UX-layer permission system with honest security documentation, while OvAgent relies on minimal Python-level isolation with `exec()` that provides a false sense of security.

---

## OmicVerse OvAgent Sandbox Architecture

### Overview

OmicVerse's agent system (`ov.Agent()`) is an AI-powered bioinformatics assistant in `omicverse/utils/smart_agent.py`. It generates Python code from natural language and executes it. The "sandbox" has two execution paths:

### Execution Path 1: In-Process `exec()` (Legacy/Fallback)

**File:** `omicverse/utils/agent_backend.py`

The `_run_python_local()` method in `OmicVerseLLMBackend`:

```python
compiled = compile(code, "<ov-agent-python>", "exec")
exec(compiled, sandbox_globals, sandbox_locals)
```

- Runs LLM-generated code via `exec()` with separate `sandbox_globals`/`sandbox_locals` dicts
- Captures stdout/stderr via `contextlib.redirect_stdout/stderr()`
- **No restricted builtins** — all Python builtins available (`os.system()`, `subprocess`, file I/O, network)
- **No import restrictions** — any module can be imported
- The separate namespace dicts prevent polluting the module scope but do NOT prevent system access

### Execution Path 2: Jupyter Kernel (Primary)

**File:** `omicverse/utils/session_notebook_executor.py`

The `SessionNotebookExecutor` class:

```python
msg_id = kc.execute(code, silent=False)
```

- Spawns a real Jupyter kernel subprocess
- Sends LLM-generated code to the kernel for execution
- State persists across prompts (variables, imports carry over)
- **No restricted builtins or import filtering**
- Full filesystem access (reads/writes `.h5ad` data files)
- Full system access within the kernel process

### Sandbox Fallback Policy

**File:** `omicverse/utils/agent_config.py`

```python
class SandboxFallbackPolicy(Enum):
    RAISE = "raise"                    # Hard fail
    WARN_AND_FALLBACK = "warn"         # Default — fall back to exec()
    SILENT = "silent"                  # Silent fallback
```

When the Jupyter kernel fails, the system falls back to in-process `exec()` — silently or with a warning — further reducing isolation.

### Error Hierarchy

**File:** `omicverse/utils/agent_errors.py`

Includes `SandboxDeniedError` (subclass of `ExecutionError`) but this is only raised when the sandbox fallback policy is `RAISE` and the notebook kernel is unavailable. It does not represent a security enforcement — it simply means "the notebook couldn't start."

### Code Safety: ProactiveCodeTransformer

The only pre-execution safety measure is a regex-based code transformer that fixes common LLM code generation mistakes:
- Removes assignments from in-place functions: `adata = ov.pp.pca(adata)` → `ov.pp.pca(adata)`
- Converts f-strings to concatenation
- Guards `.cat` accessor on DataFrames

This is for **correctness**, not security.

---

## Side-by-Side Comparison

| Dimension | OpenCode | OmicVerse OvAgent |
|-----------|----------|-------------------|
| **Language/Runtime** | TypeScript/Bun (Node.js) | Python |
| **Execution Method** | `child_process.spawn()` with shell | `exec()` in-process + Jupyter kernel |
| **What Runs** | Arbitrary shell commands | LLM-generated Python code |
| **Security Documentation** | Explicit: "No sandbox" in SECURITY.md | Minimal: buried disclaimer in docstring |
| **Permission System** | Full interactive UX (ask/once/always/reject) | None — code runs without user approval |
| **Pre-Execution Analysis** | Tree-Sitter AST parsing of commands | Regex-based code transforms (correctness only) |
| **Command Classification** | 150+ arity-based semantic groupings | None |
| **Path Boundary Detection** | Git-based project boundary + containsPath() | None |
| **External Directory Protection** | Prompts user for paths outside project | None |
| **Configurable Policies** | Per-command allow/ask/deny in opencode.json | Sandbox fallback policy only |
| **Plugin System** | Hooks for permission.ask auto-allow/deny | None |
| **Timeout Protection** | 2min default, configurable, SIGTERM→SIGKILL | 600s default via ExecutionConfig |
| **Process Cleanup** | Full process tree kill (SIGTERM→SIGKILL) | Kernel shutdown only |
| **State Isolation** | Each command is a fresh process | State persists across prompts |
| **Namespace Restriction** | N/A (shell processes) | Separate globals/locals dicts (no real restriction) |
| **Import Restrictions** | N/A (shell processes) | None — all imports allowed |
| **Builtin Restrictions** | N/A (shell processes) | None — all builtins available |
| **User Approval Before Execution** | Yes — every command requires permission | No — code executes automatically |
| **Abort/Cancel Support** | Full abort signal + process tree kill | Kernel interrupt only |
| **Container Support** | Alpine Docker image for distribution | None |
| **Error Typing** | Permission.RejectedError | SandboxDeniedError (kernel-unavailable only) |

---

## Why OpenCode's Approach Is Better

### 1. Honest Threat Model

OpenCode explicitly documents that its permission system is a UX feature, not a security boundary (`SECURITY.md`). It tells users: "If you need true isolation, run OpenCode inside a Docker container or VM." This honesty prevents users from having a false sense of security.

OmicVerse's documentation buries a disclaimer: "The sandbox restricts available built-ins and module imports, but it is not a foolproof security boundary." This is misleading — the sandbox does NOT actually restrict builtins or imports; all Python builtins and all modules remain fully accessible.

### 2. User Approval Gate

OpenCode's strongest feature is its **interactive permission system**. Every command must be approved by the user before execution. The system parses commands with Tree-Sitter, classifies them semantically (150+ command patterns), detects external directory access, and presents clear prompts. Users can approve once, always (for a pattern), or reject.

OmicVerse has **no approval gate**. LLM-generated code executes immediately and automatically. The user has no opportunity to review or reject generated code before it runs on their system.

### 3. Command Understanding

OpenCode uses **Tree-Sitter AST parsing** to understand bash commands structurally:
- Extracts command names, arguments, and redirections
- Detects filesystem-affecting operations (`cd`, `rm`, `cp`, `mv`, `mkdir`, etc.)
- Resolves paths via `realpath` to detect external directory access
- Groups commands into semantic categories via the arity system

OmicVerse applies **regex-based transforms** that fix common code generation mistakes but perform no security analysis of the generated code.

### 4. Granular Policy Configuration

OpenCode allows fine-grained permission policies in `opencode.json`:
```json
{
  "permission": {
    "bash": {
      "git *": "allow",
      "npm run *": "allow",
      "rm *": "deny"
    }
  }
}
```

OmicVerse offers only a single `SandboxFallbackPolicy` that controls what happens when the Jupyter kernel is unavailable — not what code is allowed to run.

### 5. Process Lifecycle Management

OpenCode provides robust process management:
- **Process groups**: Uses `detached: true` and negative PID kills (`process.kill(-pid)`) to kill entire process trees
- **Graceful shutdown**: SIGTERM → 200ms wait → SIGKILL escalation
- **Timeout enforcement**: Configurable with clean process tree termination
- **Abort support**: Users can cancel running commands at any time

OmicVerse's Jupyter kernel executor has basic timeout support and kernel shutdown, but no process tree management for spawned subprocesses.

### 6. Plugin Extensibility

OpenCode's permission system is extensible via plugins:
```typescript
Plugin.trigger("permission.ask", info, { status: "ask" })
// Plugins can return: "allow", "deny", or "ask"
```

This allows organizations to build custom security policies. OmicVerse has no equivalent extensibility.

---

## What Both Systems Lack

Neither system provides true OS-level isolation:

| Mechanism | OpenCode | OmicVerse |
|-----------|----------|-----------|
| Container namespaces | No | No |
| seccomp/AppArmor | No | No |
| chroot / filesystem isolation | No | No |
| Network isolation | No | No |
| Resource limits (cgroups) | No | No |
| Capability dropping | No | No |
| User namespace separation | No | No |

---

## Conclusion

OpenCode is better than OmicVerse's OvAgent sandbox in every measurable dimension:

1. **Transparency**: OpenCode is honest about not being a sandbox; OmicVerse's naming is misleading
2. **User control**: OpenCode requires explicit permission for every action; OmicVerse auto-executes
3. **Command analysis**: OpenCode uses proper AST parsing; OmicVerse uses regex
4. **Policy granularity**: OpenCode has per-command configurable policies; OmicVerse has a single fallback toggle
5. **Process management**: OpenCode handles process trees with graceful+forced termination; OmicVerse handles kernels only
6. **Extensibility**: OpenCode has a plugin system for custom policies; OmicVerse has none

However, it's important to note that the two systems serve fundamentally different purposes. OpenCode is a **general-purpose coding agent** that executes arbitrary shell commands across any language/toolchain, while OmicVerse's OvAgent is a **domain-specific bioinformatics agent** that generates and runs Python code for data analysis. OpenCode's richer permission system reflects its broader attack surface, while OvAgent's simpler approach reflects its narrower (though still dangerous) execution scope.
