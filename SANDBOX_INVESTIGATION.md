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
