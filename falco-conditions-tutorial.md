# Falco Rule Conditions — A Ground-Up Tutorial

> **Who is this for?** Anyone setting up Falco for the first time — especially on Kubernetes (EKS). No prior Falco knowledge needed. Every keyword, operator, and concept is explained in plain English with real-world analogies.

---

## 1. Where "condition" fits in a Falco rule

A Falco rule is a YAML block with five main keys:

```yaml
- rule: Unexpected shell in container
  desc: Detects a shell spawned inside a container
  condition: spawned_process and container and shell_procs and proc.tty != 0
  output: Shell spawned (user=%user.name container=%container.name shell=%proc.name parent=%proc.pname)
  priority: WARNING
  tags: [shell, container, mitre_execution]
```

Here is what each key means:

### `rule` — the name of this detection
- **What it does:** Gives the rule a unique, human-readable name. This is the title that shows up in every alert.
- **Why it matters:** When Falco fires hundreds of alerts, this name is how you identify *which* detection triggered. Make it descriptive.
- **Example:** `Unexpected shell in container` immediately tells you what happened without reading anything else.

### `desc` — human-readable description
- **What it does:** A longer explanation of what the rule detects and *why* it matters.
- **Why it matters:** Six months from now, you (or a teammate) will read this to understand the rule's intent. Write it like a sentence you'd put in a runbook.
- **Example:** `"Detects a shell spawned inside a container"` — clear, concise, explains the security concern.

### `condition` — the boolean filter expression ⭐
- **What it does:** A boolean expression (returns `true` or `false`) evaluated against every single kernel event. If `true`, the rule fires.
- **Think of it as:** An `if` statement that runs millions of times per second across every syscall on the machine.
- **This is the main subject of this entire tutorial.**

### `output` — the alert message template
- **What it does:** Defines the message string produced when the rule fires. Uses `%field.name` placeholders that Falco fills in with live data from the event.
- **Placeholders explained:**
  - `%user.name` → the Linux user that ran the process (e.g., `root`)
  - `%container.name` → the container's name (e.g., `nginx-proxy`)
  - `%proc.name` → the process name (e.g., `bash`)
  - `%proc.pname` → the **parent** process name (e.g., `docker-exec`)
- **Why it matters:** A good output message means you can triage an alert without digging into logs. Include the "who, what, where" fields.

### `priority` — severity level
- **What it does:** Sets how critical the alert is. Falco supports these levels (from highest to lowest):

| Priority | When to use |
|---|---|
| `EMERGENCY` | System is unusable — active breach confirmed |
| `ALERT` | Immediate action needed — e.g., rootkit detected |
| `CRITICAL` | Critical condition — e.g., container escape attempt |
| `ERROR` | Something went wrong that shouldn't — e.g., unauthorized binary execution |
| `WARNING` | Suspicious but not confirmed — e.g., shell in a container |
| `NOTICE` | Normal but noteworthy — e.g., new binary launched for first time |
| `INFO` | Informational — e.g., config file read |
| `DEBUG` | For development/testing only |

- **Tip:** Start with `WARNING` for new rules. Promote to `ERROR`/`CRITICAL` after you've confirmed the rule doesn't produce false positives.

### `tags` — categorization labels
- **What it does:** An array of free-form labels for filtering and grouping alerts.
- **Common tags:**
  - `shell` — rule involves shell processes
  - `container` — rule is container-specific
  - `network` — rule involves network activity
  - `mitre_execution`, `mitre_persistence`, etc. — maps to [MITRE ATT&CK](https://attack.mitre.org/) techniques
- **Why it matters:** In production, you'll route alerts based on tags (e.g., send all `mitre_*` tags to your SIEM, send `container` tags to your Slack channel).

### How it all works together
Falco evaluates every incoming kernel/syscall event (or k8s audit event, if you're using that plugin) against the `condition` expression. If it evaluates to `true`, the rule fires and produces the `output` message at the given `priority`.

> **Analogy:** Think of Falco as a security guard watching a live CCTV feed (the stream of syscalls). The `condition` is the guard's checklist ("alert me if someone enters the server room after hours"). The `output` is the incident report template. The `priority` is the phone number to call (911 vs. a text to the team).

---

## 2. The building block: a "field comparison"

The atomic unit of a condition is:

```
<field> <operator> <value>
```

Example:
```
proc.name = "bash"
```

Let's break down each part:

### Fields — the data Falco extracts from events

- **What they are:** Named pieces of information that Falco pulls out of every kernel event. Think of them as columns in a database table — each event (row) has values for many fields.
- `proc.name` → the name of the process (e.g., `bash`, `nginx`, `python3`)
- The dot notation (`proc.name`) means: the `name` property of the `proc` (process) class.

### Operators — how you compare

- `=` means "equals" (is the process name exactly `bash`?).
- There are many more operators covered in Section 3.

### Values — what you compare against

- `"bash"` is a string value (text wrapped in quotes).
- **Rule of thumb:** Strings need quotes (`"bash"`). Numbers don't (`0`, `443`). Macro and list names don't (`shell_binaries`, `spawned_process`).

### Finding available fields

Falco ships hundreds of fields. Run this to see them all, grouped by class:
```bash
falco --list
```

### Common field classes you'll use constantly

| Prefix | What it describes | Example fields | Real-world use |
|---|---|---|---|
| `evt.*` | The raw event itself (type, direction, args, return value) | `evt.type`, `evt.dir`, `evt.rawres` | "Was this an `open` syscall? Did it succeed?" |
| `proc.*` | The process that generated the event | `proc.name`, `proc.cmdline`, `proc.pname`, `proc.exepath` | "Was this `bash`? What command line was used? Who's the parent?" |
| `fd.*` | The file descriptor involved (file, socket, pipe) | `fd.name`, `fd.typechar`, `fd.num` | "Which file was opened? Is this a network socket?" |
| `user.*` | The user running the process | `user.name`, `user.uid` | "Was this run as `root`?" |
| `container.*` | The container the process is in | `container.id`, `container.name`, `container.image.repository` | "Is this inside a container? Which image?" |
| `k8s.*` | Kubernetes pod/namespace metadata | `k8s.pod.name`, `k8s.ns.name`, `k8s.pod.label.*` | "Is this in the `production` namespace?" |
| `fs.*` | Filesystem path info | `fs.path.name` | "What filesystem path is involved?" |
| `syscall.*` | Raw syscall-level detail | `syscall.type` | "Low-level syscall inspection" |

> **Tip:** You don't need to memorize all fields. Start with `proc.*`, `fd.*`, `container.*`, and `evt.*` — they cover 90% of use cases.

---

## 3. Operators — the full list

Operators are the verbs of Falco conditions — they define *how* you compare a field to a value.

### Comparison operators

| Operator | Meaning | Example | Detailed explanation |
|---|---|---|---|
| `=` or `==` | equals | `evt.type = execve` | **Exact match.** Returns `true` only if the field's value is *exactly* the specified value. Both `=` and `==` work identically — use whichever you prefer. |
| `!=` | not equal | `user.name != "root"` | **Exclusion.** Returns `true` when the value does *not* match. Very common for allow-listing (e.g., "alert on anything that is NOT root"). |
| `<` | less than | `fd.num < 3` | **Numeric comparison.** Useful for checking file descriptor numbers, return codes, or port numbers. `fd.num < 3` means "stdin (0), stdout (1), or stderr (2)". |
| `<=` | less than or equal | `user.uid <= 500` | Includes the boundary value. `user.uid <= 500` captures all system users on most Linux distros. |
| `>` | greater than | `fd.num > 0` | `fd.num > 0` means "not stdin" — the process opened an actual file or socket. |
| `>=` | greater than or equal | `evt.rawres >= 0` | `evt.rawres >= 0` is a classic pattern meaning "the syscall succeeded" (negative return = error in Linux). |

> **When to use which:** Use `=`/`!=` for strings (process names, paths). Use `<`/`>`/`<=`/`>=` for numbers (ports, UIDs, return codes, file descriptor numbers).

### Set membership operators

| Operator | Meaning | Example | Detailed explanation |
|---|---|---|---|
| `in` | value is one of a list | `proc.name in (bash, sh, zsh)` | **"Is this value in the list?"** Returns `true` if the field's value matches *any one* item in the parenthesized list. This replaces long chains of `or` — instead of writing `proc.name = "bash" or proc.name = "sh" or proc.name = "zsh"`, just use `in`. The list can be literal values or a named `list:` (see Section 6). |
| `intersects` | any overlap between two lists | `user.name intersects (root, admin)` | **"Do any values overlap?"** Used when the field itself can contain multiple values (like a set). Returns `true` if *at least one* item in the field's value set appears in the specified list. Less common than `in`, but essential for multi-valued fields. |

> **Analogy:** `in` is like asking "Is this person on the guest list?" `intersects` is like asking "Does this person's set of skills overlap with our requirements?"

> **Pro tip:** `in` is probably your most-used operator. Any time you find yourself writing `or` three or more times comparing the same field, switch to `in`.

### String matching operators

| Operator | Meaning | Example | Detailed explanation |
|---|---|---|---|
| `contains` | substring match, case-sensitive | `fd.name contains "/etc/shadow"` | **"Does this text appear anywhere inside the value?"** Returns `true` if the specified string appears anywhere in the field. Case-sensitive: `"/etc/Shadow"` would NOT match `/etc/shadow`. Use this when you know part of the value but not the full path. |
| `icontains` | substring match, case-insensitive | `proc.cmdline icontains "curl"` | **Same as `contains`, but ignores upper/lowercase.** `"CURL"`, `"Curl"`, `"curl"` all match. Use this when the casing might vary (e.g., user-typed commands). |
| `startswith` | prefix match | `fd.name startswith "/etc/"` | **"Does the value begin with this text?"** Returns `true` if the field starts with the given string. Perfect for path-based filtering: `fd.name startswith "/etc/"` catches `/etc/passwd`, `/etc/shadow`, `/etc/nginx/nginx.conf`, etc. |
| `endswith` | suffix match | `fd.name endswith ".key"` | **"Does the value end with this text?"** Returns `true` if the field ends with the given string. Great for file extension matching: `.key`, `.pem`, `.conf`, `.log`. |
| `pmatch` | path prefix match (list-aware) | `fd.name pmatch (sensitive_paths)` | **"Does the path start with any of these directory prefixes?"** Like `startswith` but designed to work with a *list* of path prefixes all at once. More efficient than chaining multiple `startswith` with `or`. Commonly used with named lists of sensitive directories. |
| `glob` | shell-style glob/wildcard match | `fd.name glob "/var/log/*.log"` | **"Does the value match this wildcard pattern?"** Supports `*` (any characters), `?` (single character), and `[abc]` (character class) — just like shell globbing. `"/var/log/*.log"` matches `/var/log/syslog.log`, `/var/log/auth.log`, etc. but NOT `/var/log/sub/app.log` (globs don't cross `/` boundaries by default). |

> **Choosing the right string operator:**
> - Know the exact path? Use `=`
> - Know the directory prefix? Use `startswith` or `pmatch`
> - Know the file extension? Use `endswith`
> - Know a keyword somewhere in the string? Use `contains` or `icontains`
> - Need wildcards? Use `glob`

### Existence / nullability operator

| Operator | Meaning | Example | Detailed explanation |
|---|---|---|---|
| `exists` | field has a non-null value for this event | `container.id exists` | **"Does this field even have a value right now?"** Not every field applies to every event. For example, `fd.name` (the file path) doesn't exist for a pure `fork` event (forking doesn't open files). `container.id` doesn't exist for host-level processes. If you compare a non-existent field with `=`, the condition silently returns `false` — which can cause you to miss events. Using `exists` lets you explicitly check first. |

> **When to use `exists`:**
> - Before comparing a field that might not be present: `fd.name exists and fd.name startswith "/etc/"`
> - To check "is this event happening inside a container?": `container.id exists`
> - Defensively, when you're unsure if the field is populated for your event type

> **Common pitfall:** If you write `fd.name startswith "/etc/"` but the event is a process fork (no file involved), `fd.name` doesn't exist, the condition returns `false`, and you get no error. This is safe but can cause silent missed detections if you expected the field to be there.

### Boolean field type — no operator needed

Some fields are natively boolean (they are already `true` or `false` by themselves):
```
container.privileged
```
This alone evaluates to true or false — no `= true` required (though `= true` also works).

**Common boolean fields:**
| Field | What it means when `true` |
|---|---|
| `container.privileged` | The container is running in privileged mode (full host access — a major security risk) |
| `evt.is_open_read` | The `open` syscall was for reading |
| `evt.is_open_write` | The `open` syscall was for writing |
| `evt.is_open_exec` | The `open` syscall was for execution |

> **Tip:** You can negate boolean fields with `not`: `not container.privileged` means "the container is NOT running in privileged mode."

---

## 4. Logical operators — combining comparisons

Individual field comparisons are useful, but real rules need to combine multiple checks. Logical operators are the glue.

| Keyword | Meaning | Detailed explanation |
|---|---|---|
| `and` | both sides must be true | **Narrows your filter.** Every `and` you add makes the rule more specific (fewer events match). Think of it as adding more requirements to a checklist — ALL must pass. |
| `or` | either side can be true | **Widens your filter.** Every `or` you add makes the rule less specific (more events match). Think of it as "any of these conditions is enough to trigger." |
| `not` | negation — flip true↔false | **Excludes.** Turns a match into a non-match. Commonly used for allow-listing: `not proc.name in (apt, dpkg)` means "ignore these known-good processes." |
| `()` | grouping — controls evaluation order | **Parentheses are critical.** Without them, `and` binds tighter than `or`, which can produce unexpected results. **Always use parentheses when mixing `and` and `or`.** |

### Operator precedence (why parentheses matter)

Without parentheses, Falco evaluates in this order:
1. `not` (highest priority — evaluated first)
2. `and`
3. `or` (lowest priority — evaluated last)

**Dangerous example without parentheses:**
```
# WRONG — this does NOT do what you probably expect
condition: spawned_process and proc.name = nc or proc.cmdline contains "/dev/tcp/"
```
This is actually evaluated as:
```
(spawned_process and proc.name = nc) or (proc.cmdline contains "/dev/tcp/")
```
The second part (`proc.cmdline contains "/dev/tcp/"`) would match even for events that aren't spawned processes! This is almost certainly not what you want.

**Correct version with parentheses:**
```
condition: spawned_process and (proc.name = nc or proc.cmdline contains "/dev/tcp/")
```
Now the `or` is explicitly grouped, and `spawned_process` is always required.

> **Rule of thumb:** If you have both `and` and `or` in the same condition, **always** use parentheses to make your intent explicit. Don't rely on precedence — future you will thank you.

### Multi-line conditions with YAML folded scalars

For readability, break long conditions across multiple lines:
```yaml
condition: >
  spawned_process
  and container
  and not user_known_shell_activities
  and (proc.name in (nc, ncat, netcat) or proc.cmdline contains "/dev/tcp/")
```

The YAML `>` (folded scalar) joins all the lines into one continuous string, replacing newlines with spaces. This makes complex conditions much easier to read.

| YAML syntax | Behavior | Use for conditions? |
|---|---|---|
| `>` | Folds newlines into spaces | ✅ Yes — recommended |
| `\|` | Preserves newlines literally | ❌ No — Falco conditions must be one logical line |
| (single line) | No folding needed | ✅ Yes — fine for short conditions |

---

## 5. Macros — reusable named conditions

### What is a macro?

A **macro** is a named, reusable snippet of condition logic. It's like a variable that holds a piece of a condition.

### Why do macros exist?

Repeating `evt.type = execve` in every rule is:
- **Tedious** — you type the same thing dozens of times
- **Error-prone** — one typo and a rule silently breaks
- **Hard to maintain** — if the pattern needs to change, you update it in one place

### Defining a macro

```yaml
- macro: spawned_process
  condition: evt.type = execve
```

- `macro:` — tells Falco "this is a reusable condition snippet, not a rule."
- `spawned_process` — the name you'll reference in conditions.
- `condition:` — the actual boolean expression this macro expands to.

### Using a macro in a rule

Now any rule can write the macro name as if it were a built-in keyword:
```yaml
condition: spawned_process and container and proc.name = "bash"
```
Falco internally expands this to:
```yaml
condition: (evt.type = execve) and container and proc.name = "bash"
```

### Built-in macros you'll see everywhere

Falco's default ruleset (`falco_rules.yaml`) is built almost entirely from stacked macros. Here are the most common:

| Macro name | What it expands to (simplified) | Plain English |
|---|---|---|
| `spawned_process` | `evt.type = execve` | "A new process was just created" |
| `container` | `container.id != host` | "This event happened inside a container, not on the bare host" |
| `shell_procs` | `proc.name in (shell_binaries)` | "The process is a shell (bash, sh, zsh, etc.)" |
| `sensitive_files` | `fd.name startswith /etc/shadow or ...` | "A sensitive system file is being accessed" |
| `open_write` | `evt.is_open_write = true` | "A file is being opened for writing" |
| `open_read` | `evt.is_open_read = true` | "A file is being opened for reading" |

### Overriding a macro (tuning without editing the base file)

**Why override?** You want to customize Falco's behavior without modifying the default rules file (which gets overwritten on upgrades).

**Full override** — replace the macro entirely:
```yaml
- macro: user_known_shell_activities
  condition: (never_true)
```
This makes the macro always `false`, effectively disabling any exception it provided.

**Append override** — add to the macro without replacing it:
```yaml
- macro: allowed_shell_containers
  append: true
  condition: or container.image.repository = "myregistry/debug-tools"
```

- `append: true` — tells Falco to add this condition to the existing macro (using `or`).
- This is the **recommended way to tune** — add your exceptions via append rather than forking the entire default ruleset.

> **Analogy:** A macro is like a function in programming. You define it once, and call it by name everywhere. Overriding is like monkey-patching — you change the function's behavior without modifying the original source code.

---

## 6. Lists — reusable named arrays

### What is a list?

A **list** is a named array of strings or numbers. It's a simple collection of values that you reference by name in conditions.

### Why do lists exist?

Instead of writing:
```yaml
condition: proc.name in (bash, sh, zsh, ksh, csh, fish)
```
...in every rule, define the values once:
```yaml
- list: shell_binaries
  items: [bash, sh, zsh, ksh, csh, fish]
```

### Using a list in a condition

Reference the list name inside parentheses with `in`, `intersects`, or `pmatch`:
```yaml
condition: proc.name in (shell_binaries)
```
Falco expands this to:
```yaml
condition: proc.name in (bash, sh, zsh, ksh, csh, fish)
```

### Lists can nest other lists

Lists can reference other named lists, building up larger collections:
```yaml
- list: interactive_binaries
  items: [shell_binaries, editor_binaries]
```
This creates a combined list containing all shell binaries AND all editor binaries.

### Common built-in lists

| List name | Contains | Used for |
|---|---|---|
| `shell_binaries` | bash, sh, zsh, ksh, csh, fish | Detecting shell access |
| `package_mgmt_binaries` | dpkg, rpm, apt, yum, pip, npm | Excluding package managers from "unexpected binary" rules |
| `sensitive_file_names` | /etc/shadow, /etc/sudoers, etc. | Detecting access to sensitive files |
| `known_sa_list` | Default Kubernetes service accounts | Excluding known-good k8s identities |

### Appending to a list

Just like macros, you can append to existing lists without replacing them:
```yaml
- list: shell_binaries
  append: true
  items: [pwsh, fish]
```
This adds `pwsh` and `fish` to the existing `shell_binaries` list.

> **Macro vs. List — when to use which:**
> - Use a **list** when you have a collection of values (process names, file paths, user names).
> - Use a **macro** when you have a condition expression (logic with operators).
> - Lists go inside operators (`in`, `pmatch`). Macros stand alone in conditions.

---

## 7. `evt.type` and `evt.dir` — the two fields you'll use most

### Understanding syscall events

Every operation on a Linux system — opening a file, launching a process, making a network connection — is a **syscall** (system call). Falco hooks into the kernel and sees every single one.

### `evt.type` — what happened

`evt.type` tells you *which* syscall fired. Common values:

| `evt.type` value | What happened | Real-world scenario |
|---|---|---|
| `execve` | A new process was executed | Someone ran `bash`, `curl`, `wget`, etc. |
| `open` | A file was opened | A process read `/etc/passwd` |
| `openat` | A file was opened (modern variant of `open`) | Same as above — most modern apps use this |
| `openat2` | A file was opened (newest variant) | Same, with extra flags |
| `connect` | A network connection was initiated | A process connected to `evil.com:443` |
| `accept` | An incoming network connection was accepted | A server accepted a new client |
| `bind` | A process bound to a network port | A process started listening on port 8080 |
| `chmod` | File permissions were changed | Someone ran `chmod 777 /etc/passwd` |
| `mkdir` | A directory was created | `mkdir /tmp/.hidden` |
| `unlink` / `unlinkat` | A file was deleted | `rm /var/log/auth.log` (covering tracks) |
| `clone` / `fork` | A new process was forked | Process spawning |

You can match several at once:
```yaml
evt.type in (open, openat, openat2)
```

> [!NOTE]
> **Deprecation Warning (Falco 0.42.0+):**
> The `evt.dir` field and the concept of event direction (`<` exit / `>` enter) are **deprecated in Falco 0.42.0+** and removed in recent Falco versions because Falco dropped syscall enter (`>`) events to streamline processing.
> All rules now process exit events natively. You should omit `evt.dir = <` or `evt.dir = >` from all Falco rule conditions.


```yaml
condition: evt.type = open and evt.rawres >= 0
```
Translation: "A file was opened (`open`), the syscall completed (exit), and it succeeded (return code ≥ 0)."

> **Why not check entry events?** Entry events happen *before* the kernel acts. The syscall might fail (permission denied, file not found). If you alert on entry, you'll get noisy false positives for failed attempts. Exit events tell you what *actually* happened.

---

## 8. `evt.arg` and `evt.rawarg` — reading syscall arguments directly

### When do you need raw arguments?

Sometimes Falco doesn't have a friendly named field for the specific data you need. In those cases, you can reach directly into the raw syscall arguments.

### Syntax

```yaml
# Access a named argument
evt.arg.flags contains "O_CREAT"

# Access an argument by position (0-indexed)
evt.arg[1] = "some_value"
```

### `evt.arg` vs. `evt.rawarg`

| Field | What it returns | Example |
|---|---|---|
| `evt.arg.flags` | Human-readable version of the argument | `"O_RDWR\|O_CREAT"` (flag names) |
| `evt.rawarg.flags` | Raw numeric value | `578` (the actual integer) |

### Best practice

**Prefer named fields** (`fd.name`, `proc.cmdline`, `user.name`) when they exist — they're:
- **Normalized** — consistent format regardless of kernel version
- **Portable** — work across different architectures
- **Readable** — `fd.name = "/etc/passwd"` is clearer than `evt.arg[1] = "/etc/passwd"`

**Fall back to `evt.arg.*`** only when no friendly field covers what you need (e.g., checking specific syscall flags).

---

## 9. Building a condition step-by-step (worked example)

**Goal:** Alert if a process inside a container writes to a file under `/etc` that isn't part of normal package management.

Let's build this condition incrementally, explaining each step:

### Step 1 — narrow to the event type
```
evt.type in (open, openat, openat2)
```
**What this does:** Only look at file-open events, and only after they complete (exit). We include all three variants of `open` because different Linux versions and applications use different ones.

### Step 2 — only container events
```
and container.id != host
```
**What this does:** `container.id = host` means the event came from the bare host (not inside any container). By excluding `host`, we only see container events. This is such a common pattern that the built-in macro `container` does exactly this.

### Step 3 — only writes
```
and evt.is_open_write = true
```
**What this does:** `evt.is_open_write` is a boolean field that Falco sets to `true` when the file was opened with write permissions (`O_WRONLY` or `O_RDWR`). We don't care about read-only access to `/etc` — that's normal.

### Step 4 — only under `/etc`
```
and fd.name startswith "/etc/"
```
**What this does:** `fd.name` is the full path of the file being opened. `startswith "/etc/"` catches everything under `/etc` — `/etc/passwd`, `/etc/shadow`, `/etc/nginx/nginx.conf`, etc.

### Step 5 — exclude known-good package manager processes
```
and not proc.name in (dpkg, rpm, yum, apt, apt-get)
```
**What this does:** Package managers legitimately write to `/etc` (installing config files). Excluding them reduces false positives. In production, you'd use a named list instead of inline values.

### Full condition assembled
```yaml
condition: >
  evt.type in (open, openat, openat2)
  and container.id != host
  and evt.is_open_write = true
  and fd.name startswith "/etc/"
  and not proc.name in (dpkg, rpm, yum, apt, apt-get)
```

This is exactly the pattern the stock `Write below etc` rule uses — you've essentially just rebuilt it from scratch.

> **Pattern to remember:** Most Falco conditions follow this structure:
> 1. **Event type filter** — what kind of syscall?
> 2. **Scope filter** — container? namespace? user?
> 3. **Specific filter** — which file? which process?
> 4. **Exclusions** — known-good processes/paths to ignore

---

## 10. Common gotchas

### 1. String values need quotes; identifiers don't
```yaml
# ✅ Correct — "bash" is a string value, needs quotes
proc.name = "bash"

# ✅ Correct — shell_binaries is a list name, no quotes
proc.name in (shell_binaries)

# ❌ Wrong — this would look for a macro/list called bash
proc.name = bash
```
**Rule:** If it's a literal value you're comparing against, quote it. If it's a macro or list name, don't.

> **Exception:** Inside `in (...)` parentheses, items don't need quotes: `in (bash, sh, zsh)` works fine. Falco treats unquoted items inside `in` as literal string values, not macro references (unless a list with that name exists).

### 2. Missing fields return false, not errors
```yaml
# If fd.name doesn't exist for this event, this silently returns false
fd.name startswith "/etc/"
```
**What happens:** If the event doesn't have a `fd.name` (e.g., it's a `fork` event), the comparison returns `false` — not an error. This is *usually* safe, but it means you might miss detections you expected to trigger.

**Fix:** Use `exists` when you want to be explicit:
```yaml
fd.name exists and fd.name startswith "/etc/"
```

### 3. Order macros and lists before use
Falco processes rules top-to-bottom in each file, and files in the order specified by `-r` or config.

```yaml
# ❌ Wrong — using shell_binaries before defining it
- rule: My Rule
  condition: proc.name in (shell_binaries)

- list: shell_binaries
  items: [bash, sh]
```

```yaml
# ✅ Correct — define first, use second
- list: shell_binaries
  items: [bash, sh]

- rule: My Rule
  condition: proc.name in (shell_binaries)
```

**Tip:** Put lists at the top, then macros, then rules. Or split them into separate files: `lists.yaml` → `macros.yaml` → `rules.yaml`, loaded in that order.

### 4. `append: true` requires an existing definition
```yaml
# ❌ Fails — nothing to append to
- list: my_new_list
  append: true
  items: [something]
```
`append: true` only works if a list/macro/rule of the same name was already loaded from an earlier file or earlier in the same file.

**Use case:** The typical pattern is:
1. Falco loads the default `falco_rules.yaml` (shipped with Falco)
2. You create `falco_rules.local.yaml` with `append: true` entries to customize

### 5. Test in isolation before deploying
```bash
# Validate syntax (no events processed, just checks for errors)
falco -r your_rules.yaml -M 30 --dry-run

# Test against a saved event trace (a .scap capture file)
falco -r your_rules.yaml -e your_capture.scap
```
Always validate syntax before deploying — a single typo can prevent *all* rules from loading.

---

## 11. For your EKS/Falco setup specifically

Since you're integrating Falco into ArgoCD App-of-Apps on EKS with Bottlerocket:

### Use Kubernetes fields for namespace scoping
```yaml
# Exclude noisy system namespaces from shell-in-container rules
and not k8s.ns.name in (kube-system, argocd, kube-node-lease)

# Only alert for production namespace
and k8s.ns.name = "production"

# Target specific pods by label
and k8s.pod.label.app = "my-app"
```

### Bottlerocket considerations
Bottlerocket's minimal userspace means many stock "package manager" exception macros (`package_mgmt_procs`, etc.) are irrelevant — there's no `apt`, `yum`, or `dpkg` on Bottlerocket nodes. You'll likely want to:
- **Prune** unused package-manager exceptions to reduce rule complexity
- **Add** Karpenter and Istio sidecar process names to your own allow-lists instead of relying on defaults built for Ubuntu-based nodes

### GitOps-friendly rule organization
Consider a dedicated `lists.yaml` / `macros.yaml` layered ahead of `falco_rules.local.yaml` in your ArgoCD-synced ConfigMap, so tuning stays declarative and diff-able in Git rather than edited in-cluster.

```
files loaded in order:
  1. falco_rules.yaml          ← Falco defaults (don't edit)
  2. lists.yaml                ← Your custom lists
  3. macros.yaml               ← Your custom macros
  4. falco_rules.local.yaml    ← Your custom rules + overrides
```

---

## Quick reference cheat-sheet

```
COMPARISON OPERATORS
  =  or ==     Exact match              evt.type = execve
  !=           Not equal                user.name != "root"
  <  <=  >  >= Numeric comparison       fd.num > 0

SET MEMBERSHIP
  in (list)         Value is in the list       proc.name in (bash, sh, zsh)
  intersects (list) Any overlap between sets   user.name intersects (root, admin)

STRING MATCHING
  contains      Substring (case-sensitive)    fd.name contains "/etc/shadow"
  icontains     Substring (case-insensitive)  proc.cmdline icontains "curl"
  startswith    Prefix match                  fd.name startswith "/etc/"
  endswith      Suffix match                  fd.name endswith ".key"
  pmatch        Path prefix match (list)      fd.name pmatch (sensitive_paths)
  glob          Wildcard pattern              fd.name glob "/var/log/*.log"

EXISTENCE
  exists        Field has a value             container.id exists

LOGIC
  and           Both sides true               spawned_process and container
  or            Either side true              proc.name = "nc" or proc.name = "ncat"
  not           Negation                      not proc.name in (apt, dpkg)
  ( )           Grouping                      (A or B) and C

EVENT DIRECTION
  evt.dir = >   Syscall entry (before kernel acts)
  evt.dir = <   Syscall exit  (after kernel acts — use this most of the time)

REUSABLE BUILDING BLOCKS
  macro:        Named condition snippet       macro: spawned_process
  list:         Named array of values         list: shell_binaries
  append: true  Add to existing macro/list    Without replacing the original
```
