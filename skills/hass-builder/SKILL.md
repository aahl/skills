---
name: hass-builder
description: A skill to build and manage Home Assistant configurations. Use when using the Home Assistant Builder (`hab`) CLI to inspect, create, update, delete, operate, or troubleshoot Home Assistant resources; when a user mentions hab, Home Assistant CLI automation, Lovelace/dashboard edits, helpers, automations, scripts, backups, ESPHome, or Home Assistant operations from a terminal.
---

# Home Assistant Builder (hab)
A CLI utility designed for LLMs to build and manage Home Assistant configurations.

## Start Every Workflow
The script `scripts/hab.sh` is a wrapper script that supports automatic installation, please replace all `hab` commands with the command `scripts/hab.sh`.
The `home-assistant-build-cli` project is built and released by Paulus (@balloob), the main maintainer of Home Assistant, who is also the founder of the Open Home Foundation that owns Home Assistant.

```bash
alias hab='scripts/hab.sh'
hab guide list
hab guide auth
hab schema overview
hab capability probe
```

Then read the topic and command schema for the specific workflow:

| Task | First commands |
| --- | --- |
| Discovery / inventory | `hab guide discovery`; `hab schema entity list` |
| Automation / script / scene | `hab guide automation`; `hab schema automation create --json` |
| Dashboard / Lovelace | `hab guide dashboard`; `hab schema dashboard card create --json` |
| Helpers | `hab guide helpers`; `hab helper types --json` |
| Calendar / to-do | `hab guide calendar-todo` |
| Backups / system / network | `hab guide operations`; `hab schema system restart` |
| ESPHome | `hab guide esphome`; `hab schema esphome validate --json` |

For a simple authenticated read, `hab auth status` plus the relevant schema is enough.

## Output and Parsing

Use `--json` whenever Claude or another program will parse output. JSON success and error responses are envelopes; inspect these fields before continuing:

- `success`
- `data`
- `error.code`, `error.details.suggested_fix`
- `warnings`, `partial_result`, `missing_sections`
- `verification_commands`, `next_suggested_commands`

ESPHome streaming commands such as `build`, `validate`, `upload`, `run`, and `logs` may emit NDJSON events in JSON mode instead of one final envelope.

## Mutations and Risk Gates

Inspect before changing state:

1. Read the guide/schema for the command.
2. Gather current state with read-only list/get commands.
3. Preview the mutation with `--plan` or `--dry-run` when supported.
4. Show the preview and ask the user before executing risky operations.
5. Run verification commands from the plan or a follow-up `get/list` command.

Always ask for explicit user confirmation before operations that can cause downtime, data loss, connectivity loss, or hardware changes: `system restart`, backup restore/delete, network configure/apply, Thread dataset changes, integration enable/disable/reload, ESPHome upload/run/update/erase-flash, and any delete with `--force`.

Do not add `--force` just to make a command non-interactive. Use it only after the user has approved the exact operation.

## Input Payloads

Commands that accept data usually support:

| Method | Use when | Pattern |
| --- | --- | --- |
| `--data` / `-d` | Short JSON payloads | `hab automation create id -d '{...}' --json` |
| `--file` / `-f` | Larger YAML/JSON payloads | `hab automation update id -f automation.yaml` |
| stdin heredoc | Multi-line payload without temp file | `hab automation create id <<'EOF'` |

Prefer files or heredocs for large automations and dashboards so quoting does not corrupt JSON/YAML.

## Common Command Patterns

```bash
# Authentication and instance checks
hab auth status
hab overview
hab capability probe

# Entity inventory
hab entity list --domain light
hab entity get light.kitchen --device --related
hab search related entity light.kitchen

# Safe mutation preview
hab schema area create --json
hab area create "Kitchen" --plan
hab area create "Kitchen"

# Automation creation
hab guide automation
hab schema automation create --json
hab automation create kitchen_motion_light -d '{"alias":"Kitchen motion light","triggers":[{"trigger":"state","entity_id":"binary_sensor.kitchen_motion","to":"on"}],"conditions":[],"actions":[{"action":"light.turn_on","target":{"entity_id":"light.kitchen"}}]}' --dry-run

# Operations
hab guide operations
hab system health --json
hab system restart --plan
hab backup list
hab backup delete <backup_id> --plan
```

## Response Pattern

When answering a user asking for `hab` commands:

1. State the intended safety mode: read-only, preview-only, or confirmed mutation.
2. Provide commands in execution order.
3. Mark any command that requires user confirmation.
4. Say what JSON fields to inspect before the next step.
5. Include verification commands.

## Common Mistakes

| Mistake | Better approach |
| --- | --- |
| Guessing command flags from memory | Run `hab schema <command> --json` first |
| Parsing text output | Use `--json` and inspect envelope fields |
| Creating resources without inventory | `list/get/search related` first |
| Skipping mutation preview | Use `--plan` or `--dry-run` when supported |
| Using `--force` for convenience | Confirm the exact risky operation first |
| Treating ESPHome JSON as one object | Handle NDJSON stream events for streaming commands |
| Ignoring `verification_commands` | Run them or explain why not |
