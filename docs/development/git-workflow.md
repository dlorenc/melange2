# Git Workflow

This document describes the Git workflow for contributing to melange2.

## Golden Rule

**Never push directly to main. Always use branches and pull requests.**

## Branch Strategy

### Branch Naming

Use descriptive branch names with conventional prefixes:

| Prefix | Purpose | Example |
|--------|---------|---------|
| `feat/` | New features | `feat/add-rust-pipeline` |
| `fix/` | Bug fixes | `fix/cache-mount-permissions` |
| `docs/` | Documentation | `docs/update-testing-guide` |
| `test/` | Test improvements | `test/add-cache-e2e-tests` |
| `refactor/` | Code refactoring | `refactor/simplify-llb-builder` |
| `ci/` | CI/CD changes | `ci/add-coverage-report` |

### Creating a Branch

```bash
# Make sure you're on main and up to date
git checkout main
git pull origin main

# Create a new branch
git checkout -b feat/your-feature-name
```

## Commit Guidelines

### Commit Message Format

```
type: short description (imperative mood, lowercase)

Longer explanation if needed. Explain the motivation for the change
and how it differs from previous behavior.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
```

### Commit Types

| Type | Description |
|------|-------------|
| `feat` | A new feature |
| `fix` | A bug fix |
| `docs` | Documentation changes |
| `test` | Adding or modifying tests |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `ci` | CI/CD configuration changes |
| `chore` | Other changes that don't modify src or test files |

### Good Commit Messages

```
feat: add Rust cargo cache mounts

Add persistent cache mounts for Rust cargo registry and git
dependencies. This significantly speeds up Rust builds by reusing
previously downloaded crates.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
```

```
fix: correct build user permissions on workspace

The workspace directory was created with root ownership, causing
permission errors when pipelines ran as the build user (UID 1000).
Now explicitly set ownership during workspace preparation.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
```

### Bad Commit Messages

```
fixed stuff          # Too vague
WIP                  # Not descriptive
Update config.go     # What was updated?
```

## Making Changes

### 1. Make Your Changes

```bash
# Edit files
vim pkg/buildkit/builder.go

# Run tests
go test -short ./...

# Run linting
golangci-lint run
```

### 2. Stage and Commit

```bash
# Stage changes
git add -A

# Commit with a good message
git commit -m "$(cat <<'EOF'
feat: add description here

More details if needed.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

### 3. Push Your Branch

```bash
git push -u origin feat/your-feature-name
```

## Creating a Pull Request

### Using GitHub CLI

```bash
gh pr create --title "feat: your feature description" --body "$(cat <<'EOF'
## Summary
- Brief description of changes

## Test Plan
- [ ] Unit tests pass
- [ ] E2E tests pass
- [ ] Manual testing done

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

### PR Template

```markdown
## Summary
- What does this PR do?
- Why is it needed?
- Any important implementation details?

## Test Plan
- [ ] `go test -short ./...` passes
- [ ] `go test ./pkg/buildkit/...` passes (if E2E changes)
- [ ] Manual verification: [describe what you tested]

## Related Issues
Fixes #123
```

### PR Checklist

Before submitting:

- [ ] Code compiles without errors
- [ ] Unit tests pass (`go test -short ./...`)
- [ ] E2E tests pass if applicable
- [ ] Code is formatted (`goimports -w .`)
- [ ] Linting passes (`golangci-lint run`)
- [ ] Documentation updated if needed
- [ ] Commit messages follow conventions

## Code Review

### As an Author

- Respond to all review comments
- Make requested changes promptly
- Mark conversations as resolved after addressing
- Request re-review when ready

### As a Reviewer

- Be constructive and specific
- Explain the reasoning behind suggestions
- Approve when changes are satisfactory
- Use "Request changes" for blocking issues

## Merging

PRs are merged via squash merge to keep history clean. The PR title becomes the commit message.

## What NOT to Do

1. **Don't push to main directly**
   ```bash
   # WRONG
   git push origin main

   # RIGHT
   git push origin feat/my-feature
   gh pr create
   ```

2. **Don't use interactive git commands**
   ```bash
   # WRONG (interactive mode not supported in CI)
   git rebase -i HEAD~3
   git add -i
   ```

3. **Don't skip hooks**
   ```bash
   # WRONG
   git commit --no-verify
   git push --no-verify
   ```

4. **Don't force push to main**
   ```bash
   # NEVER DO THIS
   git push --force origin main
   ```

5. **Don't amend pushed commits without care**
   ```bash
   # Only amend if:
   # 1. Commit was created by you in this session
   # 2. Commit has NOT been pushed
   # 3. Pre-commit hook auto-modified files
   ```

## Handling Merge Conflicts

### Rebasing on Main

```bash
git checkout main
git pull origin main
git checkout feat/your-feature
git rebase main
```

### Resolving Conflicts

```bash
# Edit conflicting files to resolve
vim conflicting-file.go

# Stage resolved files
git add conflicting-file.go

# Continue rebase
git rebase --continue
```

### Force Push After Rebase

```bash
# Safe force push to your feature branch only
git push --force-with-lease origin feat/your-feature
```

## Keeping Your Branch Updated

```bash
# Fetch latest changes
git fetch origin

# Rebase your branch on main
git rebase origin/main

# Push updates (if previously pushed)
git push --force-with-lease origin feat/your-feature
```

## Undoing Mistakes

### Undo Last Commit (Not Pushed)

```bash
# Keep changes staged
git reset --soft HEAD~1

# Discard changes
git reset --hard HEAD~1
```

### Fix Commit Message (Not Pushed)

```bash
git commit --amend -m "new message"
```

### Discard All Local Changes

```bash
git checkout -- .
git clean -fd
```

## CI/CD Integration

Every PR triggers the CI pipeline (`.github/workflows/ci.yaml`):

1. **Build**: Compiles all code
2. **Test**: Runs unit tests with coverage
3. **E2E**: Runs E2E tests
4. **Lint**: Runs golangci-lint
5. **Verify**: Checks go.mod is tidy

All checks must pass before merging.

## Automatic Deployment

When changes are merged to `main`, the deploy workflow (`.github/workflows/deploy.yaml`) automatically:

1. Builds container images with ko
2. Deploys to GKE cluster
3. Updates the running melange-server

## Quick Reference

```bash
# Start new feature
git checkout main && git pull
git checkout -b feat/new-feature

# Make changes and commit
git add -A
git commit -m "feat: add new feature

Description here.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"

# Push and create PR
git push -u origin feat/new-feature
gh pr create --title "feat: add new feature" --body "## Summary
- Added new feature

## Test Plan
- [ ] Tests pass"

# After review and approval, merge via GitHub UI
```
