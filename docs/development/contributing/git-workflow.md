# Git Workflow

**Always use branches and pull requests.** Never push directly to main.

## Creating a Branch

```bash
git checkout -b descriptive-branch-name
```

Use descriptive names:
- `feat/add-debug-export`
- `fix/cache-mount-permissions`
- `docs/update-readme`

## Making Changes

### 1. Make Changes and Test

```bash
# Build
go build ./...

# Test
go test -short ./...

# Lint
go vet ./...
```

### 2. Commit

Use conventional commit messages:

```bash
git add -A
git commit -m "feat: add debug image export on build failure

Exports the build container as an OCI image when a build fails,
allowing developers to inspect the failed state.

Closes #42"
```

#### Commit Prefixes

| Prefix | Use For |
|--------|---------|
| `feat:` | New features |
| `fix:` | Bug fixes |
| `docs:` | Documentation only |
| `test:` | Adding/updating tests |
| `refactor:` | Code restructuring |
| `ci:` | CI/CD changes |

### 3. Push

```bash
git push -u origin descriptive-branch-name
```

## Creating a Pull Request

```bash
gh pr create --title "feat: add debug image export" --body "## Summary
- Exports debug image on build failure
- Uses OCI image format
- Configurable via --export-debug-image flag

## Test Plan
- [x] Unit tests added
- [x] E2E test added
- [x] Manual testing completed"
```

Or use the GitHub web UI.

## CI Checks

PRs must pass:

| Check | What It Does |
|-------|--------------|
| Build | Compiles all packages |
| Test | Runs unit tests |
| E2E Tests | Runs BuildKit integration tests |
| Lint | Runs golangci-lint |
| Verify | Checks go.mod is tidy |

## Addressing Review Feedback

```bash
# Make changes
git add -A
git commit -m "fix: address review feedback"
git push
```

CI re-runs automatically.

## Merging

Once approved and CI passes:

```bash
gh pr merge --squash
```

Or use the GitHub web UI "Squash and merge" button.

## Branch Protection

The `main` branch has protection rules:
- Changes must go through PRs
- CI checks must pass
- PRs should be reviewed

## Tips

### Keep PRs Focused

One feature or fix per PR. Large PRs are hard to review.

### Write Good Commit Messages

- First line: brief summary (50 chars)
- Blank line
- Body: explain what and why (wrap at 72 chars)

### Update Your Branch

If main has changed:

```bash
git fetch origin
git rebase origin/main
git push --force-with-lease
```

### Cleanup After Merge

```bash
git checkout main
git pull
git branch -d your-branch-name
```
