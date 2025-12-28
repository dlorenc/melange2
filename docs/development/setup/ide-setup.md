# IDE Setup

Configuration guides for common editors.

## VS Code

### Recommended Extensions

- **Go** (`golang.go`) - Essential Go support
- **YAML** (`redhat.vscode-yaml`) - YAML schema validation
- **GitLens** (`eamodio.gitlens`) - Git integration

### Settings

Add to `.vscode/settings.json`:

```json
{
  "go.useLanguageServer": true,
  "go.lintTool": "golangci-lint",
  "go.lintFlags": ["--fast"],
  "editor.formatOnSave": true,
  "[go]": {
    "editor.defaultFormatter": "golang.go"
  },
  "yaml.schemas": {
    "https://raw.githubusercontent.com/chainguard-dev/melange/main/pkg/config/schema.json": "*.yaml"
  }
}
```

### Launch Configuration

Add to `.vscode/launch.json`:

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Debug Build",
      "type": "go",
      "request": "launch",
      "mode": "debug",
      "program": "${workspaceFolder}",
      "args": ["build", "examples/minimal.yaml", "--buildkit-addr", "tcp://localhost:1234", "--debug"]
    },
    {
      "name": "Debug Test",
      "type": "go",
      "request": "launch",
      "mode": "test",
      "program": "${workspaceFolder}/pkg/buildkit",
      "args": ["-test.v", "-test.run", "TestE2E_FetchSource"]
    }
  ]
}
```

## GoLand / IntelliJ IDEA

### Run Configuration

1. **Run/Debug Configurations** > **Go Build**
2. Set:
   - Package path: `github.com/dlorenc/melange2`
   - Program arguments: `build examples/minimal.yaml --buildkit-addr tcp://localhost:1234`
   - Working directory: Project root

### Test Configuration

1. **Run/Debug Configurations** > **Go Test**
2. Set:
   - Test kind: Package
   - Package path: `github.com/dlorenc/melange2/pkg/buildkit`
   - Program arguments: `-test.v -test.run TestE2E_FetchSource`

### File Watchers

Enable auto-formatting:
1. **Settings** > **Tools** > **File Watchers**
2. Add `gofmt` or `goimports`

## Vim/Neovim

### With vim-go

```vim
" .vimrc
call plug#begin()
Plug 'fatih/vim-go', { 'do': ':GoUpdateBinaries' }
call plug#end()

let g:go_fmt_command = "goimports"
let g:go_def_mode = 'gopls'
let g:go_info_mode = 'gopls'
```

### With nvim-lspconfig

```lua
-- init.lua
require('lspconfig').gopls.setup{
  settings = {
    gopls = {
      analyses = { unusedparams = true },
      staticcheck = true,
    },
  },
}
```

## Emacs

### With lsp-mode

```elisp
;; init.el
(use-package go-mode)
(use-package lsp-mode
  :hook (go-mode . lsp-deferred))
```

## Editor-Agnostic Tips

### Configure GOPATH

Ensure your module is accessible:

```bash
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
```

### Pre-commit Hooks

Add to `.git/hooks/pre-commit`:

```bash
#!/bin/sh
go vet ./...
go test -short ./...
```

Make executable:

```bash
chmod +x .git/hooks/pre-commit
```

### Shell Aliases

```bash
# ~/.bashrc or ~/.zshrc
alias m2='./melange2'
alias m2b='./melange2 build --buildkit-addr tcp://localhost:1234'
alias gots='go test -short ./...'
alias gota='go test ./...'
```
