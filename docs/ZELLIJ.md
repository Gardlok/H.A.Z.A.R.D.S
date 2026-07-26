# Zellij workspace behavior

HAZARDS keeps ordinary Zellij startup ordinary. Running `zellij` loads Zellij's built-in `default` layout with normal mouse selection, scrollback selection, automatic copy-on-select, and the standard interface bars.

The HAZARDS workspace is opt-in:

```console
zellij --layout hazards
```

The `hazards` layout opens the editor, shell, tests, logs, system, and maintenance panes and includes Zellij's tab bar and status bar.

Holding `Shift` while using the mouse temporarily bypasses Zellij mouse handling and delegates selection to the outer terminal emulator.
