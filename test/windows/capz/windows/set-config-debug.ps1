(Get-Content c:\\CalicoWindows\\config.ps1).replace("# `$env:FELIX_LOGSEVERITYSCREEN = `"info`"", "`$env:FELIX_LOGSEVERITYSCREEN = `"debug`"") | Set-Content c:\\CalicoWindows\\config.ps1 -Force

