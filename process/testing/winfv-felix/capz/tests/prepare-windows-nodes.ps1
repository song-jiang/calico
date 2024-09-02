# containerd expects to be in c:\Program Files
mkdir -p C:\bin -ErrorAction SilentlyContinue
Copy-Item "$Env:ProgramFiles\containerd\ctr.exe" "c:\bin"
C:\bin\ctr.exe --version

Write-Output "Pulling servercore:ltsc2022 image..."
C:\bin\ctr.exe -n k8s.io images pull mcr.microsoft.com/windows/servercore:ltsc2022 | Out-Null

Write-Output "Pulling pause image..."
c:\bin\ctr.exe images pull k8s.gcr.io/pause:3.5 | Out-Null

Write-Output "All done."
