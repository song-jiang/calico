#Bcdedit.exe -set TESTSIGNING ON
#Restart-Computer

curl https://github.com/song-jiang/calico/releases/download/win-fix-ep/ebpf-win-temp-e56e80.zip -OutFile c:\ebpf-win-temp.zip

Write-Host "Unzip Ebpf for Windows release..."
Expand-Archive -Force c:\ebpf-win-temp.zip c:\

cd c:\TEMP
./install-ebpf.bat
