@echo off
reg delete HKLM\Software\Microsoft\Windows\CurrentVersion\Run /f
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /f
