Set wshShell = WScript.CreateObject("WScript.Shell")
do
    WScript.Sleep 100
    wshShell.SendKeys "{CAPSLOCK}"
loop
