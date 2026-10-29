@echo off
rem SystemInformer 4.0.26241.138 - Task Manager on steroids + kernel-mode inspection
rem (successor of Process Hacker). Run elevated for kernel driver features; without
rem admin rights it starts in a limited user-mode mode.
start "" "%~dp0SystemInformer\amd64\SystemInformer.exe" %*
