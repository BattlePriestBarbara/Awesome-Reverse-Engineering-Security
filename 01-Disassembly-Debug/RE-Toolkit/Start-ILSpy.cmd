@echo off
rem ILSpy 11.2 - open-source .NET assembly decompiler (C# / IL / metadata browser).
rem This is the *self-contained* build (bundles .NET 8 runtime), so it runs on a machine
rem without any installed .NET; it just needs the whole folder, do not copy ILSpy.exe alone.
start "" "%~dp0..\ILSpy\ILSpy.exe" %*
