@echo off
rem Ghidra 12.1.3 - full disassembler + decompiler (IDA/Hex-Rays replacement).
rem NOTE: Ghidra does NOT read the JAVA_HOME environment variable. launch.bat asks
rem LaunchSupport for a JDK >= 21 and caches the answer per user in
rem   %APPDATA%\ghidra\ghidra_12.1.3_PUBLIC\java_home.save
rem That file holds the ASCII junction D:\RE-JDK (-> ..\..\04-Runtimes\jdk25), because the
rem save file is parsed with the platform codepage and a non-ASCII JDK path breaks it.
rem If Ghidra ever reports "Failed to find a supported JDK", set
rem   JAVA_HOME_OVERRIDE=D:\RE-JDK
rem in ...\support\launch.properties to pin it explicitly.
rem Paths are relative to this script so the toolkit survives being moved.
start "" "%~dp0..\Ghidra\ghidraRun.bat" %*