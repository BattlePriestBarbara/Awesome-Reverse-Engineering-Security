@echo off
rem Il2CppDumper 6.7.46 - recovers types/methods/metadata from Unity IL2CPP games.
rem usage: Il2CppDumper.exe <libil2cpp.so/GameAssembly.dll> <global-metadata.dat> <out_dir>
rem The -x86 build is for 32-bit il2cpp; the ghidra*.py / ida*.py scripts load the
rem generated il2cpp.h into those disassemblers.
start "" "%~dp0Il2CppDumper\Il2CppDumper.exe" %*
