# EasyDump

A simple x64dbg plugin for dumping unpacked PE payloads in memory.

## Building

From a Visual Studio command prompt:

```
cmake -B build64 -A x64
cmake --build build64 --config Release
```

You will get `build64\EasyDump.sln` that you can open in Visual Studio.

To build a 32-bit plugin:

```
cmake -B build32 -A Win32
cmake --build build32 --config Release
```

