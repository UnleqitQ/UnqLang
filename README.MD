# UnqLang

This is a project to learn how to write a compiler from scratch.
The language is called UnqLang and is a C-like language with some differences.

This is not a production ready compiler, it is just a learning project!

## Building

To build the compiler, you need a C++ compiler that supports C++20 or later.
You can use CMake to build the project.

The CMake Project has multiple targets:
- `MiscMachine`: The main.cpp executable.
- `MiscMachine_assembler`: The main_assembler.cpp executable.
- `MiscMachine_compiler`: The main_compiler.cpp executable. (This is the one you want to use)

```bash
mkdir build
cd build
cmake ..
cmake --build . --target MiscMachine_compiler
```
