# Compiler

So this will be a doc or more like a dump of how the compiler works and what it does.
This is mostly for my own reference. (As if anyone would read this..., that's not going publicly)

## Overview

The language is in C-like syntax, but it is not C (because I'm not crazy enough to make a C compiler).\
The compiler is written in C++ and uses a custom lexer and parser to generate an Abstract Syntax Tree (AST).\
The AST is then transformed into an Intermediate Representation (IR) which is then optimized and finally translated into
assembly code. (At least that's the plan)

So now on to the details of the language.

## Language Features

The language will for now be called "UnqLang" (file extension: .unq).
The language will have the following features (at least in the beginning):

- Basic data types: int, float, char, bool
- Variables and constants
- Arithmetic and logical operations
- Control flow: if, else, while, for
- Functions
- Pointers (including arrays)
- Structs
- Basic I/O operations (print, read (not implemented in machine yet))
- Comments (// for single line, /* */ for multi line)

