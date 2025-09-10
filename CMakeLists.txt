cmake_minimum_required(VERSION 4.0)
project(MiscMachine)

set(CMAKE_CXX_STANDARD 23)

add_executable(MiscMachine

	src/assembly/assembly_parser.cpp
	src/assembly/assembly.cpp
	src/machine/computer.cpp
	src/machine/computer_split.cpp
	src/main.cpp
	src/compiler/lexer.cpp
	src/compiler/ast.cpp
	src/compiler/compiler.cpp
	src/compiler/ast_interpreter.cpp
	src/compiler/ast_helpers.cpp
	src/compiler/analysis/types.cpp
	src/machine/assembler.cpp
)
