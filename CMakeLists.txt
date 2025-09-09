cmake_minimum_required(VERSION 4.0)
project(MiscMachine)

set(CMAKE_CXX_STANDARD 23)

add_executable(MiscMachine

	src/assembly/assembly_parser.cpp
	src/assembly/assembly.cpp
	src/machine/computer.cpp
	src/main.cpp
	src/compiler/lexer.cpp
	src/compiler/lexer.hpp
	src/compiler/ast.cpp
	src/compiler/ast.hpp
	src/compiler/compiler.cpp
	src/compiler/compiler.hpp
	src/compiler/ast_interpreter.cpp
	src/compiler/ast_interpreter.hpp
	src/compiler/ast_helpers.cpp
)
