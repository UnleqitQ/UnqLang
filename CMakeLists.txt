cmake_minimum_required(VERSION 4.0)
project(MiscMachine)

set(CMAKE_CXX_STANDARD 23)

add_library(UnqLangLib
	src/unqlang/analysis/types.cpp
	src/unqlang/ast_helpers.cpp
	src/unqlang/ast_interpreter.cpp
	src/unqlang/ast.cpp
	src/unqlang/lexer.cpp
)

add_library(UnqLangCompilerLib
	src/unqlang/compiler/compiler.cpp
	src/unqlang/compiler/function.cpp
	src/unqlang/compiler/scope.cpp
	src/unqlang/compiler/variable.cpp
)
add_library(MiscMachineLib
	src/assembly/assembly_parser.cpp
	src/assembly/assembly.cpp
	src/machine/assembler.cpp
	src/machine/computer_split.cpp
	src/machine/computer.cpp
)

link_libraries(UnqLangCompilerLib UnqLangLib MiscMachineLib)


add_executable(MiscMachine

	src/main.cpp
)
add_executable(MiscMachine_compiler

	src/main_compiler.cpp
)
add_executable(MiscMachine_assembler

	src/main_assembler.cpp
)

target_link_libraries(MiscMachine MiscMachineLib UnqLangCompilerLib UnqLangLib)
target_link_libraries(MiscMachine_compiler MiscMachineLib UnqLangCompilerLib UnqLangLib)
target_link_libraries(MiscMachine_assembler MiscMachineLib)

