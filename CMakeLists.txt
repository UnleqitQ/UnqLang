cmake_minimum_required(VERSION 4.0)
project(MiscMachine)

include(CMakeRC.cmake)

set(CMAKE_CXX_STANDARD 23)

add_library(UnqLangLib
	src/unqlang/analysis/expressions.cpp
	src/unqlang/analysis/functions.cpp
	src/unqlang/analysis/statements.cpp
	src/unqlang/analysis/types.cpp
	src/unqlang/analysis/variables.cpp
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
	src/machine/instruction_helper.cpp
)

link_libraries(UnqLangCompilerLib UnqLangLib MiscMachineLib)


add_executable(MiscMachine

	src/main.cpp
)

cmrc_add_resource_library(
	BuiltinResources
	NAMESPACE builtin
	WHENCE res

	res/builtin/puti.usm
	res/builtin/putc.usm
	res/builtin/dev_in.usm
	res/builtin/dev_out.usm
)

target_link_libraries(MiscMachine MiscMachineLib UnqLangCompilerLib UnqLangLib BuiltinResources)

