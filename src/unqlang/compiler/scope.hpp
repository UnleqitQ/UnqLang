#pragma once

#include <cstdint>

#include "common.hpp"
#include "variable.hpp"

namespace unqlang::compiler {
	struct scope {
		std::shared_ptr<scope> parent; // parent scope, nullptr if global
		std::unordered_map<std::string, variable_info> symbol_table; // symbol name to variable info
		uint32_t stack_size; // size of local variables in this scope
	};
	struct assembly_scope {
		// parent scope, nullptr if global
		std::shared_ptr<assembly_scope> parent;
		// symbol name to variable info
		std::unordered_map<std::string, assembly_variable_info> symbol_table;
		// size of local variables in this scope
		uint32_t stack_size;
		// registers used in this scope
		regmask used_registers;
		// registers that need to be saved/restored in this scope
		regmask saved_registers;
		// registers that are changed in this scope (but not saved/restored, e.g. caller-saved registers)
		regmask changed_registers;
	};
} // unqlang::compiler
