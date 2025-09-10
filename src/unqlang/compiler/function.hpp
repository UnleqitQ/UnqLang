#pragma once
#include <vector>

#include "common.hpp"
#include "../../machine/register.hpp"
#include "../analysis/types.hpp"

namespace unqlang::compiler {
	struct function_signature {
		std::vector<analysis::types::type_node> parameters;
		analysis::types::type_node return_type;
		std::string name;
	};
	struct assembly_function_signature {
		struct assembly_function_parameter {
			analysis::types::type_node type;
			enum class passing_convention {
				stack,
				reg
			} convention;
			union {
				struct {
					machine::register_id reg;
				} reg;
				struct {
					uint16_t offset;
				} stack;
			} assignment;
		};
		uint32_t stack_size; // total size of parameters passed on stack
		std::vector<assembly_function_parameter> parameters;
		assembly_function_parameter return_value;
		std::string name;

		// registers used in this scope
		regmask used_registers;
		// registers that need to be saved/restored in this scope
		regmask saved_registers;
		// registers that are changed in this scope (but not saved/restored, e.g. caller-saved registers)
		regmask changed_registers;
	};
} // unqlang::compiler
