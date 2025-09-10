#pragma once
#include <vector>

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
		uint16_t stack_size; // total size of parameters passed on stack
		std::vector<assembly_function_parameter> parameters;
		assembly_function_parameter return_value;
		std::string name;
	};
} // unqlang::compiler
