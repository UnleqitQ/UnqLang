#pragma once
#include "../analysis/types.hpp"
#include "../../machine/register.hpp"


namespace unqlang::compiler {
	struct variable_info {
		analysis::types::type_node type;
		uint32_t type_size;
		bool is_parameter;
	};
	struct assembly_variable_info {
		enum class location_type {
			stack,
			reg,
			param_stack
		} type;
		union {
			struct {
				uint16_t offset; // offset from base pointer (parameters are positive, locals are negative)
			} stack;
			struct {
				machine::register_id reg;
			} register_;
		} location;
		uint32_t size; // size in bytes
	};
} // unqlang::compiler
