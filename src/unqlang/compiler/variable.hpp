#pragma once
#include "../analysis/types.hpp"
#include "../../machine/register.hpp"


namespace unqlang::compiler {
	struct variable_info {
		analysis::types::type_node type;
		uint32_t type_size;
	};
	struct assembly_variable_info {
		analysis::types::type_node type;
		uint16_t offset; // offset from base pointer
		uint32_t size; // size in bytes
	};
} // unqlang::compiler
