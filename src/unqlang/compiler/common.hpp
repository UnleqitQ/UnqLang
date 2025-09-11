#pragma once
#include <cstdint>

#include "../analysis/types.hpp"

namespace unqlang::compiler {
	union regmask {
		struct {
			uint8_t eax : 1;
			uint8_t ebx : 1;
			uint8_t ecx : 1;
			uint8_t edx : 1;
			uint8_t esi : 1;
			uint8_t edi : 1;
			uint8_t ebp : 1;
			uint8_t esp : 1;
			// eip is not included as there is no way to use it directly
		};
		uint16_t raw;
	};
	struct compilation_context {
		// type system for type information
		std::shared_ptr<analysis::types::type_system> type_system;
	};
} // unqlang::compiler