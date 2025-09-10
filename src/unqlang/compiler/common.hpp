#pragma once
#include <cstdint>

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
} // unqlang::compiler