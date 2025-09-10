#pragma once

#ifndef MACHINE_INSTRUCTION
#define MACHINE_INSTRUCTION
#endif

#include "instruction.hpp"

namespace machine::instruction_helper {
	union operands_type {
		struct {
			uint8_t has_result : 1;
			uint8_t num_operands : 2;
			uint8_t reserved : 5;
		};
		uint8_t raw;

		static constexpr uint8_t NO_OPERANDS = 0;
		static constexpr uint8_t ONE_OPERAND = 1;
		static constexpr uint8_t TWO_OPERANDS = 2;
		static constexpr uint8_t MEMORY_OPERAND = 3;
	};
	inline operands_type get_operands_type(const operation op);
} // namespace machine::instruction_helper

#include "instruction_helper.inl"
