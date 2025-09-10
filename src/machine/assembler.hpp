#pragma once

#include <vector>

#include "instruction.hpp"

namespace machine::assembler {
	typedef std::vector<uint8_t> bytecode_t;
	void assemble(const machine::instruction_t& instr, bytecode_t& out);
	void assemble(const machine::program_t& program, bytecode_t& out);
}
