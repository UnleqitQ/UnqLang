#pragma once

#include <vector>

#include "instruction.hpp"

namespace machine::assembler {
	typedef std::vector<uint8_t> bytecode_t;
	void assemble(const machine::instruction_t& instr, bytecode_t& out);
	void assemble(const machine::program_t& program, bytecode_t& out);
	void assemble_unsafe(const machine::instruction_t& instr, bytecode_t& out);
	void assemble_unsafe(const machine::program_t& program, bytecode_t& out);

	void disassemble(const bytecode_t& bytecode, machine::instruction_t& out, size_t& pc);
	void disassemble(const bytecode_t& bytecode, machine::program_t& out, size_t start = 0, size_t end = SIZE_MAX);
	void disassemble_unsafe(const bytecode_t& bytecode, machine::instruction_t& out, size_t& pc);
	void disassemble_unsafe(const bytecode_t& bytecode, machine::program_t& out, size_t start = 0, size_t end = SIZE_MAX);
}
