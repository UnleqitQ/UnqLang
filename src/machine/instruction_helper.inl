#pragma once
#ifndef MACHINE_INSTRUCTION
#error "Include machine/instruction.hpp instead of machine/instruction.inl"
#endif

namespace machine::instruction_helper {
	inline operands_type get_operands_type(const operation op) {
		switch (op) {
			case operation::NOP:
			case operation::RET:
			case operation::PUSHA:
			case operation::POPA:
			case operation::PUSHF:
			case operation::POPF:
			case operation::CLC:
			case operation::STC:
			case operation::HLT:
				return {0, 0, 0}; // No operands, no result
			case operation::MOV:
			case operation::ADD:
			case operation::SUB:
			case operation::ADC:
			case operation::SBB:
			case operation::MUL:
			case operation::IMUL:
			case operation::DIV:
			case operation::IDIV:
			case operation::MOD:
			case operation::IMOD:
			case operation::AND:
			case operation::OR:
			case operation::XOR:
			case operation::SHL:
			case operation::SHR:
			case operation::SAR:
			case operation::ROL:
			case operation::ROR:
			case operation::RCL:
			case operation::RCR:
				return {1, 1, 0}; // One operand, one result
			case operation::LEA:
				return {1, 3, 0}; // One memory operand, one result
			case operation::CMP:
			case operation::TEST:
				return {0, 2, 0}; // Two operands, no result
			case operation::INC:
			case operation::DEC:
			case operation::NEG:
			case operation::NOT:
			case operation::POP:
			case operation::IN:
				return {1, 0, 0}; // No operands, one result
			case operation::PUSH:
			case operation::JMP:
			case operation::JZ:
			case operation::JNZ:
			case operation::JC:
			case operation::JNC:
			case operation::JO:
			case operation::JNO:
			case operation::JP:
			case operation::JNP:
			case operation::JS:
			case operation::JNS:
			case operation::JG:
			case operation::JGE:
			case operation::JL:
			case operation::JLE:
			case operation::JA:
			case operation::JAE:
			case operation::JB:
			case operation::JBE:
			case operation::CALL:
			case operation::OUT:
				return {0, 1, 0}; // One operand, no result
			default:
				return {0, 0, 0}; // Unknown operation
		}
	}
} // namespace machine::instruction_helper
