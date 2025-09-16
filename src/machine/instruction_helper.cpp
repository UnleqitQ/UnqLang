#include "instruction_helper.hpp"

namespace machine::instruction_helper {
	operands_type get_operands_type(const operation op) {
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
			case operation::MOVSX:
			case operation::MOVZX:
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
			case operation::IN:
				return {1, 1, 0}; // One operand, one result
			case operation::LEA:
				return {1, 3, 0}; // One memory operand, one result
			case operation::CMP:
			case operation::TEST:
			case operation::OUT:
				return {0, 2, 0}; // Two operands, no result
			case operation::INC:
			case operation::DEC:
			case operation::NEG:
			case operation::NOT:
			case operation::POP:
			case operation::SETZ:
			case operation::SETNZ:
			case operation::SETO:
			case operation::SETNO:
			case operation::SETC:
			case operation::SETNC:
			case operation::SETS:
			case operation::SETNS:
			case operation::SETG:
			case operation::SETGE:
			case operation::SETL:
			case operation::SETLE:
			case operation::SETA:
			case operation::SETAE:
			case operation::SETB:
			case operation::SETBE:
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
				return {0, 1, 0}; // One operand, no result
		}
		std::cerr << "Warning: Unknown operation in get_operands_type: " << static_cast<uint8_t>(op) << "\n";
		return {0, 0, 0}; // Default to no operands, no result
	}
} // namespace machine::instruction_helper
