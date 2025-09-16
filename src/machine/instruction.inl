#pragma once
#ifndef MACHINE_INSTRUCTION
#error "Include machine/instruction.hpp instead of machine/instruction.inl"
#endif

namespace machine {
	inline std::ostream& operator<<(std::ostream& os, const operation& op) {
		os << operation_to_string(op);
		return os;
	}
	inline std::string operation_to_string(operation op) {
		switch (op) {
			case operation::NOP: return "nop";
			case operation::MOV: return "mov";
			case operation::MOVSX: return "movsx";
			case operation::MOVZX: return "movzx";
			case operation::PUSH: return "push";
			case operation::POP: return "pop";
			case operation::LEA: return "lea";
			case operation::ADD: return "add";
			case operation::SUB: return "sub";
			case operation::MUL: return "mul";
			case operation::IMUL: return "imul";
			case operation::DIV: return "div";
			case operation::IDIV: return "idiv";
			case operation::MOD: return "mod";
			case operation::IMOD: return "imod";
			case operation::INC: return "inc";
			case operation::DEC: return "dec";
			case operation::NEG: return "neg";
			case operation::ADC: return "adc";
			case operation::SBB: return "sbb";
			case operation::CMP: return "cmp";
			case operation::AND: return "and";
			case operation::OR: return "or";
			case operation::XOR: return "xor";
			case operation::NOT: return "not";
			case operation::SHL: return "shl";
			case operation::SHR: return "shr";
			case operation::SAR: return "sar";
			case operation::ROL: return "rol";
			case operation::ROR: return "ror";
			case operation::RCL: return "rcl";
			case operation::RCR: return "rcr";
			case operation::TEST: return "test";
			case operation::JMP: return "jmp";
			case operation::JZ: return "jz";
			case operation::JNZ: return "jnz";
			case operation::JC: return "jc";
			case operation::JNC: return "jnc";
			case operation::JO: return "jo";
			case operation::JNO: return "jno";
			case operation::JP: return "jp";
			case operation::JNP: return "jnp";
			case operation::JS: return "js";
			case operation::JNS: return "jns";
			case operation::JG: return "jg";
			case operation::JGE: return "jge";
			case operation::JL: return "jl";
			case operation::JLE: return "jle";
			case operation::JA: return "ja";
			case operation::JAE: return "jae";
			case operation::JB: return "jb";
			case operation::JBE: return "jbe";
			case operation::CALL: return "call";
			case operation::RET: return "ret";
			case operation::PUSHA: return "pusha";
			case operation::POPA: return "popa";
			case operation::PUSHF: return "pushf";
			case operation::POPF: return "popf";
			case operation::CLC: return "clc";
			case operation::STC: return "stc";
			case operation::HLT: return "hlt";
			case operation::SETZ: return "setz";
			case operation::SETNZ: return "setnz";
			case operation::SETO: return "seto";
			case operation::SETNO: return "setno";
			case operation::SETC: return "setc";
			case operation::SETNC: return "setnc";
			case operation::SETS: return "sets";
			case operation::SETNS: return "setns";
			case operation::SETG: return "setg";
			case operation::SETGE: return "setge";
			case operation::SETL: return "setl";
			case operation::SETLE: return "setle";
			case operation::SETA: return "seta";
			case operation::SETAE: return "setae";
			case operation::SETB: return "setb";
			case operation::SETBE: return "setbe";
			case operation::IN: return "in";
			case operation::OUT: return "out";
			default: return "unknown";
		}
	}
	inline operation operation_from_string(const std::string& str) {
		if (str == "nop") return operation::NOP;
		if (str == "mov") return operation::MOV;
		if (str == "movsx") return operation::MOVSX;
		if (str == "movzx") return operation::MOVZX;
		if (str == "push") return operation::PUSH;
		if (str == "pop") return operation::POP;
		if (str == "lea") return operation::LEA;
		if (str == "add") return operation::ADD;
		if (str == "sub") return operation::SUB;
		if (str == "mul") return operation::MUL;
		if (str == "imul") return operation::IMUL;
		if (str == "div") return operation::DIV;
		if (str == "idiv") return operation::IDIV;
		if (str == "mod") return operation::MOD;
		if (str == "imod") return operation::IMOD;
		if (str == "inc") return operation::INC;
		if (str == "dec") return operation::DEC;
		if (str == "neg") return operation::NEG;
		if (str == "adc") return operation::ADC;
		if (str == "sbb") return operation::SBB;
		if (str == "cmp") return operation::CMP;
		if (str == "and") return operation::AND;
		if (str == "or") return operation::OR;
		if (str == "xor") return operation::XOR;
		if (str == "not") return operation::NOT;
		if (str == "shl") return operation::SHL;
		if (str == "shr") return operation::SHR;
		if (str == "sar") return operation::SAR;
		if (str == "rol") return operation::ROL;
		if (str == "ror") return operation::ROR;
		if (str == "rcl") return operation::RCL;
		if (str == "rcr") return operation::RCR;
		if (str == "test") return operation::TEST;
		if (str == "jmp") return operation::JMP;
		if (str == "jz" || str == "je") return operation::JZ;
		if (str == "jnz" || str == "jne") return operation::JNZ;
		if (str == "jc") return operation::JC;
		if (str == "jnc") return operation::JNC;
		if (str == "jo") return operation::JO;
		if (str == "jno") return operation::JNO;
		if (str == "jp") return operation::JP;
		if (str == "jnp") return operation::JNP;
		if (str == "js") return operation::JS;
		if (str == "jns") return operation::JNS;
		if (str == "jg") return operation::JG;
		if (str == "jge") return operation::JGE;
		if (str == "jl") return operation::JL;
		if (str == "jle") return operation::JLE;
		if (str == "ja") return operation::JA;
		if (str == "jae") return operation::JAE;
		if (str == "jb") return operation::JB;
		if (str == "jbe") return operation::JBE;
		if (str == "call") return operation::CALL;
		if (str == "ret") return operation::RET;
		if (str == "pusha") return operation::PUSHA;
		if (str == "popa") return operation::POPA;
		if (str == "pushf") return operation::PUSHF;
		if (str == "popf") return operation::POPF;
		if (str == "clc") return operation::CLC;
		if (str == "stc") return operation::STC;
		if (str == "hlt" || str == "end") return operation::HLT;
		if (str == "setz") return operation::SETZ;
		if (str == "setnz") return operation::SETNZ;
		if (str == "seto") return operation::SETO;
		if (str == "setno") return operation::SETNO;
		if (str == "setc") return operation::SETC;
		if (str == "setnc") return operation::SETNC;
		if (str == "sets") return operation::SETS;
		if (str == "setns") return operation::SETNS;
		if (str == "setg") return operation::SETG;
		if (str == "setge") return operation::SETGE;
		if (str == "setl") return operation::SETL;
		if (str == "setle") return operation::SETLE;
		if (str == "seta") return operation::SETA;
		if (str == "setae") return operation::SETAE;
		if (str == "setb") return operation::SETB;
		if (str == "setbe") return operation::SETBE;
		if (str == "in") return operation::IN;
		if (str == "out") return operation::OUT;
		return operation::NOP; // Default to NOP for unrecognized strings
	}

	inline std::ostream& operator<<(std::ostream& os, const memory_operand& mem) {
		switch (mem.memory_type) {
			case memory_operand::type::DIRECT:
				os << "[" << std::hex << "0x" << mem.value.direct_address << std::dec << "]";
				break;
			case memory_operand::type::REGISTER:
				os << "[" << mem.value.reg << "]";
				break;
			case memory_operand::type::DISPLACEMENT:
				os << "[" << mem.value.disp.base;
				if (mem.value.disp.disp >= 0) {
					os << " + " << mem.value.disp.disp;
				}
				else {
					os << " - " << -mem.value.disp.disp;
				}
				os << "]";
				break;
			case memory_operand::type::SCALED_INDEX:
				os << "[" << mem.value.s_index.base << " + " << mem.value.s_index.index;
				if (mem.value.s_index.scale != 1) {
					os << " * " << static_cast<int>(mem.value.s_index.scale);
				}
				os << "]";
				break;
			case memory_operand::type::SCALED_INDEX_DISPLACEMENT:
				os << "[" << mem.value.s_index_disp.base << " + " << mem.value.s_index_disp.index;
				if (mem.value.s_index_disp.scale != 1) {
					os << " * " << static_cast<int>(mem.value.s_index_disp.scale);
				}
				if (mem.value.s_index_disp.disp >= 0) {
					os << " + " << mem.value.s_index_disp.disp;
				}
				else {
					os << " - " << -mem.value.s_index_disp.disp;
				}
				os << "]";
				break;
			default:
				os << "unknown";
				break;
		}
		return os;
	}
	inline std::ostream& operator<<(std::ostream& os, const operand_arg& arg) {
		switch (arg.type) {
			case operand_arg::type_t::REGISTER:
				os << arg.value.reg;
				break;
			case operand_arg::type_t::IMMEDIATE:
				os << "#" << arg.value.imm;
				break;
			case operand_arg::type_t::MEMORY:
				os << arg.value.mem;
				break;
			default:
				os << "unknown";
				break;
		}
		return os;
	}
	inline std::ostream& operator<<(std::ostream& os, const result_arg& res) {
		switch (res.type) {
			case result_arg::type_t::REGISTER:
				os << res.value.reg;
				break;
			case result_arg::type_t::MEMORY:
				os << res.value.mem;
				break;
			default:
				os << "unknown";
				break;
		}
		return os;
	}
	inline std::ostream& operator<<(std::ostream& os, const instruction_t& inst) {
		os << inst.op;
		switch (inst.op) {
			// One read only memory, one read & write (LEA)
			case operation::LEA: {
				const auto& args = inst.args.args_1r_mem;
				os << ' ' << args.result << ", " << args.operands[0];
				break;
			}
			// One read only, one read & write
			case operation::MOV:
			case operation::MOVSX:
			case operation::MOVZX:
			case operation::ADD:
			case operation::ADC:
			case operation::SUB:
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
			case operation::RCR: {
				const auto& args = inst.args.args_1r;
				os << ' ' << args.result << ", " << args.operands[0];
				break;
			}
			// Two read only
			case operation::CMP:
			case operation::TEST: {
				const auto& args = inst.args.args_2n;
				os << ' ' << args.operands[0] << ", " << args.operands[1];
				break;
			}
			// One read & write
			case operation::NOT:
			case operation::NEG:
			case operation::INC:
			case operation::DEC:
			case operation::POP:
			case operation::IN:
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
			case operation::SETBE: {
				const auto& args = inst.args.args_0r;
				os << ' ' << args.result;
				break;
			}
			// One read only
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
			case operation::OUT: {
				const auto& args = inst.args.args_1n;
				os << ' ' << args.operands[0];
				break;
			}
			// No arguments
			case operation::NOP:
			case operation::RET:
			case operation::PUSHA:
			case operation::POPA:
			case operation::PUSHF:
			case operation::POPF:
			case operation::CLC:
			case operation::STC:
			case operation::HLT:
				break;
		}
		return os;
	}
	inline uint32_t instruction_t::get_size() const {
		switch (op) {
			// One read only memory, one read & write (LEA)
			case operation::LEA:
				return args.args_1r_mem.get_size() + 1;
			// One read only, one read & write
			case operation::MOV:
			case operation::MOVSX:
			case operation::MOVZX:
			case operation::ADD:
			case operation::ADC:
			case operation::SUB:
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
				return args.args_1r.get_size() + 1;
			// Two read only
			case operation::CMP:
			case operation::TEST:
				return args.args_2n.get_size() + 1;
			// One read & write
			case operation::NOT:
			case operation::NEG:
			case operation::INC:
			case operation::DEC:
			case operation::POP:
			case operation::IN:
				return args.args_0r.get_size() + 1;
			// One read only
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
				return args.args_1n.get_size() + 1;
			// No arguments
			case operation::NOP:
			case operation::RET:
			case operation::PUSHA:
			case operation::POPA:
			case operation::PUSHF:
			case operation::POPF:
			case operation::CLC:
			case operation::STC:
			case operation::HLT:
				return 1;
		}
		return 1; // Default to 1 byte for unrecognized operations
	}
} // namespace machine

template<>
struct std::formatter<machine::operation> : std::formatter<std::string> {
	auto format(const machine::operation& op, auto& ctx) const {
		return std::formatter<std::string>::format(machine::operation_to_string(op), ctx);
	}
};
