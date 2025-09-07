#pragma once
#include "ram.hpp"
#include "register.hpp"
#ifndef MACHINE_INSTRUCTION
#define MACHINE_INSTRUCTION
#endif

#include <cstdint>
#include <string>

namespace machine {
	enum class operation : uint8_t {
		// No Operation
		NOP = 0,

		// Data Movement
		MOV,
		PUSH,
		POP,
		LEA,

		// Arithmetic
		ADD,
		SUB,
		MUL, // unsigned
		IMUL, // signed
		DIV, // unsigned
		IDIV, // signed
		MOD, // unsigned
		IMOD, // signed
		INC,
		DEC,
		NEG,
		ADC, // Add with Carry
		SBB, // Subtract with Borrow
		CMP,

		// Bitwise Operations
		AND,
		OR,
		XOR,
		NOT,
		SHL,
		SHR,
		SAR, // Shift Arithmetic Right
		ROL,
		ROR,
		RCL, // Rotate through Carry Left
		RCR, // Rotate through Carry Right
		TEST,

		// Control Flow
		JMP,
		// Flag checks
		// Zero / Equal
		JZ,
		JE = JZ,
		JNZ,
		JNE = JNZ,
		// Carry
		JC,
		JNC,
		// Overflow
		JO,
		JNO,
		// Parity
		JP,
		JNP,
		// Sign
		JS,
		JNS,
		// Comparisons
		JG,
		JGE,
		JL,
		JLE,
		JA,
		JAE,
		JB,
		JBE,
		// Calls and Returns
		CALL,
		RET,
		// Stack Operations
		PUSHA, // Push All General-Purpose Registers
		POPA, // Pop All General-Purpose Registers
		PUSHF, // Push Flags Register
		POPF, // Pop Flags Register
		// Miscellaneous
		CLC, // Clear Carry Flag
		STC, // Set Carry Flag
		HLT, // Halt
		// Input/Output
		IN,
		OUT
	};

	inline std::ostream& operator<<(std::ostream& os, const operation& op);
	inline std::string operation_to_string(operation op);
	inline operation operation_from_string(const std::string& str);

	struct memory_operand {
		enum class type : uint8_t {
			DIRECT, // [address]
			REGISTER, // [register]
			DISPLACEMENT, // [base + disp]
			SCALED_INDEX, // [base + index * scale]
			SCALED_INDEX_DISPLACEMENT // [base + index * scale + disp]
		} memory_type;
		struct displacement {
			register_t base;
			int32_t disp;
		};
		struct scaled_index {
			register_t base;
			register_t index;
			int8_t scale; // 1, 2, 4, or 8
		};
		struct scaled_index_displacement {
			register_t base;
			register_t index;
			int8_t scale; // 1, 2, 4, or 8
			int32_t disp;
		};
		union {
			uint32_t direct_address; // For DIRECT type
			register_t reg; // For REGISTER type
			displacement disp; // For DISPLACEMENT type
			scaled_index s_index; // For SCALED_INDEX type
			scaled_index_displacement s_index_disp; // For SCALED_INDEX_DISPLACEMENT type
		} value;
		data_size_t size;
		explicit memory_operand(uint32_t addr, data_size_t sz = data_size_t::DWORD)
			: memory_type(type::DIRECT), value(addr), size(sz) {
		}
		explicit memory_operand(register_t r, data_size_t sz = data_size_t::DWORD)
			: memory_type(type::REGISTER), value({.reg = r}), size(sz) {
		}
		memory_operand(register_t base, int32_t disp, data_size_t sz = data_size_t::DWORD)
			: memory_type(type::DISPLACEMENT), value({.disp = {base, disp}}), size(sz) {
		}
		memory_operand(register_t base, register_t index, int8_t scale, data_size_t sz = data_size_t::DWORD)
			: memory_type(type::SCALED_INDEX), value({.s_index = {base, index, scale}}), size(sz) {
		}
		memory_operand(register_t base, register_t index, int8_t scale, int32_t disp, data_size_t sz = data_size_t::DWORD)
			: memory_type(type::SCALED_INDEX_DISPLACEMENT), value({.s_index_disp = {base, index, scale, disp}}), size(sz) {
		}

		friend std::ostream& operator<<(std::ostream& os, const memory_operand& mem);
	};
	struct operand_arg {
		enum class type_t : uint8_t {
			REGISTER = 0,
			IMMEDIATE,
			MEMORY
		} type;
		union {
			register_t reg;
			int32_t imm;
			memory_operand mem;
		} value;

		friend std::ostream& operator<<(std::ostream& os, const operand_arg& arg);
	};
	struct result_arg {
		enum class type_t : uint8_t {
			REGISTER = 0,
			MEMORY
		} type;
		union {
			register_t reg;
			memory_operand mem;
		} value;

		friend std::ostream& operator<<(std::ostream& os, const result_arg& res);
	};
	template<size_t N, bool R>
	struct args_t {
		std::array<operand_arg, N> operands;
		std::conditional_t<R, result_arg, std::monostate> result;
		args_t() : operands{}, result{} {
		}
		args_t(const std::array<operand_arg, N>& ops, result_arg res)
			: operands(ops), result(res) {
			static_assert(R, "Result provided for args_t with R == false");
		}
		args_t(const std::array<operand_arg, N>& ops)
			: operands(ops), result(std::monostate{}) {
			static_assert(!R, "No result provided for args_t with R == true");
		}
	};
	struct instruction_t {
		operation op;
		union {
			args_t<2, true> args_2r;
			args_t<2, false> args_2n;
			args_t<1, true> args_1r;
			args_t<1, false> args_1n;
			args_t<0, true> args_0r;
			args_t<0, false> args_0n;
		} args;

		instruction_t() : op(operation::NOP), args{.args_0n = {}} {
		}
		instruction_t(const operation oper, const args_t<2, true>& a)
			: op(oper), args{.args_2r = a} {
		}
		instruction_t(const operation oper, const args_t<2, false>& a)
			: op(oper), args{.args_2n = a} {
		}
		instruction_t(const operation oper, const args_t<1, true>& a)
			: op(oper), args{.args_1r = a} {
		}
		instruction_t(const operation oper, const args_t<1, false>& a)
			: op(oper), args{.args_1n = a} {
		}
		instruction_t(const operation oper, const args_t<0, true>& a)
			: op(oper), args{.args_0r = a} {
		}
		instruction_t(const operation oper, const args_t<0, false>& a)
			: op(oper), args{.args_0n = a} {
		}

		friend std::ostream& operator<<(std::ostream& os, const instruction_t& inst);
	};
	typedef std::vector<instruction_t> program_t;
}

#include "instruction.inl"
