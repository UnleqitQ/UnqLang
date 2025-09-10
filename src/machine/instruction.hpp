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
		explicit memory_operand(uint32_t addr)
			: memory_type(type::DIRECT), value(addr) {
		}
		explicit memory_operand(register_t r)
			: memory_type(type::REGISTER), value({.reg = r}) {
		}
		memory_operand(register_t base, int32_t disp)
			: memory_type(type::DISPLACEMENT), value({.disp = {base, disp}}) {
		}
		memory_operand(register_t base, register_t index, int8_t scale)
			: memory_type(type::SCALED_INDEX), value({.s_index = {base, index, scale}}) {
		}
		memory_operand(register_t base, register_t index, int8_t scale, int32_t disp)
			: memory_type(type::SCALED_INDEX_DISPLACEMENT), value({.s_index_disp = {base, index, scale, disp}}) {
		}

		friend std::ostream& operator<<(std::ostream& os, const memory_operand& mem);

		uint32_t get_size() const {
			switch (memory_type) {
				case type::DIRECT:
					return 4; // int32 (4 bytes)
				case type::REGISTER:
					return 1; // register (1 byte)
				case type::DISPLACEMENT:
					return 1 + 4; // register (1 byte) + int32 (4 bytes)
				case type::SCALED_INDEX:
					return 1 + 1 + 1; // base register (1 byte) + index register (1 byte) + scale (1 byte)
				case type::SCALED_INDEX_DISPLACEMENT:
					return 1 + 1 + 1 + 4; // base register (1 byte) + index register (1 byte) + scale (1 byte) + int32 (4 bytes)
				default:
					throw std::runtime_error("Unknown memory operand type");
			}
		}
	};
	struct memory_pointer_operand {
		data_size_t size;
		memory_operand memory;
		memory_pointer_operand(data_size_t sz, const memory_operand& mem)
			: size(sz), memory(mem) {
		}
		friend std::ostream& operator<<(std::ostream& os, const memory_pointer_operand& mem) {
			os << mem.size << " PTR " << mem.memory;
			return os;
		}

		uint32_t get_size() const {
			return memory.get_size() + 1; // +1 for the size and type byte
		}
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
			memory_pointer_operand mem;
		} value;

		friend std::ostream& operator<<(std::ostream& os, const operand_arg& arg);

		uint32_t get_size() const {
			switch (type) {
				case type_t::REGISTER:
					return 1; // register (1 byte)
				case type_t::IMMEDIATE:
					return 4; // int32 (4 bytes)
				case type_t::MEMORY:
					return value.mem.get_size();
				default:
					throw std::runtime_error("Unknown operand type");
			}
		}
	};
	struct result_arg {
		enum class type_t : uint8_t {
			REGISTER = 0,
			MEMORY,
			UNDEFINED = 255
		} type;
		union {
			std::monostate none;
			register_t reg;
			memory_pointer_operand mem;
		} value;

		result_arg() : type(type_t::UNDEFINED), value{} {
		}

		explicit result_arg(register_t r)
			: type(type_t::REGISTER), value{.reg = r} {
		}
		explicit result_arg(const memory_pointer_operand& m)
			: type(type_t::MEMORY), value{.mem = m} {
		}
		explicit operator bool() const {
			return type != type_t::UNDEFINED;
		}
		friend std::ostream& operator<<(std::ostream& os, const result_arg& res);

		uint32_t get_size() const {
			switch (type) {
				case type_t::REGISTER:
					return 1; // register (1 byte)
				case type_t::MEMORY:
					return value.mem.get_size();
				case type_t::UNDEFINED:
					return 0;
				default:
					throw std::runtime_error("Unknown result type");
			}
		}
	};
	template<size_t N, bool R, typename O = operand_arg>
	struct args_t {
		std::array<O, N> operands;
		std::conditional_t<R, result_arg, std::monostate> result;
		args_t() : operands{}, result{} {
		}
		args_t(const std::array<O, N>& ops, result_arg res)
			: operands(ops), result(res) {
			static_assert(R, "Result provided for args_t with R == false");
		}
		args_t(const std::array<O, N>& ops)
			: operands(ops), result(std::monostate{}) {
			static_assert(!R, "No result provided for args_t with R == true");
		}

		uint32_t get_size() const;
	};
	template<>
	inline uint32_t args_t<0, false>::get_size() const {
		return 0;
	}
	template<>
	inline uint32_t args_t<0, true>::get_size() const {
		return result.get_size();
	}
	template<>
	inline uint32_t args_t<1, false>::get_size() const {
		return operands[0].get_size() + 1;
	}
	template<>
	inline uint32_t args_t<1, true>::get_size() const {
		return operands[0].get_size() + result.get_size() + 1;
	}
	template<>
	inline uint32_t args_t<2, false>::get_size() const {
		return operands[0].get_size() + operands[1].get_size() + 1;
	}
	template<>
	inline uint32_t args_t<1, true, memory_operand>::get_size() const {
		return operands[0].get_size() + result.get_size() + 1;
	}
	struct instruction_t {
		operation op;
		union {
			args_t<2, false> args_2n;
			args_t<1, true> args_1r;
			args_t<1, false> args_1n;
			args_t<0, true> args_0r;
			args_t<0, false> args_0n;
			args_t<1, true, memory_operand> args_1r_mem;
		} args;

		instruction_t() : op(operation::NOP), args{.args_0n = {}} {
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
		instruction_t(const operation oper, const args_t<1, true, memory_operand>& a)
			: op(oper), args{.args_1r_mem = a} {
		}

		friend std::ostream& operator<<(std::ostream& os, const instruction_t& inst);

		uint32_t get_size() const;
	};
	typedef std::vector<instruction_t> program_t;
}

#include "instruction.inl"
