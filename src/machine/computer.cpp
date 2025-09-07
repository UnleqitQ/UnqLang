#include "computer.hpp"

namespace machine {
	data_size_t get_size_from_access(register_access access) {
		switch (access) {
			case register_access::dword:
				return data_size_t::DWORD;
			case register_access::word:
				return data_size_t::WORD;
			case register_access::low_byte:
			case register_access::high_byte:
				return data_size_t::BYTE;
			default:
				throw std::runtime_error("Invalid register access type");
		}
	}

	uint8_t get_size_in_bytes(data_size_t size) {
		switch (size) {
			case data_size_t::BYTE:
				return 1;
			case data_size_t::WORD:
				return 2;
			case data_size_t::DWORD:
				return 4;
			default:
				throw std::runtime_error("Invalid data size");
		}
	}

	bool get_parity(uint8_t value) {
		value ^= value >> 4;
		value ^= value >> 2;
		value ^= value >> 1;
		return (value & 1) == 0;
	}

	bool check_jump_condition(operation op, const register_file& regs) {
		switch (op) {
			case operation::JMP:
				return true;
			case operation::JZ:
				return regs.flags.zf;
			case operation::JNZ:
				return !regs.flags.zf;
			case operation::JC:
				return regs.flags.cf;
			case operation::JNC:
				return !regs.flags.cf;
			case operation::JO:
				return regs.flags.of;
			case operation::JNO:
				return !regs.flags.of;
			case operation::JS:
				return regs.flags.sf;
			case operation::JNS:
				return !regs.flags.sf;
			case operation::JP:
				return regs.flags.pf;
			case operation::JNP:
				return !regs.flags.pf;

			case operation::JG:
				return !regs.flags.zf && (regs.flags.sf == regs.flags.of);
			case operation::JL:
				return regs.flags.sf != regs.flags.of;
			case operation::JGE:
				return regs.flags.sf == regs.flags.of;
			case operation::JLE:
				return regs.flags.zf || (regs.flags.sf != regs.flags.of);

			case operation::JA:
				return !regs.flags.cf && !regs.flags.zf;
			case operation::JAE:
				return !regs.flags.cf;
			case operation::JB:
				return regs.flags.cf;
			case operation::JBE:
				return regs.flags.cf || regs.flags.zf;
			default:
				throw std::runtime_error("Invalid jump operation");
		}
	}

	void push_stack(register_file& regs, ram& memory, uint32_t value, data_size_t size) {
		regs.esp -= get_size_in_bytes(size);
		switch (size) {
			case data_size_t::BYTE:
				memory.write8(regs.esp, static_cast<uint8_t>(value & 0xFF));
				break;
			case data_size_t::WORD:
				memory.write16(regs.esp, static_cast<uint16_t>(value & 0xFFFF));
				break;
			case data_size_t::DWORD:
				memory.write32(regs.esp, value);
				break;
			default:
				throw std::runtime_error("Invalid data size for stack push");
		}
	}
	uint32_t pop_stack(register_file& regs, ram& memory, data_size_t size) {
		uint32_t value;
		switch (size) {
			case data_size_t::BYTE:
				value = memory.read8(regs.esp);
				break;
			case data_size_t::WORD:
				value = memory.read16(regs.esp);
				break;
			case data_size_t::DWORD:
				value = memory.read32(regs.esp);
				break;
			default:
				throw std::runtime_error("Invalid data size for stack pop");
		}
		regs.esp += get_size_in_bytes(size);
		return value;
	}

	uint32_t handle_add(bool with_carry, uint32_t val1, uint32_t val2, data_size_t size, register_file& regs) {
		uint64_t carry_in = with_carry && regs.flags.cf ? 1 : 0;
		uint64_t result = static_cast<uint64_t>(val1) + static_cast<uint64_t>(val2) + carry_in;
		uint32_t mask;
		switch (size) {
			case data_size_t::BYTE:
				mask = 0xFF;
				break;
			case data_size_t::WORD:
				mask = 0xFFFF;
				break;
			case data_size_t::DWORD:
				mask = 0xFFFFFFFF;
				break;
			default:
				throw std::runtime_error("Invalid data size");
		}
		uint32_t res32 = static_cast<uint32_t>(result & mask);

		// Set flags
		regs.flags.cf = (result >> (get_size_in_bytes(size) * 8)) != 0; // Carry flag
		regs.flags.zf = (res32 & mask) == 0; // Zero flag
		regs.flags.sf = (res32 & (1 << ((get_size_in_bytes(size) * 8) - 1))) != 0; // Sign flag
		// Overflow flag (set if the sign of the result is incorrect for signed addition)
		regs.flags.of = ((val1 ^ res32) & (val2 ^ res32) & (1 << ((get_size_in_bytes(size) * 8) - 1))) != 0;
		// Auxiliary flag (set if there is a carry from bit 3 to bit 4)
		regs.flags.af = ((val1 & 0xF) + (val2 & 0xF) + carry_in) > 0xF;
		// Parity flag (set if the number of set bits in the least significant byte is even)
		regs.flags.pf = get_parity(res32 & 0xFF);

		return res32;
	}
	uint32_t handle_sub(bool with_borrow, uint32_t val1, uint32_t val2, data_size_t size, register_file& regs) {
		uint64_t borrow_in = with_borrow && regs.flags.cf ? 1 : 0;
		uint64_t result = static_cast<uint64_t>(val1) - static_cast<uint64_t>(val2) - borrow_in;
		uint32_t mask;
		switch (size) {
			case data_size_t::BYTE:
				mask = 0xFF;
				break;
			case data_size_t::WORD:
				mask = 0xFFFF;
				break;
			case data_size_t::DWORD:
				mask = 0xFFFFFFFF;
				break;
			default:
				throw std::runtime_error("Invalid data size");
		}
		uint32_t res32 = static_cast<uint32_t>(result & mask);
		// Set flags
		regs.flags.cf = (result >> (get_size_in_bytes(size) * 8)) != 0; // Carry flag (borrow)
		regs.flags.zf = (res32 & mask) == 0; // Zero flag
		regs.flags.sf = (res32 & (1 << ((get_size_in_bytes(size) * 8) - 1))) != 0; // Sign flag
		// Overflow flag (set if the sign of the result is incorrect for signed subtraction)
		regs.flags.of = ((val1 ^ val2) & (val1 ^ res32) & (1 << ((get_size_in_bytes(size) * 8) - 1))) != 0;
		// Auxiliary flag (set if there is a borrow from bit 4 to bit 3)
		regs.flags.af = ((val1 & 0xF) < (val2 & 0xF) + borrow_in);
		// Parity flag (set if the number of set bits in the least significant byte is even)
		regs.flags.pf = get_parity(res32 & 0xFF);

		return res32;
	}
	uint32_t handle_mul(bool is_signed, uint32_t val1, uint32_t val2, data_size_t size, register_file& regs) {
		uint64_t result;
		if (is_signed) {
			int64_t s_val1 = static_cast<int32_t>(val1);
			int64_t s_val2 = static_cast<int32_t>(val2);
			result = static_cast<uint64_t>(s_val1 * s_val2);
		}
		else {
			result = static_cast<uint64_t>(val1) * static_cast<uint64_t>(val2);
		}
		uint32_t mask;
		switch (size) {
			case data_size_t::BYTE:
				mask = 0xFF;
				break;
			case data_size_t::WORD:
				mask = 0xFFFF;
				break;
			case data_size_t::DWORD:
				mask = 0xFFFFFFFF;
				break;
			default:
				throw std::runtime_error("Invalid data size");
		}
		uint32_t res32 = static_cast<uint32_t>(result & mask);
		// Set flags
		regs.flags.cf = (result >> (get_size_in_bytes(size) * 8)) != 0; // Carry flag
		regs.flags.of = regs.flags.cf; // Overflow flag is the same as carry flag
		regs.flags.zf = (res32 & mask) == 0; // Zero flag
		regs.flags.sf = (res32 & (1 << ((get_size_in_bytes(size) * 8) - 1))) != 0; // Sign flag
		// Parity flag (set if the number of set bits in the least significant byte is even)
		regs.flags.pf = get_parity(res32 & 0xFF);
		// AF is undefined for MUL

		return res32;
	}
	uint32_t handle_div(bool is_signed, uint32_t dividend, uint32_t divisor, data_size_t size, register_file& regs) {
		if (divisor == 0) {
			throw std::runtime_error("Division by zero");
		}
		uint32_t quotient;
		if (is_signed) {
			int32_t s_dividend = static_cast<int32_t>(dividend);
			int32_t s_divisor = static_cast<int32_t>(divisor);
			quotient = static_cast<uint32_t>(s_dividend / s_divisor);
		}
		else {
			quotient = dividend / divisor;
		}
		uint32_t mask;
		switch (size) {
			case data_size_t::BYTE:
				mask = 0xFF;
				break;
			case data_size_t::WORD:
				mask = 0xFFFF;
				break;
			case data_size_t::DWORD:
				mask = 0xFFFFFFFF;
				break;
			default:
				throw std::runtime_error("Invalid data size");
		}
		if ((quotient & ~mask) != 0) {
			throw std::runtime_error("Quotient overflow");
		}
		uint32_t res32 = quotient & mask;
		// Set flags
		regs.flags.cf = false; // Carry flag is cleared
		regs.flags.of = false; // Overflow flag is cleared
		regs.flags.zf = (res32 & mask) == 0; // Zero flag
		regs.flags.sf = (res32 & (1 << ((get_size_in_bytes(size) * 8) - 1))) != 0; // Sign flag
		// Parity flag (set if the number of set bits in the least significant byte is even)
		regs.flags.pf = get_parity(res32 & 0xFF);
		// AF is undefined for DIV

		return res32;
	}
	uint32_t handle_mod(bool is_signed, uint32_t dividend, uint32_t divisor, data_size_t size, register_file& regs) {
		if (divisor == 0) {
			throw std::runtime_error("Division by zero");
		}
		uint32_t remainder;
		if (is_signed) {
			int32_t s_dividend = static_cast<int32_t>(dividend);
			int32_t s_divisor = static_cast<int32_t>(divisor);
			remainder = static_cast<uint32_t>(s_dividend % s_divisor);
		}
		else {
			remainder = dividend % divisor;
		}
		uint32_t mask;
		switch (size) {
			case data_size_t::BYTE:
				mask = 0xFF;
				break;
			case data_size_t::WORD:
				mask = 0xFFFF;
				break;
			case data_size_t::DWORD:
				mask = 0xFFFFFFFF;
				break;
			default:
				throw std::runtime_error("Invalid data size");
		}
		uint32_t res32 = remainder & mask;
		// Set flags
		regs.flags.cf = false; // Carry flag is cleared
		regs.flags.of = false; // Overflow flag is cleared
		regs.flags.zf = (res32 & mask) == 0; // Zero flag
		regs.flags.sf = (res32 & (1 << ((get_size_in_bytes(size) * 8) - 1))) != 0; // Sign flag
		// Parity flag (set if the number of set bits in the least significant byte is even)
		regs.flags.pf = get_parity(res32 & 0xFF);
		// AF is undefined for MOD

		return res32;
	}
	uint32_t handle_logical(operation op, uint32_t val1, uint32_t val2, data_size_t size, register_file& regs) {
		uint32_t result;
		switch (op) {
			case operation::AND:
				result = val1 & val2;
				break;
			case operation::OR:
				result = val1 | val2;
				break;
			case operation::XOR:
				result = val1 ^ val2;
				break;
			default:
				throw std::runtime_error("Invalid logical operation");
		}
		uint32_t mask;
		switch (size) {
			case data_size_t::BYTE:
				mask = 0xFF;
				break;
			case data_size_t::WORD:
				mask = 0xFFFF;
				break;
			case data_size_t::DWORD:
				mask = 0xFFFFFFFF;
				break;
			default:
				throw std::runtime_error("Invalid data size");
		}
		uint32_t res32 = result & mask;
		// Set flags
		regs.flags.cf = false; // Carry flag is cleared
		regs.flags.of = false; // Overflow flag is cleared
		regs.flags.zf = (res32 & mask) == 0; // Zero flag
		regs.flags.sf = (res32 & (1 << ((get_size_in_bytes(size) * 8) - 1))) != 0; // Sign flag
		// Parity flag (set if the number of set bits in the least significant byte is even)
		regs.flags.pf = get_parity(res32 & 0xFF);
		// AF is undefined for logical operations

		return res32;
	}
	uint32_t handle_shift(operation op, uint32_t value, uint32_t count, data_size_t size, register_file& regs) {
		if (count == 0) {
			return value; // No change
		}
		uint32_t result;
		switch (op) {
			case operation::SHL:
				result = value << count;
				regs.flags.cf = (value >> (get_size_in_bytes(size) * 8 - count)) & 1; // Last bit shifted out
				break;
			case operation::SHR:
				result = value >> count;
				regs.flags.cf = (value >> (count - 1)) & 1; // Last bit shifted out
				break;
			case operation::SAR: {
				int32_t s_value = static_cast<int32_t>(value);
				result = static_cast<uint32_t>(s_value >> count);
				regs.flags.cf = (value >> (count - 1)) & 1; // Last bit shifted out
				break;
			}
			default:
				throw std::runtime_error("Invalid shift operation");
		}
		uint32_t mask;
		switch (size) {
			case data_size_t::BYTE:
				mask = 0xFF;
				break;
			case data_size_t::WORD:
				mask = 0xFFFF;
				break;
			case data_size_t::DWORD:
				mask = 0xFFFFFFFF;
				break;
			default:
				throw std::runtime_error("Invalid data size");
		}
		uint32_t res32 = result & mask;
		// Set flags
		regs.flags.zf = (res32 & mask) == 0; // Zero flag
		regs.flags.sf = (res32 & (1 << ((get_size_in_bytes(size) * 8) - 1))) != 0; // Sign flag
		// Parity flag (set if the number of set bits in the least significant byte is even)
		regs.flags.pf = get_parity(res32 & 0xFF);
		// OF is affected only for single-bit shifts
		if (count == 1) {
			switch (op) {
				case operation::SHL:
					regs.flags.of = ((res32 & (1 << ((get_size_in_bytes(size) * 8) - 1))) != 0) != ((value & (1 << ((
						get_size_in_bytes(size) * 8) - 1))) != 0);
					break;
				case operation::SHR:
				case operation::SAR:
					regs.flags.of = false;
					break;
				default:
					break;
			}
		}
		// AF is undefined for shift operations
		return res32;
	}
	uint32_t handle_rotate(operation op, uint32_t value, uint32_t count, data_size_t size, register_file& regs) {
		if (count == 0) {
			return value; // No change
		}
		uint32_t mask;
		switch (size) {
			case data_size_t::BYTE:
				mask = 0xFF;
				break;
			case data_size_t::WORD:
				mask = 0xFFFF;
				break;
			case data_size_t::DWORD:
				mask = 0xFFFFFFFF;
				break;
			default:
				throw std::runtime_error("Invalid data size");
		}
		count %= (get_size_in_bytes(size) * 8); // Normalize count
		uint32_t result;
		switch (op) {
			case operation::ROL:
				result = ((value << count) | (value >> ((get_size_in_bytes(size) * 8) - count))) & mask;
				regs.flags.cf = (result & 1) != 0; // Last bit rotated out
				break;
			case operation::ROR:
				result = ((value >> count) | (value << ((get_size_in_bytes(size) * 8) - count))) & mask;
				regs.flags.cf = (result & (1 << ((get_size_in_bytes(size) * 8) - 1))) != 0; // Last bit rotated out
				break;
			default:
				throw std::runtime_error("Invalid rotate operation");
		}
		uint32_t res32 = result & mask;
		// Set flags
		regs.flags.zf = (res32 & mask) == 0; // Zero flag
		regs.flags.sf = (res32 & (1 << ((get_size_in_bytes(size) * 8) - 1))) != 0; // Sign flag
		// Parity flag (set if the number of set bits in the least significant byte is even)
		regs.flags.pf = get_parity(res32 & 0xFF);
		// OF is affected only for single-bit rotates
		if (count == 1) {
			switch (op) {
				case operation::ROL:
					regs.flags.of = ((res32 & (1 << ((get_size_in_bytes(size) * 8) - 1))) != 0) != regs.flags.cf;
					break;
				case operation::ROR:
					regs.flags.of = ((value & 1) != 0) != ((value & (1 << ((get_size_in_bytes(size) * 8) - 1))) != 0);
					break;
				default:
					break;
			}
		}
		// AF is undefined for rotate operations
		return res32;
	}

	data_size_t get_result_size(const result_arg& res) {
		switch (res.type) {
			case result_arg::type_t::REGISTER:
				return get_size_from_access(res.value.reg.access);
			case result_arg::type_t::MEMORY:
				return res.value.mem.size;
			default:
				throw std::runtime_error("Invalid result type");
		}
	}

	uint32_t computer::retrieve_memory_address(const memory_operand& mem_op) const {
		switch (mem_op.memory_type) {
			case memory_operand::type::DIRECT:
				return mem_op.value.direct_address;
			case memory_operand::type::REGISTER:
				return m_registers.get(mem_op.value.reg);
			case memory_operand::type::DISPLACEMENT: {
				uint32_t base_addr = m_registers.get(mem_op.value.disp.base);
				return base_addr + mem_op.value.disp.disp;
			}
			case memory_operand::type::SCALED_INDEX: {
				uint32_t base_addr = m_registers.get(mem_op.value.s_index.base);
				uint32_t index_val = m_registers.get(mem_op.value.s_index.index);
				return base_addr + (index_val * mem_op.value.s_index.scale);
			}
			case memory_operand::type::SCALED_INDEX_DISPLACEMENT: {
				uint32_t base_addr = m_registers.get(mem_op.value.s_index_disp.base);
				uint32_t index_val = m_registers.get(mem_op.value.s_index_disp.index);
				return base_addr + (index_val * mem_op.value.s_index_disp.scale) + mem_op.value.s_index_disp.disp;
			}
			default:
				throw std::runtime_error("Invalid memory operand type");
		}
	}
	uint32_t computer::retrieve_operand_value(const operand_arg& op) const {
		switch (op.type) {
			case operand_arg::type_t::REGISTER:
				return m_registers.get(op.value.reg);
			case operand_arg::type_t::IMMEDIATE:
				return op.value.imm;
			case operand_arg::type_t::MEMORY: {
				uint32_t addr = retrieve_memory_address(op.value.mem);
				switch (op.value.mem.size) {
					case data_size_t::BYTE:
						return static_cast<int32_t>(m_ram.read8(addr));
					case data_size_t::WORD:
						return static_cast<int32_t>(m_ram.read16(addr));
					case data_size_t::DWORD:
						return static_cast<int32_t>(m_ram.read32(addr));
					default:
						throw std::runtime_error("Invalid data size for memory read");
				}
			}
			default:
				throw std::runtime_error("Invalid operand type");
		}
	}
	uint32_t computer::retrieve_result_value(const result_arg& res) const {
		switch (res.type) {
			case result_arg::type_t::REGISTER:
				return m_registers.get(res.value.reg);
			case result_arg::type_t::MEMORY: {
				uint32_t addr = retrieve_memory_address(res.value.mem);
				switch (res.value.mem.size) {
					case data_size_t::BYTE:
						return static_cast<int32_t>(m_ram.read8(addr));
					case data_size_t::WORD:
						return static_cast<int32_t>(m_ram.read16(addr));
					case data_size_t::DWORD:
						return static_cast<int32_t>(m_ram.read32(addr));
					default:
						throw std::runtime_error("Invalid data size for memory read");
				}
			}
			default:
				throw std::runtime_error("Invalid result type");
		}
	}
	void computer::set_result_value(const result_arg& res, uint32_t value) {
		switch (res.type) {
			case result_arg::type_t::REGISTER:
				m_registers.set(res.value.reg, value);
				break;
			case result_arg::type_t::MEMORY: {
				uint32_t addr = retrieve_memory_address(res.value.mem);
				switch (res.value.mem.size) {
					case data_size_t::BYTE:
						m_ram.write8(addr, static_cast<uint8_t>(value));
						break;
					case data_size_t::WORD:
						m_ram.write16(addr, static_cast<uint16_t>(value));
						break;
					case data_size_t::DWORD:
						m_ram.write32(addr, value);
						break;
					default:
						throw std::runtime_error("Invalid data size for memory write");
				}
				break;
			}
			default:
				throw std::runtime_error("Invalid result type");
		}
	}
	void computer::execute_instruction(const instruction_t& instr) {
		bool jump_occurred = false;
		switch (instr.op) {
			case operation::NOP:
				// Do nothing
				break;
			case operation::MOV: {
				const auto args = instr.args.args_1r;
				uint32_t value = retrieve_operand_value(args.operands[0]);
				set_result_value(args.result, value);
				break;
			}
			case operation::ADC:
			case operation::ADD: {
				const auto args = instr.args.args_1r;
				uint32_t val1 = retrieve_result_value(args.result);
				uint32_t val2 = retrieve_operand_value(args.operands[0]);
				data_size_t size = get_result_size(args.result);
				uint32_t result = handle_add(instr.op == operation::ADC, val1, val2, size, m_registers);
				set_result_value(args.result, result);
				break;
			}
			case operation::SBB:
			case operation::SUB: {
				const auto args = instr.args.args_1r;
				uint32_t val1 = retrieve_result_value(args.result);
				uint32_t val2 = retrieve_operand_value(args.operands[0]);
				data_size_t size = get_result_size(args.result);
				uint32_t result = handle_sub(instr.op == operation::SBB, val1, val2, size, m_registers);
				set_result_value(args.result, result);
				break;
			}
			case operation::MUL:
			case operation::IMUL: {
				const auto args = instr.args.args_1r;
				int32_t val1 = retrieve_result_value(args.result);
				int32_t val2 = retrieve_operand_value(args.operands[0]);
				data_size_t size = get_result_size(args.result);
				uint32_t result = handle_mul(instr.op == operation::IMUL, val1, val2, size, m_registers);
				set_result_value(args.result, result);
				break;
			}
			case operation::DIV:
			case operation::IDIV: {
				const auto args = instr.args.args_1r;
				int32_t dividend = retrieve_result_value(args.result);
				int32_t divisor = retrieve_operand_value(args.operands[0]);
				data_size_t size = get_result_size(args.result);
				uint32_t result = handle_div(instr.op == operation::IDIV, dividend, divisor, size, m_registers);
				set_result_value(args.result, result);
				break;
			}
			case operation::MOD:
			case operation::IMOD: {
				const auto args = instr.args.args_1r;
				int32_t dividend = retrieve_result_value(args.result);
				int32_t divisor = retrieve_operand_value(args.operands[0]);
				data_size_t size = get_result_size(args.result);
				uint32_t result = handle_mod(instr.op == operation::IMOD, dividend, divisor, size, m_registers);
				set_result_value(args.result, result);
				break;
			}
			case operation::PUSH: {
				const auto args = instr.args.args_1n;
				uint32_t value = retrieve_operand_value(args.operands[0]);
				data_size_t size;
				if (args.operands[0].type == operand_arg::type_t::REGISTER) {
					size = get_size_from_access(args.operands[0].value.reg.access);
				}
				else if (args.operands[0].type == operand_arg::type_t::MEMORY) {
					size = args.operands[0].value.mem.size;
				}
				else {
					size = data_size_t::DWORD; // Immediate values are treated as DWORD
				}
				push_stack(m_registers, m_ram, value, size);
				break;
			}
			case operation::POP: {
				const auto args = instr.args.args_0r;
				data_size_t size = get_result_size(args.result);
				uint32_t value = pop_stack(m_registers, m_ram, size);
				set_result_value(args.result, value);
				break;
			}
			case operation::LEA: {
				const auto args = instr.args.args_1r;
				if (args.operands[0].type != operand_arg::type_t::MEMORY) {
					throw std::runtime_error("LEA requires a memory operand");
				}
				uint32_t addr = retrieve_memory_address(args.operands[0].value.mem);
				set_result_value(args.result, addr);
				break;
			}
			case operation::INC: {
				const auto args = instr.args.args_0r;
				uint32_t val = retrieve_result_value(args.result);
				data_size_t size = get_result_size(args.result);
				uint32_t result = handle_add(false, val, 1, size, m_registers);
				set_result_value(args.result, result);
				break;
			}
			case operation::DEC: {
				const auto args = instr.args.args_0r;
				uint32_t val = retrieve_result_value(args.result);
				data_size_t size = get_result_size(args.result);
				uint32_t result = handle_sub(false, val, 1, size, m_registers);
				set_result_value(args.result, result);
				break;
			}
			case operation::NEG: {
				const auto args = instr.args.args_0r;
				uint32_t val = retrieve_result_value(args.result);
				data_size_t size = get_result_size(args.result);
				uint32_t result = handle_sub(false, 0, val, size, m_registers);
				m_registers.flags.cf = val != 0; // Set CF if operand was non-zero
				set_result_value(args.result, result);
				break;
			}
			case operation::CMP: {
				const auto args = instr.args.args_2n;
				uint32_t val1 = retrieve_operand_value(args.operands[0]);
				uint32_t val2 = retrieve_operand_value(args.operands[1]);
				data_size_t size = data_size_t::DWORD;
				if (args.operands[0].type != operand_arg::type_t::IMMEDIATE && args.operands[1].type !=
					operand_arg::type_t::IMMEDIATE) {
					size = std::min(
						(args.operands[0].type == operand_arg::type_t::REGISTER)
						? get_size_from_access(args.operands[0].value.reg.access)
						: args.operands[0].value.mem.size,
						(args.operands[1].type == operand_arg::type_t::REGISTER)
						? get_size_from_access(args.operands[1].value.reg.access)
						: args.operands[1].value.mem.size);
				}
				else if (args.operands[0].type != operand_arg::type_t::IMMEDIATE) {
					size = (args.operands[0].type == operand_arg::type_t::REGISTER)
						? get_size_from_access(args.operands[0].value.reg.access)
						: args.operands[0].value.mem.size;
				}
				else if (args.operands[1].type != operand_arg::type_t::IMMEDIATE) {
					size = (args.operands[1].type == operand_arg::type_t::REGISTER)
						? get_size_from_access(args.operands[1].value.reg.access)
						: args.operands[1].value.mem.size;
				}
				handle_sub(false, val1, val2, size, m_registers);
				// Result is not stored
				break;
			}
			case operation::AND:
			case operation::OR:
			case operation::XOR: {
				const auto args = instr.args.args_1r;
				uint32_t val1 = retrieve_result_value(args.result);
				uint32_t val2 = retrieve_operand_value(args.operands[0]);
				data_size_t size = get_result_size(args.result);
				uint32_t result = handle_logical(instr.op, val1, val2, size, m_registers);
				set_result_value(args.result, result);
				break;
			}
			case operation::NOT: {
				const auto args = instr.args.args_0r;
				uint32_t val = retrieve_result_value(args.result);
				data_size_t size = get_result_size(args.result);
				uint32_t mask;
				switch (size) {
					case data_size_t::BYTE:
						mask = 0xFF;
						break;
					case data_size_t::WORD:
						mask = 0xFFFF;
						break;
					case data_size_t::DWORD:
						mask = 0xFFFFFFFF;
						break;
					default:
						throw std::runtime_error("Invalid data size");
				}
				uint32_t result = (~val) & mask;
				// NOT does not affect flags
				set_result_value(args.result, result);
				break;
			}
			case operation::SHL:
			case operation::SHR:
			case operation::SAR: {
				const auto args = instr.args.args_1r;
				uint32_t val = retrieve_result_value(args.result);
				uint32_t count = retrieve_operand_value(args.operands[0]) & 0x1F; // Only lower 5 bits are used
				data_size_t size = get_result_size(args.result);
				uint32_t result = handle_shift(instr.op, val, count, size, m_registers);
				set_result_value(args.result, result);
				break;
			}
			case operation::ROL:
			case operation::ROR:
			case operation::RCL:
			case operation::RCR: {
				const auto args = instr.args.args_1r;
				uint32_t val = retrieve_result_value(args.result);
				uint32_t count = retrieve_operand_value(args.operands[0]) & 0x1F; // Only lower 5 bits are used
				data_size_t size = get_result_size(args.result);
				uint32_t result = handle_rotate(instr.op, val, count, size, m_registers);
				set_result_value(args.result, result);
				break;
			}
			case operation::TEST: {
				const auto args = instr.args.args_2n;
				uint32_t val1 = retrieve_operand_value(args.operands[0]);
				uint32_t val2 = retrieve_operand_value(args.operands[1]);
				data_size_t size = data_size_t::DWORD;
				if (args.operands[0].type != operand_arg::type_t::IMMEDIATE && args.operands[1].type !=
					operand_arg::type_t::IMMEDIATE) {
					size = std::min(
						(args.operands[0].type == operand_arg::type_t::REGISTER)
						? get_size_from_access(args.operands[0].value.reg.access)
						: args.operands[0].value.mem.size,
						(args.operands[1].type == operand_arg::type_t::REGISTER)
						? get_size_from_access(args.operands[1].value.reg.access)
						: args.operands[1].value.mem.size);
				}
				else if (args.operands[0].type != operand_arg::type_t::IMMEDIATE) {
					size = (args.operands[0].type == operand_arg::type_t::REGISTER)
						? get_size_from_access(args.operands[0].value.reg.access)
						: args.operands[0].value.mem.size;
				}
				else if (args.operands[1].type != operand_arg::type_t::IMMEDIATE) {
					size = (args.operands[1].type == operand_arg::type_t::REGISTER)
						? get_size_from_access(args.operands[1].value.reg.access)
						: args.operands[1].value.mem.size;
				}
				handle_logical(operation::AND, val1, val2, size, m_registers);
				// Result is not stored
				break;
			}
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
			case operation::JBE: {
				bool condition_met = check_jump_condition(instr.op, m_registers);
				if (!condition_met) break;
				const auto args = instr.args.args_1n;
				uint32_t target = retrieve_operand_value(args.operands[0]);
				m_instruction_pointer = target;
				jump_occurred = true;
				break;
			}
			case operation::CALL: {
				const auto args = instr.args.args_1n;
				uint32_t target = retrieve_operand_value(args.operands[0]);
				// Push return address onto stack
				push_stack(m_registers, m_ram, m_instruction_pointer + 1, data_size_t::DWORD);
				m_instruction_pointer = target;
				jump_occurred = true;
				break;
			}
			case operation::RET: {
				// Pop return address from stack
				uint32_t return_address = pop_stack(m_registers, m_ram, data_size_t::DWORD);
				m_instruction_pointer = return_address;
				jump_occurred = true;
				break;
			}
			case operation::PUSHA: {
				uint32_t original_esp = m_registers.esp;
				push_stack(m_registers, m_ram, m_registers.eax, data_size_t::DWORD);
				push_stack(m_registers, m_ram, m_registers.ecx, data_size_t::DWORD);
				push_stack(m_registers, m_ram, m_registers.edx, data_size_t::DWORD);
				push_stack(m_registers, m_ram, m_registers.ebx, data_size_t::DWORD);
				push_stack(m_registers, m_ram, original_esp, data_size_t::DWORD); // Push original ESP
				push_stack(m_registers, m_ram, m_registers.ebp, data_size_t::DWORD);
				push_stack(m_registers, m_ram, m_registers.esi, data_size_t::DWORD);
				push_stack(m_registers, m_ram, m_registers.edi, data_size_t::DWORD);
				break;
			}
			case operation::POPA: {
				m_registers.edi = pop_stack(m_registers, m_ram, data_size_t::DWORD);
				m_registers.esi = pop_stack(m_registers, m_ram, data_size_t::DWORD);
				m_registers.ebp = pop_stack(m_registers, m_ram, data_size_t::DWORD);
				uint32_t discarded_esp = pop_stack(m_registers, m_ram, data_size_t::DWORD); // Discard original ESP
				(void) discarded_esp; // Avoid unused variable warning
				m_registers.ebx = pop_stack(m_registers, m_ram, data_size_t::DWORD);
				m_registers.edx = pop_stack(m_registers, m_ram, data_size_t::DWORD);
				m_registers.ecx = pop_stack(m_registers, m_ram, data_size_t::DWORD);
				m_registers.eax = pop_stack(m_registers, m_ram, data_size_t::DWORD);
				break;
			}
			case operation::PUSHF:
				push_stack(m_registers, m_ram, m_registers.flags.value, data_size_t::DWORD);
				break;
			case operation::POPF: {
				uint32_t flags_value = pop_stack(m_registers, m_ram, data_size_t::DWORD);
				m_registers.flags.value = flags_value;
				break;
			}
			case operation::CLC:
				m_registers.flags.cf = false;
				break;
			case operation::STC:
				m_registers.flags.cf = true;
				break;
			case operation::HLT:
				m_state = execution_state_t::HALTED;
				break;
			case operation::IN: {
				// Input operation not implemented
				break;
			}
			case operation::OUT: {
				const auto args = instr.args.args_1n;
				uint32_t value = retrieve_operand_value(args.operands[0]);
				std::cout << "OUT: " << value << std::endl;
				break;
			}
		}
		if (!jump_occurred) {
			++m_instruction_pointer;
		}
	}

	void print_registers(const register_file& regs) {
		std::cout << std::format("EAX: 0x{:08X} ({}) , ", regs.eax, static_cast<int32_t>(regs.eax));
		std::cout << std::format("EBX: 0x{:08X} ({}) , ", regs.ebx, static_cast<int32_t>(regs.ebx));
		std::cout << std::format("ECX: 0x{:08X} ({}) , ", regs.ecx, static_cast<int32_t>(regs.ecx));
		std::cout << std::format("EDX: 0x{:08X} ({}) , ", regs.edx, static_cast<int32_t>(regs.edx));
		std::cout << std::format("ESI: 0x{:08X} ({}) , ", regs.esi, static_cast<int32_t>(regs.esi));
		std::cout << std::format("EDI: 0x{:08X} ({}) , ", regs.edi, static_cast<int32_t>(regs.edi));
		std::cout << std::format("EBP: 0x{:08X} ({}) , ", regs.ebp, static_cast<int32_t>(regs.ebp));
		std::cout << std::format("ESP: 0x{:08X} ({}) | ", regs.esp, static_cast<int32_t>(regs.esp));
		std::cout << std::format("FLAGS: [C={} O={} Z={} S={} P={} A={}] ",
			regs.flags.cf ? 1 : 0,
			regs.flags.of ? 1 : 0,
			regs.flags.zf ? 1 : 0,
			regs.flags.sf ? 1 : 0,
			regs.flags.pf ? 1 : 0,
			regs.flags.af ? 1 : 0);
	}

	void computer::step() {
		if (m_state != execution_state_t::RUNNING) {
			return;
		}
		if (m_instruction_pointer >= m_program.size()) {
			m_state = execution_state_t::HALTED;
			return;
		}

		if (m_verbose) {
			std::cout << "IP: " << m_instruction_pointer << " | ";
			print_registers(m_registers);
			std::cout << std::endl;
			std::cout << "Executing: " << m_program[m_instruction_pointer] << std::endl;
		}

		const instruction_t& instr = m_program[m_instruction_pointer];
		try {
			execute_instruction(instr);
		}
		catch (const std::exception& e) {
			m_state = execution_state_t::ERROR;
			m_error_message = e.what();
			if (m_verbose) {
				std::cout << "Error: " << m_error_message << std::endl;
			}
		}
	}
	void computer::run(int max_steps) {
		if (max_steps <= 0) {
			while (m_state == execution_state_t::RUNNING) {
				step();
			}
		}
		else {
			for (int i = 0; i < max_steps && m_state == execution_state_t::RUNNING; ++i) {
				step();
			}
		}
	}
} // machine
