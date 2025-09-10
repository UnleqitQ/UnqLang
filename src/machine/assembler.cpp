#include "assembler.hpp"

#include "instruction_helper.hpp"

namespace machine::assembler {
	template<bool unsafe>
	result_arg get_result_arg(const machine::instruction_t& instr, instruction_helper::operands_type opstype) {
		if (!opstype.has_result) {
			return {};
		}
		switch (opstype.num_operands) {
			case instruction_helper::operands_type::NO_OPERANDS:
				return instr.args.args_0r.result;
			case instruction_helper::operands_type::ONE_OPERAND:
				return instr.args.args_1r.result;
			case instruction_helper::operands_type::MEMORY_OPERAND:
				return instr.args.args_1r_mem.result;
			default:
				if constexpr (unsafe) {
					return {};
				}
				else {
					throw std::runtime_error("Invalid number of operands for instruction with result");
				}
		}
	}
	inline uint8_t register_to_byte(const register_t& reg) {
		// register is currently 6 bits, but we use a full byte for future expansion
		// register_t already saves it in the correct format, so we can just copy the byte

		return reinterpret_cast<const uint8_t&>(reg);
	}
	inline register_t byte_to_register(const uint8_t& byte) {
		return reinterpret_cast<const register_t&>(byte);
	}
	void assemble_32bit_integer(uint32_t value, bytecode_t& out) {
		out.resize(out.size() + 4);
		memcpy(&out[out.size() - 4], &value, 4);
	}
	template<bool unsafe>
	void disassemble_32bit_integer(const bytecode_t& bytecode, size_t& pc, uint32_t& out) {
		if constexpr (!unsafe)
			if (pc + 4 > bytecode.size()) {
				throw std::runtime_error("Program counter out of bounds while reading 32-bit integer");
			}
		memcpy(&out, &bytecode[pc], 4);
		pc += 4;
	}

	void assemble_memory_data(const memory_operand memory, bytecode_t& out) {
		switch (memory.memory_type) {
			case memory_operand::type::DIRECT: {
				// direct memory address
				uint32_t addr = memory.value.direct_address;
				assemble_32bit_integer(addr, out);
				break;
			}
			case memory_operand::type::REGISTER: {
				// register
				uint8_t reg_byte = register_to_byte(memory.value.reg);
				out.push_back(reg_byte);
				break;
			}
			case memory_operand::type::DISPLACEMENT: {
				// base register + displacement
				uint8_t reg_byte = register_to_byte(memory.value.disp.base);
				out.push_back(reg_byte);
				int32_t disp = memory.value.disp.disp;
				assemble_32bit_integer(disp, out);
				break;
			}
			case memory_operand::type::SCALED_INDEX: {
				// base register + index register * scale
				uint8_t base_reg_byte = register_to_byte(memory.value.s_index.base);
				out.push_back(base_reg_byte);
				uint8_t index_reg_byte = register_to_byte(memory.value.s_index.index);
				out.push_back(index_reg_byte);
				int8_t scale = memory.value.s_index.scale;
				out.push_back(static_cast<uint8_t>(scale));
				break;
			}
			case memory_operand::type::SCALED_INDEX_DISPLACEMENT: {
				// base register + index register * scale + displacement
				uint8_t base_reg_byte = register_to_byte(memory.value.s_index_disp.base);
				out.push_back(base_reg_byte);
				uint8_t index_reg_byte = register_to_byte(memory.value.s_index_disp.index);
				out.push_back(index_reg_byte);
				int8_t scale = memory.value.s_index_disp.scale;
				out.push_back(static_cast<uint8_t>(scale));
				int32_t disp = memory.value.s_index_disp.disp;
				assemble_32bit_integer(disp, out);
				break;
			}
		}
	}
	void assemble_memory_pointer_operand(const memory_pointer_operand& mem, bytecode_t& out) {
		uint8_t size = static_cast<uint8_t>(mem.size);
		memory_operand memory = mem.memory;
		uint8_t type = static_cast<uint8_t>(memory.memory_type);
		uint8_t size_type = size | (type << 2);
		out.push_back(size_type);
		assemble_memory_data(memory, out);
	}
	void assemble_operand(const operand_arg& op, bytecode_t& out) {
		switch (op.type) {
			case operand_arg::type_t::REGISTER: {
				uint8_t reg_byte = register_to_byte(op.value.reg);
				out.push_back(reg_byte);
				break;
			}
			case operand_arg::type_t::IMMEDIATE: {
				int32_t imm = op.value.imm;
				for (size_t i = 0; i < 4; i++) {
					out.push_back(static_cast<uint8_t>(imm >> (i * 8) & 0xFF));
				}
				break;
			}
			case operand_arg::type_t::MEMORY: {
				assemble_memory_pointer_operand(op.value.mem, out);
				break;
			}
		}
	}
	template<bool unsafe>
	void assemble_instr(const machine::instruction_t& instr, bytecode_t& out) {
		// first byte is always the operation (7 bits) and if there is a result, the type of result (reg or mem) (1 bit)
		uint8_t opcode = static_cast<uint8_t>(instr.op) & 0x7F;
		auto operands_type = instruction_helper::get_operands_type(instr.op);
		auto res_arg = get_result_arg<unsafe>(instr, operands_type);
		if (operands_type.has_result)
			opcode |= (static_cast<uint8_t>(res_arg.type) & 1) << 7;
		out.push_back(opcode);

		// if there is a result encode it next
		if (operands_type.has_result && res_arg.type == result_arg::type_t::REGISTER) {
			uint8_t reg_byte = register_to_byte(res_arg.value.reg);
			out.push_back(reg_byte);
		}
		else if (operands_type.has_result && res_arg.type == result_arg::type_t::MEMORY) {
			assemble_memory_pointer_operand(res_arg.value.mem, out);
		}
		// then encode the operands
		switch (operands_type.num_operands) {
			case instruction_helper::operands_type::NO_OPERANDS:
				// no operands to encode
				break;
			case instruction_helper::operands_type::ONE_OPERAND: {
				auto op = operands_type.has_result ? instr.args.args_1r.operands[0] : instr.args.args_1n.operands[0];
				out.push_back(static_cast<uint8_t>(op.type));
				assemble_operand(op, out);
				break;
			}
			case instruction_helper::operands_type::TWO_OPERANDS: {
				auto op1 = instr.args.args_2n.operands[0];
				auto op2 = instr.args.args_2n.operands[1];
				const uint8_t types = (static_cast<uint8_t>(op1.type) & 0x03) | ((static_cast<uint8_t>(op2.type) & 0x03) << 2);
				out.push_back(types);
				assemble_operand(op1, out);
				assemble_operand(op2, out);
				break;
			}
			case instruction_helper::operands_type::MEMORY_OPERAND: {
				auto op = instr.args.args_1r_mem.operands[0];
				out.push_back(static_cast<uint8_t>(op.memory_type));
				assemble_memory_data(op, out);
				break;
			}
			default:
				if constexpr (unsafe) {
					// do nothing
				}
				else {
					throw std::runtime_error("Unknown number of operands");
				}
		}
	}

	void assemble(const machine::instruction_t& instr, bytecode_t& out) {
		assemble_instr<false>(instr, out);
	}
	void assemble_unsafe(const machine::instruction_t& instr, bytecode_t& out) {
		assemble_instr<true>(instr, out);
	}
	void assemble(const machine::program_t& program, bytecode_t& out) {
		for (const auto& instr : program) {
			assemble(instr, out);
		}
	}
	void assemble_unsafe(const machine::program_t& program, bytecode_t& out) {
		for (const auto& instr : program) {
			assemble_unsafe(instr, out);
		}
	}

	template<bool unsafe>
	void disassemble_memory_data(const bytecode_t& bytecode, memory_operand& out, size_t& pc) {
		if constexpr (!unsafe)
			if (pc >= bytecode.size()) {
				throw std::runtime_error("Program counter out of bounds while reading memory data");
			}
		switch (out.memory_type) {
			case memory_operand::type::DIRECT:
				disassemble_32bit_integer<unsafe>(bytecode, pc, out.value.direct_address);
				break;
			case memory_operand::type::REGISTER: {
				if constexpr (!unsafe)
					if (pc >= bytecode.size()) {
						throw std::runtime_error("Program counter out of bounds while reading register memory operand");
					}
				uint8_t reg_byte = bytecode[pc++];
				out.value.reg = byte_to_register(reg_byte);
				break;
			}
			case memory_operand::type::DISPLACEMENT: {
				if constexpr (!unsafe)
					if (pc >= bytecode.size()) {
						throw std::runtime_error(
							"Program counter out of bounds while reading base register of displacement memory operand");
					}
				uint8_t reg_byte = bytecode[pc++];
				out.value.disp.base = byte_to_register(reg_byte);
				disassemble_32bit_integer<unsafe>(bytecode, pc, reinterpret_cast<uint32_t&>(out.value.disp.disp));
				break;
			}
			case memory_operand::type::SCALED_INDEX: {
				if constexpr (!unsafe)
					if (pc + 3 > bytecode.size()) {
						throw std::runtime_error("Program counter out of bounds while reading scaled index memory operand");
					}
				uint8_t base_reg_byte = bytecode[pc++];
				out.value.s_index.base = byte_to_register(base_reg_byte);
				uint8_t index_reg_byte = bytecode[pc++];
				out.value.s_index.index = byte_to_register(index_reg_byte);
				uint8_t scale_byte = bytecode[pc++];
				out.value.s_index.scale = static_cast<int8_t>(scale_byte);
				break;
			}
			case memory_operand::type::SCALED_INDEX_DISPLACEMENT: {
				if constexpr (!unsafe)
					if (pc + 7 > bytecode.size()) {
						throw std::runtime_error(
							"Program counter out of bounds while reading scaled index with displacement memory operand");
					}
				uint8_t base_reg_byte = bytecode[pc++];
				out.value.s_index_disp.base = byte_to_register(base_reg_byte);
				uint8_t index_reg_byte = bytecode[pc++];
				out.value.s_index_disp.index = byte_to_register(index_reg_byte);
				uint8_t scale_byte = bytecode[pc++];
				out.value.s_index_disp.scale = static_cast<int8_t>(scale_byte);
				disassemble_32bit_integer<unsafe>(bytecode, pc, reinterpret_cast<uint32_t&>(out.value.s_index_disp.disp));
				break;
			}
		}
	}
	template<bool unsafe>
	void disassemble_memory_pointer_operand(const bytecode_t& bytecode, memory_pointer_operand& out, size_t& pc) {
		if constexpr (!unsafe)
			if (pc >= bytecode.size()) {
				throw std::runtime_error("Program counter out of bounds while reading memory pointer operand");
			}
		uint8_t size_type = bytecode[pc++];
		out.size = static_cast<data_size_t>(size_type & 0x03);
		out.memory.memory_type = static_cast<memory_operand::type>(size_type >> 2 & 0x03);
		disassemble_memory_data<unsafe>(bytecode, out.memory, pc);
	}
	template<bool unsafe>
	void disassemble_operand(const bytecode_t& bytecode, operand_arg& out, size_t& pc) {
		switch (out.type) {
			case operand_arg::type_t::REGISTER: {
				if constexpr (!unsafe)
					if (pc >= bytecode.size()) {
						throw std::runtime_error("Program counter out of bounds while reading register operand");
					}
				uint8_t reg_byte = bytecode[pc++];
				out.value.reg = byte_to_register(reg_byte);
				break;
			}
			case operand_arg::type_t::IMMEDIATE: {
				if constexpr (!unsafe)
					if (pc + 4 > bytecode.size()) {
						throw std::runtime_error("Program counter out of bounds while reading immediate operand");
					}
				disassemble_32bit_integer<unsafe>(bytecode, pc, reinterpret_cast<uint32_t&>(out.value.imm));
				break;
			}
			case operand_arg::type_t::MEMORY: {
				disassemble_memory_pointer_operand<unsafe>(bytecode, out.value.mem, pc);
				break;
			}
		}
	}
	template<bool unsafe>
	void disassemble_instr(const bytecode_t& bytecode, machine::instruction_t& out, size_t& pc) {
		if constexpr (!unsafe)
			if (pc >= bytecode.size()) {
				throw std::runtime_error("Program counter out of bounds");
			}
		uint8_t opcode = bytecode[pc++];
		out.op = static_cast<machine::operation>(opcode & 0x7F);
		result_arg::type_t result_type = static_cast<result_arg::type_t>((opcode >> 7) & 0x01);
		auto operands_type = instruction_helper::get_operands_type(out.op);
		// if there is a result, decode it next
		if (operands_type.has_result) {
			if (result_type == result_arg::type_t::REGISTER) {
				if constexpr (!unsafe)
					if (pc >= bytecode.size()) {
						throw std::runtime_error("Program counter out of bounds while reading register result");
					}
				uint8_t reg_byte = bytecode[pc++];
				out.args.args_0r.result.type = result_arg::type_t::REGISTER;
				out.args.args_0r.result.value.reg = byte_to_register(reg_byte);
			}
			else if (result_type == result_arg::type_t::MEMORY) {
				out.args.args_0r.result.type = result_arg::type_t::MEMORY;
				disassemble_memory_pointer_operand<unsafe>(bytecode, out.args.args_0r.result.value.mem, pc);
			}
		}
		// then decode the operands
		switch (operands_type.num_operands) {
			case instruction_helper::operands_type::NO_OPERANDS:
				// no operands to decode
				break;
			case instruction_helper::operands_type::ONE_OPERAND: {
				if constexpr (!unsafe)
					if (pc >= bytecode.size()) {
						throw std::runtime_error("Program counter out of bounds while reading one operand type");
					}
				operand_arg::type_t op_type = static_cast<operand_arg::type_t>(bytecode[pc++]);
				if (operands_type.has_result) {
					out.args.args_1r.operands[0].type = op_type;
					disassemble_operand<unsafe>(bytecode, out.args.args_1r.operands[0], pc);
				}
				else {
					out.args.args_1n.operands[0].type = op_type;
					disassemble_operand<unsafe>(bytecode, out.args.args_1n.operands[0], pc);
				}
				break;
			}
			case instruction_helper::operands_type::TWO_OPERANDS: {
				if constexpr (!unsafe)
					if (pc >= bytecode.size()) {
						throw std::runtime_error("Program counter out of bounds while reading two operand types");
					}
				uint8_t types = bytecode[pc++];
				operand_arg::type_t op1_type = static_cast<operand_arg::type_t>(types & 0x03);
				operand_arg::type_t op2_type = static_cast<operand_arg::type_t>((types >> 2) & 0x03);
				out.args.args_2n.operands[0].type = op1_type;
				out.args.args_2n.operands[1].type = op2_type;
				disassemble_operand<unsafe>(bytecode, out.args.args_2n.operands[0], pc);
				disassemble_operand<unsafe>(bytecode, out.args.args_2n.operands[1], pc);
				break;
			}
			case instruction_helper::operands_type::MEMORY_OPERAND: {
				if constexpr (!unsafe)
					if (pc >= bytecode.size()) {
						throw std::runtime_error("Program counter out of bounds while reading memory operand type");
					}
				memory_operand::type mem_type = static_cast<memory_operand::type>(bytecode[pc++]);
				out.args.args_1r_mem.operands[0].memory_type = mem_type;
				disassemble_memory_data<unsafe>(bytecode, out.args.args_1r_mem.operands[0], pc);
				break;
			}
			default:
				if constexpr (unsafe) {
					// do nothing
				}
				else {
					throw std::runtime_error("Unknown number of operands");
				}
		}
	}
	void disassemble(const bytecode_t& bytecode, machine::instruction_t& out, size_t& pc) {
		disassemble_instr<false>(bytecode, out, pc);
	}
	void disassemble_unsafe(const bytecode_t& bytecode, machine::instruction_t& out, size_t& pc) {
		disassemble_instr<true>(bytecode, out, pc);
	}
	void disassemble(const bytecode_t& bytecode, machine::program_t& out, size_t start, size_t end) {
		if (end > bytecode.size()) {
			end = bytecode.size();
		}
		size_t pc = start;
		while (pc < end) {
			machine::instruction_t instr;
			disassemble(bytecode, instr, pc);
			out.push_back(instr);
		}
	}
	void disassemble_unsafe(const bytecode_t& bytecode, machine::program_t& out, size_t start, size_t end) {
		if (end > bytecode.size()) {
			end = bytecode.size();
		}
		size_t pc = start;
		while (pc < end) {
			machine::instruction_t instr;
			disassemble_unsafe(bytecode, instr, pc);
			out.push_back(instr);
		}
	}
} // namespace machine::assembler
