#include "assembler.hpp"

#include "instruction_helper.hpp"

namespace machine::assembler {
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
				return {};
		}
	}
	inline uint8_t register_to_byte(const register_t& reg) {
		// register is currently 6 bits, but we use a full byte for future expansion
		// register_t already saves it in the correct format, so we can just copy the byte

		uint8_t reg_byte;
		std::memcpy(&reg_byte, &reg, sizeof(uint8_t));
		return reg_byte;
	}
	void assemble_memory_data(const memory_operand memory, bytecode_t& out) {
		switch (memory.memory_type) {
			case memory_operand::type::DIRECT: {
				// direct memory address
				uint32_t addr = memory.value.direct_address;
				for (size_t i = 0; i < 4; i++) {
					out.push_back(static_cast<uint8_t>(addr >> (i * 8) & 0xFF));
				}
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
				for (size_t i = 0; i < 4; i++) {
					out.push_back(static_cast<uint8_t>(disp >> (i * 8) & 0xFF));
				}
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
				for (size_t i = 0; i < 4; i++) {
					out.push_back(static_cast<uint8_t>(disp >> (i * 8) & 0xFF));
				}
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
	void assemble(const machine::instruction_t& instr, bytecode_t& out) {
		// first byte is always the operation (7 bits) and if there is a result, the type of result (reg or mem) (1 bit)
		uint8_t opcode = static_cast<uint8_t>(instr.op) & 0x7F;
		auto operands_type = instruction_helper::get_operands_type(instr.op);
		auto res_arg = get_result_arg(instr, operands_type);
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
				throw std::runtime_error("Unknown number of operands");
		}
	}

	void assemble(const machine::program_t& program, bytecode_t& out) {
		for (const auto& instr : program) {
			assemble(instr, out);
		}
	}
} // namespace machine::assembler
