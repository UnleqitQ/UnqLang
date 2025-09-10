#include "assembly.hpp"

#include <format>

namespace assembly {
	std::string assembly_literal::to_string(bool hex) const {
		switch (literal_type) {
			case type::NUMBER:
				if (hex) {
					if (std::get<int32_t>(value) < 0) {
						return std::format("-0x{:X}", -std::get<int32_t>(value));
					}
					else {
						return std::format("0x{:X}", std::get<int32_t>(value));
					}
				}
				else {
					return std::to_string(std::get<int32_t>(value));
				}
			case type::LABEL:
				return std::format("\"{}\"", std::get<std::string>(value));
		}
		return "";
	}
	std::string assembly_memory::to_string() const {
		switch (memory_type) {
			case type::DIRECT:
				return std::format("[{}]", std::get<assembly_literal>(value).to_string(true));
			case type::REGISTER:
				return std::format("[{}]", std::get<machine::register_t>(value).to_string());
			case type::DISPLACEMENT: {
				const displacement& disp = std::get<displacement>(value);
				return std::format("[{} + {}]", disp.reg.to_string(), disp.disp.to_string(true));
			}
			case type::SCALED_INDEX: {
				const scaled_index& si = std::get<scaled_index>(value);
				if (si.scale >= 0) {
					return std::format("[{} + {}*{}]", si.base.to_string(), si.index.to_string(), static_cast<int>(si.scale));
				}
				else {
					return std::format("[{} - {}*{}]", si.base.to_string(), si.index.to_string(), -static_cast<int>(si.scale));
				}
			}
			case type::SCALED_INDEX_DISPLACEMENT: {
				const scaled_index_displacement& sid = std::get<scaled_index_displacement>(value);
				if (sid.scale >= 0) {
					return std::format("[{} + {}*{} + {}]", sid.base.to_string(), sid.index.to_string(),
						static_cast<int>(sid.scale), sid.disp.to_string(true));
				}
				else {
					return std::format("[{} - {}*{} + {}]", sid.base.to_string(), sid.index.to_string(),
						-static_cast<int>(sid.scale), sid.disp.to_string(true));
				}
			}
		}
		return "";
	}


	uint32_t resolve_literal(const assembly_literal& lit,
		const std::unordered_map<std::string, uint32_t>& label_map) {
		switch (lit.literal_type) {
			case assembly_literal::type::NUMBER:
				return static_cast<uint32_t>(std::get<int32_t>(lit.value));
			case assembly_literal::type::LABEL: {
				const auto& label = std::get<std::string>(lit.value);
				const auto it = label_map.find(label);
				if (it == label_map.end()) {
					throw std::runtime_error("Undefined label: " + label);
				}
				return it->second;
			}
		}
		throw std::runtime_error("Unknown literal type");
	}
	machine::memory_operand assemble_memory(const assembly_memory& mem,
		const std::unordered_map<std::string, uint32_t>& label_map) {
		switch (mem.memory_type) {
			case assembly_memory::type::DIRECT: {
				const auto addr = resolve_literal(std::get<assembly_literal>(mem.value), label_map);
				return machine::memory_operand(addr);
			}
			case assembly_memory::type::REGISTER: {
				const auto reg = std::get<machine::register_t>(mem.value);
				return machine::memory_operand(reg);
			}
			case assembly_memory::type::DISPLACEMENT: {
				const auto disp = std::get<assembly_memory::displacement>(mem.value);
				const auto base = disp.reg;
				const auto offset = resolve_literal(disp.disp, label_map);
				return machine::memory_operand(base, static_cast<int32_t>(offset));
			}
			case assembly_memory::type::SCALED_INDEX: {
				const auto si = std::get<assembly_memory::scaled_index>(mem.value);
				const auto base = si.base;
				const auto index = si.index;
				const auto scale = si.scale;
				return machine::memory_operand(base, index, scale);
			}
			case assembly_memory::type::SCALED_INDEX_DISPLACEMENT: {
				const auto sid = std::get<assembly_memory::scaled_index_displacement>(mem.value);
				const auto base = sid.base;
				const auto index = sid.index;
				const auto scale = sid.scale;
				const auto offset = resolve_literal(sid.disp, label_map);
				return machine::memory_operand(base, index, scale, static_cast<int32_t>(offset));
			}
		}
		throw std::runtime_error("Unknown memory type");
	}
	machine::result_arg assemble_result(const assembly_result& res,
		const std::unordered_map<std::string, uint32_t>& label_map) {
		switch (res.result_type) {
			case assembly_result::type::REGISTER: {
				const auto reg = std::get<machine::register_t>(res.value);
				return machine::result_arg{machine::result_arg::type_t::REGISTER, {.reg = reg}};
			}
			case assembly_result::type::MEMORY_POINTER: {
				const auto mem = std::get<assembly_memory_pointer>(res.value);
				return machine::result_arg{machine::result_arg::type_t::MEMORY, {.mem = assemble_memory(mem, label_map)}};
			}
		}
		throw std::runtime_error("Unknown result type");
	}
	machine::operand_arg assemble_operand(const assembly_operand& op,
		const std::unordered_map<std::string, uint32_t>& label_map) {
		switch (op.operand_type) {
			case assembly_operand::type::REGISTER: {
				const auto reg = std::get<machine::register_t>(op.value);
				return machine::operand_arg{machine::operand_arg::type_t::REGISTER, {.reg = reg}};
			}
			case assembly_operand::type::LITERAL: {
				const auto lit = std::get<assembly_literal>(op.value);
				const auto imm = resolve_literal(lit, label_map);
				return machine::operand_arg{machine::operand_arg::type_t::IMMEDIATE, {.imm = static_cast<int32_t>(imm)}};
			}
			case assembly_operand::type::MEMORY_POINTER: {
				const auto mem = std::get<assembly_memory>(op.value);
				return machine::operand_arg{machine::operand_arg::type_t::MEMORY, {.mem = assemble_memory(mem, label_map)}};
			}
		}
		throw std::runtime_error("Unknown operand type");
	}

	machine::instruction_t assemble_instruction(const assembly_instruction& inst,
		const std::unordered_map<std::string, uint32_t>& label_map) {
		const auto op = inst.op;
		const auto& args = inst.args;
		machine::instruction_t result;
		std::visit([&]<typename T0>(const T0& a) {
			using T = std::decay_t<T0>;
			if constexpr (std::is_same_v<T, assembly_instruction::args_t<2, false>>) {
				// Binary operation without result: op1, op2
				const auto op1 = a.operands[0];
				const auto op2 = a.operands[1];
				result = machine::instruction_t(op, machine::args_t<2, false>{
					{assemble_operand(op1, label_map), assemble_operand(op2, label_map)}
				});
			}
			else if constexpr (std::is_same_v<T, assembly_instruction::args_t<1, true>>) {
				// Unary operation with result: res, op
				const auto res = a.result;
				const auto op1 = a.operands[0];
				result = machine::instruction_t(op, machine::args_t<1, true>{
					{assemble_operand(op1, label_map)},
					assemble_result(res, label_map)
				});
			}
			else if constexpr (std::is_same_v<T, assembly_instruction::args_t<1, false>>) {
				// Unary operation without result: op
				const auto op1 = a.operands[0];
				result = machine::instruction_t(op, machine::args_t<1, false>{
					{assemble_operand(op1, label_map)}
				});
			}
			else if constexpr (std::is_same_v<T, assembly_instruction::args_t<0, true>>) {
				// Nullary operation with result: res
				const auto res = a.result;
				result = machine::instruction_t(op, machine::args_t<0, true>{
					{},
					assemble_result(res, label_map)
				});
			}
			else if constexpr (std::is_same_v<T, assembly_instruction::args_t<0, false>>) {
				// Nullary operation without result: no operands
				result = machine::instruction_t(op, machine::args_t<0, false>{});
			}
			else {
				throw std::runtime_error("Unhandled args type in assemble_instruction");
			}
		}, args);
		return result;
	}
	void retrieve_labels(const assembly_program_t& assembly_program, std::unordered_map<std::string, uint32_t>& label_map,
		uint32_t start_address) {
		uint32_t address = start_address;
		for (const auto& comp : assembly_program) {
			if (comp.component_type == assembly_component::type::LABEL) {
				const auto& label = std::get<std::string>(comp.value);
				if (label_map.find(label) != label_map.end()) {
					std::cerr << "Warning: Duplicate label definition: " << label << std::endl;
				}
				else {
					label_map[label] = address;
				}
			}
			else if (comp.component_type == assembly_component::type::INSTRUCTION) {
				++address; // Each instruction is 1 address unit
			}
		}
	}

	machine::program_t assemble(const assembly_program_t& assembly_program, uint32_t start_address) {
		machine::program_t program;
		std::unordered_map<std::string, uint32_t> label_map;
		retrieve_labels(assembly_program, label_map, start_address);
		program.reserve(assembly_program.size() - label_map.size());
		for (const auto& comp : assembly_program) {
			if (comp.component_type == assembly_component::type::INSTRUCTION) {
				const auto& inst = std::get<assembly_instruction>(comp.value);
				program.push_back(assemble_instruction(inst, label_map));
			}
		}
		return program;
	}
}
