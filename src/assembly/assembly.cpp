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
	std::string extended_assembly_literal::to_string(bool hex) const {
		switch (type) {
			case type_t::VALUE:
				return std::get<assembly_literal>(value).to_string(hex);
			case type_t::ADD: {
				const auto& op = std::get<binary_operation>(value);
				return std::format("({} + {})", op.left->to_string(hex), op.right->to_string(hex));
			}
			case type_t::SUB: {
				const auto& op = std::get<binary_operation>(value);
				return std::format("({} - {})", op.left->to_string(hex), op.right->to_string(hex));
			}
			case type_t::MUL: {
				const auto& op = std::get<binary_operation>(value);
				return std::format("({} * {})", op.left->to_string(hex), op.right->to_string(hex));
			}
		}
		return "";
	}
	bool extended_assembly_literal::operator==(const extended_assembly_literal& other) const {
		if (type != other.type) {
			return false;
		}
		switch (type) {
			case type_t::VALUE: {
				const auto& lit1 = std::get<assembly_literal>(value);
				const auto& lit2 = std::get<assembly_literal>(other.value);
				return lit1.literal_type == lit2.literal_type && lit1.value == lit2.value;
			}
			case type_t::ADD:
			case type_t::SUB:
			case type_t::MUL: {
				const auto& op1 = std::get<binary_operation>(value);
				const auto& op2 = std::get<binary_operation>(other.value);
				return *op1.left == *op2.left && *op1.right == *op2.right;
			}
		}
		return false;
	}
	extended_assembly_literal extended_assembly_literal::reduced() const {
		switch (type) {
			case type_t::VALUE:
				return *this;
			case type_t::ADD: {
				const auto& op = std::get<binary_operation>(value);
				const auto left_reduced = op.left->reduced();
				const auto right_reduced = op.right->reduced();
				if (left_reduced.type == type_t::VALUE && right_reduced.type == type_t::VALUE) {
					const auto left_lit = std::get<assembly_literal>(left_reduced.value);
					const auto right_lit = std::get<assembly_literal>(right_reduced.value);
					if (left_lit.literal_type == assembly_literal::type::NUMBER &&
						right_lit.literal_type == assembly_literal::type::NUMBER) {
						return extended_assembly_literal(assembly_literal(
							static_cast<int32_t>(std::get<int32_t>(left_lit.value) + std::get<int32_t>(right_lit.value))));
					}
				}
				return extended_assembly_literal(type_t::ADD,
					std::make_shared<extended_assembly_literal>(left_reduced),
					std::make_shared<extended_assembly_literal>(right_reduced));
			}
			case type_t::SUB: {
				const auto& op = std::get<binary_operation>(value);
				const auto left_reduced = op.left->reduced();
				const auto right_reduced = op.right->reduced();
				if (left_reduced.type == type_t::VALUE && right_reduced.type == type_t::VALUE) {
					const auto left_lit = std::get<assembly_literal>(left_reduced.value);
					const auto right_lit = std::get<assembly_literal>(right_reduced.value);
					if (left_lit.literal_type == assembly_literal::type::NUMBER &&
						right_lit.literal_type == assembly_literal::type::NUMBER) {
						return extended_assembly_literal(assembly_literal(
							static_cast<int32_t>(std::get<int32_t>(left_lit.value) - std::get<int32_t>(right_lit.value))));
					}
				}
				return extended_assembly_literal(type_t::SUB,
					std::make_shared<extended_assembly_literal>(left_reduced),
					std::make_shared<extended_assembly_literal>(right_reduced));
			}
			case type_t::MUL: {
				const auto& op = std::get<binary_operation>(value);
				const auto left_reduced = op.left->reduced();
				const auto right_reduced = op.right->reduced();
				if (left_reduced.type == type_t::VALUE && right_reduced.type == type_t::VALUE) {
					const auto left_lit = std::get<assembly_literal>(left_reduced.value);
					const auto right_lit = std::get<assembly_literal>(right_reduced.value);
					if (left_lit.literal_type == assembly_literal::type::NUMBER &&
						right_lit.literal_type == assembly_literal::type::NUMBER) {
						return extended_assembly_literal(assembly_literal(
							static_cast<int32_t>(std::get<int32_t>(left_lit.value) * std::get<int32_t>(right_lit.value))));
					}
				}
				return extended_assembly_literal(type_t::MUL,
					std::make_shared<extended_assembly_literal>(left_reduced),
					std::make_shared<extended_assembly_literal>(right_reduced));
			}
		}
		return *this;
	}
	std::string assembly_memory::to_string() const {
		switch (memory_type) {
			case type::DIRECT:
				return std::format("[{}]", std::get<extended_assembly_literal>(value).to_string(true));
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
	assembly_memory assembly_memory::reduced() const {
		switch (memory_type) {
			case type::DIRECT: {
				return assembly_memory(std::get<extended_assembly_literal>(value).reduced());
			}
			case type::REGISTER:
				return *this;
			case type::DISPLACEMENT: {
				const displacement& disp = std::get<displacement>(value);
				const auto reduced_disp = disp.disp.reduced();
				if (reduced_disp.type == extended_assembly_literal::type_t::VALUE &&
					std::get<assembly_literal>(reduced_disp.value).literal_type == assembly_literal::type::NUMBER &&
					std::get<int32_t>(std::get<assembly_literal>(reduced_disp.value).value) == 0) {
					return assembly_memory(disp.reg);
				}
				return assembly_memory(disp.reg, reduced_disp);
			}
			case type::SCALED_INDEX: {
				if (std::get<scaled_index>(value).scale == 0) {
					return assembly_memory(std::get<scaled_index>(value).base);
				}
				return *this;
			}
			case type::SCALED_INDEX_DISPLACEMENT: {
				const scaled_index_displacement& sid = std::get<scaled_index_displacement>(value);
				const auto reduced_disp = sid.disp.reduced();
				bool scale_zero = sid.scale == 0;
				bool disp_zero = reduced_disp.type == extended_assembly_literal::type_t::VALUE &&
					std::get<assembly_literal>(reduced_disp.value).literal_type == assembly_literal::type::NUMBER &&
					std::get<int32_t>(std::get<assembly_literal>(reduced_disp.value).value) == 0;
				if (scale_zero && disp_zero) {
					return assembly_memory(sid.base);
				}
				if (scale_zero) {
					return assembly_memory(sid.base, reduced_disp);
				}
				if (disp_zero) {
					return assembly_memory(sid.base, sid.index, sid.scale);
				}
				return assembly_memory(sid.base, sid.index, sid.scale, reduced_disp);
			}
		}
		return *this;
	}
	assembly_memory assembly_memory::add_displacement(int32_t disp) const {
		if (disp == 0) {
			return *this;
		}
		return add_displacement(extended_assembly_literal(assembly_literal(disp)));
	}
	assembly_memory assembly_memory::add_displacement(const extended_assembly_literal& disp) const {
		switch (memory_type) {
			case type::DIRECT: {
				const auto base = std::get<extended_assembly_literal>(value);
				return assembly_memory(extended_assembly_literal(
					extended_assembly_literal::type_t::ADD,
					std::make_shared<extended_assembly_literal>(base),
					std::make_shared<extended_assembly_literal>(disp)
				).reduced());
			}
			case type::REGISTER: {
				const auto reg = std::get<machine::register_t>(value);
				return assembly_memory(reg, disp);
			}
			case type::DISPLACEMENT: {
				const auto d = std::get<displacement>(value);
				return assembly_memory(d.reg, extended_assembly_literal(
					extended_assembly_literal::type_t::ADD,
					std::make_shared<extended_assembly_literal>(d.disp),
					std::make_shared<extended_assembly_literal>(disp)
				).reduced());
			}
			case type::SCALED_INDEX: {
				const auto si = std::get<scaled_index>(value);
				return assembly_memory(si.base, si.index, si.scale, disp);
			}
			case type::SCALED_INDEX_DISPLACEMENT: {
				const auto sid = std::get<scaled_index_displacement>(value);
				return assembly_memory(sid.base, sid.index, sid.scale, extended_assembly_literal(
					extended_assembly_literal::type_t::ADD,
					std::make_shared<extended_assembly_literal>(sid.disp),
					std::make_shared<extended_assembly_literal>(disp)
				).reduced());
			}
		}
		throw std::runtime_error("Unknown memory type");
	}
	bool assembly_memory::can_add_register(machine::register_t reg) const {
		switch (memory_type) {
			case type::DIRECT:
				return true;
			case type::REGISTER:
				return true;
			case type::DISPLACEMENT:
				return true;
			case type::SCALED_INDEX: {
				const auto si = std::get<scaled_index>(value);
				if (si.index == reg) {
					return true; // Adding the same register as index is allowed (scale will be adjusted)
				}
				if (si.scale == 0) {
					return true; // Can add index if scale is 0
				}
				if (si.base == reg && si.scale == 1) {
					return true; // Can add if base is the same and scale is 1 (so they can be swapped)
				}
				if (si.base == si.index) {
					return true; // Can add if base and index are the same (so they can be merged)
				}
				return false; // Cannot add another register if both base and index are occupied
			}
			case type::SCALED_INDEX_DISPLACEMENT: {
				const auto sid = std::get<scaled_index_displacement>(value);
				if (sid.index == reg) {
					return true; // Adding the same register as index is allowed (scale will be adjusted)
				}
				if (sid.scale == 0) {
					return true; // Can add index if scale is 0
				}
				if (sid.base == reg && sid.scale == 1) {
					return true; // Can add if base is the same and scale is 1 (so they can be swapped)
				}
				if (sid.base == sid.index) {
					return true; // Can add if base and index are the same (so they can be merged)
				}
				return false; // Cannot add another register if both base and index are occupied
			}
		}
		return false;
	}
	assembly_memory assembly_memory::add_register(machine::register_t reg) const {
		switch (memory_type) {
			case type::DIRECT: {
				return assembly_memory(reg);
			}
			case type::REGISTER: {
				const auto base = std::get<machine::register_t>(value);
				return assembly_memory(base, reg, 1);
			}
			case type::DISPLACEMENT: {
				const auto d = std::get<displacement>(value);
				return assembly_memory(d.reg, reg, 1, d.disp);
			}
			case type::SCALED_INDEX: {
				const auto si = std::get<scaled_index>(value);
				if (si.index == reg) {
					// Adding the same register as index, increment scale
					return assembly_memory(si.base, si.index, si.scale + 1);
				}
				if (si.scale == 0) {
					// Scale is 0, just set the index to the new register with scale 1
					return assembly_memory(si.base, reg, 1);
				}
				if (si.base == reg && si.scale == 1) {
					// Base is the same as the new register and scale is 1, swap base and index
					return assembly_memory(si.index, si.base, 2);
				}
				if (si.base == si.index) {
					// Base and index are the same, increment scale
					return assembly_memory(reg, si.index, si.scale + 1);
				}
				throw std::runtime_error("Cannot add another register to this memory operand");
			}
			case type::SCALED_INDEX_DISPLACEMENT: {
				const auto sid = std::get<scaled_index_displacement>(value);
				if (sid.index == reg) {
					// Adding the same register as index, increment scale
					return assembly_memory(sid.base, sid.index, sid.scale + 1, sid.disp);
				}
				if (sid.scale == 0) {
					// Scale is 0, just set the index to the new register with scale 1
					return assembly_memory(sid.base, reg, 1, sid.disp);
				}
				if (sid.base == reg && sid.scale == 1) {
					// Base is the same as the new register and scale is 1, swap base and index
					return assembly_memory(sid.index, sid.base, 2, sid.disp);
				}
				if (sid.base == sid.index) {
					// Base and index are the same, increment scale
					return assembly_memory(reg, sid.index, sid.scale + 1, sid.disp);
				}
				throw std::runtime_error("Cannot add another register to this memory operand");
			}
		}
		throw std::runtime_error("Unknown memory type");
	}
	bool assembly_memory::can_add_scaled_register(machine::register_t reg, int16_t scale) const {
		if (scale == 1) {
			return can_add_register(reg);
		}
		if (scale == 0) {
			return true; // Adding a scale of 0 is always allowed (it has no effect)
		}
		switch (memory_type) {
			case type::DIRECT:
				return true;
			case type::REGISTER:
				return true;
			case type::DISPLACEMENT:
				return true;
			case type::SCALED_INDEX: {
				const auto si = std::get<scaled_index>(value);
				if (si.index == reg) {
					return true; // Adding the same register as index is allowed (scale will be adjusted)
				}
				if (si.scale == 0) {
					return true; // Can add index if scale is 0
				}
				if (si.base == reg && si.scale == 1) {
					return true; // Can add if base is the same and scale is 1 (so they can be swapped)
				}
				if (si.base == si.index && si.scale == -1) {
					return true; // Can add if base and index are the same, and they add to 0 (so they can be merged)
				}
				return false; // Cannot add another register if both base and index are occupied
			}
			case type::SCALED_INDEX_DISPLACEMENT: {
				const auto sid = std::get<scaled_index_displacement>(value);
				if (sid.index == reg) {
					return true; // Adding the same register as index is allowed (scale will be adjusted)
				}
				if (sid.scale == 0) {
					return true; // Can add index if scale is 0
				}
				if (sid.base == reg && sid.scale == 1) {
					return true; // Can add if base is the same and scale is 1 (so they can be swapped)
				}
				if (sid.base == sid.index && sid.scale == -1) {
					return true; // Can add if base and index are the same, and they add to 0 (so they can be merged)
				}
				return false; // Cannot add another register if both base and index are occupied
			}
		}
		return false;
	}
	assembly_memory assembly_memory::add_scaled_register(machine::register_t reg, int16_t scale) const {
		if (scale == 1) {
			return add_register(reg);
		}
		if (scale == 0) {
			return *this; // Adding a scale of 0 has no effect
		}
		switch (memory_type) {
			case type::DIRECT: {
				auto dir = std::get<extended_assembly_literal>(value);
				return assembly_memory(reg, reg, scale - 1, dir);
			}
			case type::REGISTER: {
				const auto base = std::get<machine::register_t>(value);
				return assembly_memory(base, reg, scale);
			}
			case type::DISPLACEMENT: {
				const auto d = std::get<displacement>(value);
				return assembly_memory(d.reg, reg, scale, d.disp);
			}
			case type::SCALED_INDEX: {
				const auto si = std::get<scaled_index>(value);
				if (si.index == reg) {
					// Adding the same register as index, increment scale
					return assembly_memory(si.base, si.index, si.scale + scale);
				}
				if (si.scale == 0) {
					// Scale is 0, just set the index to the new register with the given scale
					return assembly_memory(si.base, reg, scale);
				}
				if (si.base == reg && si.scale == 1) {
					// Base is the same as the new register and scale is 1, swap base and index
					return assembly_memory(si.index, si.base, scale + 1);
				}
				if (si.base == si.index && si.scale == -scale) {
					// Base and index are the same, and they add to 0
					return assembly_memory(reg, reg, scale - 1);
				}
				throw std::runtime_error("Cannot add another register to this memory operand");
			}
			case type::SCALED_INDEX_DISPLACEMENT: {
				const auto sid = std::get<scaled_index_displacement>(value);
				if (sid.index == reg) {
					// Adding the same register as index, increment scale
					return assembly_memory(sid.base, sid.index, sid.scale + scale, sid.disp);
				}
				if (sid.scale == 0) {
					// Scale is 0, just set the index to the new register with the given scale
					return assembly_memory(sid.base, reg, scale, sid.disp);
				}
				if (sid.base == reg && sid.scale == 1) {
					// Base is the same as the new register and scale is 1, swap base and index
					return assembly_memory(sid.index, sid.base, scale + 1, sid.disp);
				}
				if (sid.base == sid.index && sid.scale == -scale) {
					// Base and index are the same, and they add to 0
					return assembly_memory(reg, reg, scale - 1, sid.disp);
				}
				throw std::runtime_error("Cannot add another register to this memory operand");
			}
		}
		throw std::runtime_error("Unknown memory type");
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
	uint32_t resolve_literal(const extended_assembly_literal& lit,
		const std::unordered_map<std::string, uint32_t>& label_map) {
		switch (lit.type) {
			case extended_assembly_literal::type_t::VALUE:
				return resolve_literal(std::get<assembly_literal>(lit.value), label_map);
			case extended_assembly_literal::type_t::ADD: {
				const auto& op = std::get<extended_assembly_literal::binary_operation>(lit.value);
				return resolve_literal(*op.left, label_map) + resolve_literal(*op.right, label_map);
			}
			case extended_assembly_literal::type_t::SUB: {
				const auto& op = std::get<extended_assembly_literal::binary_operation>(lit.value);
				return resolve_literal(*op.left, label_map) - resolve_literal(*op.right, label_map);
			}
			case extended_assembly_literal::type_t::MUL: {
				const auto& op = std::get<extended_assembly_literal::binary_operation>(lit.value);
				return resolve_literal(*op.left, label_map) * resolve_literal(*op.right, label_map);
			}
		}
		throw std::runtime_error("Unknown extended literal type");
	}
	machine::memory_operand assemble_memory(const assembly_memory& mem,
		const std::unordered_map<std::string, uint32_t>& label_map) {
		switch (mem.memory_type) {
			case assembly_memory::type::DIRECT: {
				const auto addr = resolve_literal(std::get<extended_assembly_literal>(mem.value), label_map);
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
	machine::memory_pointer_operand assemble_memory_pointer(const assembly_memory_pointer& mem,
		const std::unordered_map<std::string, uint32_t>& label_map) {
		const auto size = mem.size;
		const auto base = mem.mem;
		const auto assembled_mem = assemble_memory(base, label_map);
		return machine::memory_pointer_operand(size, assembled_mem);
	}
	machine::result_arg assemble_result(const assembly_result& res,
		const std::unordered_map<std::string, uint32_t>& label_map) {
		switch (res.result_type) {
			case assembly_result::type::REGISTER: {
				const auto reg = std::get<machine::register_t>(res.value);
				return machine::result_arg{reg};
			}
			case assembly_result::type::MEMORY_POINTER: {
				const auto mem = std::get<assembly_memory_pointer>(res.value);
				return machine::result_arg{assemble_memory_pointer(mem, label_map)};
			}
		}
		throw std::runtime_error("Unknown result type");
	}
	machine::operand_arg assemble_operand(const assembly_operand& op,
		const std::unordered_map<std::string, uint32_t>& label_map) {
		switch (op.operand_type) {
			case assembly_operand::type::REGISTER: {
				const auto reg = std::get<machine::register_t>(op.value);
				return machine::operand_arg{reg};
			}
			case assembly_operand::type::LITERAL: {
				const auto lit = std::get<extended_assembly_literal>(op.value);
				const auto imm = resolve_literal(lit, label_map);
				return machine::operand_arg{imm};
			}
			case assembly_operand::type::MEMORY_POINTER: {
				const auto mem = std::get<assembly_memory_pointer>(op.value);
				return machine::operand_arg{assemble_memory_pointer(mem, label_map)};
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
			else if constexpr (std::is_same_v<T, assembly_instruction::args_mr_t>) {
				const auto mem = a.mem;
				const auto res = a.result;
				result = machine::instruction_t(op, machine::args_t<1, true, machine::memory_operand>{
					{assemble_memory(mem, label_map)},
					assemble_result(res, label_map)
				});
			}
			else {
				throw std::runtime_error("Unhandled args type in assemble_instruction");
			}
		}, args);
		return result;
	}
	void retrieve_labels(const assembly_program_t& assembly_program, std::unordered_map<std::string, uint32_t>& label_map,
		bool byte_addressing,
		uint32_t start_address) {
		uint32_t address = start_address;
		for (const auto& comp : assembly_program) {
			if (comp.component_type == assembly_component::type::LABEL) {
				const auto& label = std::get<std::string>(comp.value);
				if (label_map.contains(label)) {
					std::cerr << "Warning: Duplicate label definition: " << label << std::endl;
				}
				else {
					label_map[label] = address;
				}
			}
			else if (comp.component_type == assembly_component::type::INSTRUCTION) {
				if (byte_addressing) {
					const auto& inst = std::get<assembly_instruction>(comp.value);
					address += inst.instruction_size();
				}
				else {
					++address; // Each instruction is 1 address unit
				}
			}
			else if (comp.component_type == assembly_component::type::RAW_DATA) {
				if (byte_addressing) {
					const auto& data = std::get<std::vector<uint8_t>>(comp.value);
					address += static_cast<uint32_t>(data.size());
				}
				else {
					const auto& data = std::get<std::vector<uint8_t>>(comp.value);
					address += static_cast<uint32_t>((data.size() + 3) / 4); // Round up to nearest 4 bytes
				}
			}
			else {
				throw std::runtime_error("Unknown assembly component type");
			}
		}
	}

	machine::simple_program_t assemble_simple(const assembly_program_t& assembly_program,
		bool byte_addressing,
		uint32_t start_address) {
		machine::simple_program_t program;
		std::unordered_map<std::string, uint32_t> label_map;
		retrieve_labels(assembly_program, label_map, byte_addressing, start_address);
		program.reserve(assembly_program.size() - label_map.size());
		for (const auto& comp : assembly_program) {
			if (comp.component_type == assembly_component::type::INSTRUCTION) {
				const auto& inst = std::get<assembly_instruction>(comp.value);
				program.emplace_back(assemble_instruction(inst, label_map));
			}
			else if (comp.component_type == assembly_component::type::RAW_DATA) {
				throw std::runtime_error("Unsupported raw data in simple assembly");
			}
		}
		return program;
	}
	machine::program_t assemble(const assembly_program_t& assembly_program,
		bool byte_addressing,
		uint32_t start_address) {
		machine::program_t program;
		std::unordered_map<std::string, uint32_t> label_map;
		retrieve_labels(assembly_program, label_map, byte_addressing, start_address);
		program.reserve(assembly_program.size() - label_map.size());
		for (const auto& comp : assembly_program) {
			if (comp.component_type == assembly_component::type::INSTRUCTION) {
				const auto& inst = std::get<assembly_instruction>(comp.value);
				program.emplace_back(assemble_instruction(inst, label_map));
			}
			else if (comp.component_type == assembly_component::type::RAW_DATA) {
				const auto& data = std::get<std::vector<uint8_t>>(comp.value);
				program.emplace_back(data);
			}
		}
		return program;
	}

	uint32_t program_size(const assembly_program_t& assembly_program) {
		uint32_t size = 0;
		for (const auto& comp : assembly_program) {
			size += comp.instruction_size();
		}
		return size;
	}
}
