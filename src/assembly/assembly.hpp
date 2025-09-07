#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>
#include <variant>

#include "../machine/instruction.hpp"
#include "../machine/ram.hpp"
#include "../machine/register.hpp"

namespace assembly {
	struct assembly_literal {
		enum class type : uint8_t {
			NUMBER,
			LABEL
		} literal_type;
		std::variant<int32_t, std::string> value;
		explicit assembly_literal(int32_t num)
			: literal_type(type::NUMBER), value(num) {
		}
		explicit assembly_literal(const std::string& label)
			: literal_type(type::LABEL), value(label) {
		}
		std::string to_string(bool hex = false) const;
		friend std::ostream& operator<<(std::ostream& os, const assembly_literal& lit) {
			return os << lit.to_string();
		}
	};
	struct assembly_memory {
		enum class type : uint8_t {
			DIRECT, // [label] or [number]
			REGISTER, // [register]
			DISPLACEMENT, // [register + number]
			SCALED_INDEX, // [register + register * scale]
			SCALED_INDEX_DISPLACEMENT // [register + register * scale + number]
		};
		struct displacement {
			machine::register_t reg;
			assembly_literal disp;
		};
		struct scaled_index {
			machine::register_t base;
			machine::register_t index;
			int8_t scale; // typically 1, 2, 4, or 8, but others are allowed
		};
		struct scaled_index_displacement {
			machine::register_t base;
			machine::register_t index;
			int8_t scale;
			assembly_literal disp;
		};
		type memory_type;
		std::variant<assembly_literal, machine::register_t, displacement, scaled_index, scaled_index_displacement> value;
		machine::data_size_t size = machine::data_size_t::DWORD; // Default to DWORD
		explicit assembly_memory(assembly_literal lit)
			: memory_type(type::DIRECT), value(lit) {
		}
		explicit assembly_memory(machine::register_t reg)
			: memory_type(type::REGISTER), value(reg) {
		}
		assembly_memory(machine::register_t reg, assembly_literal disp)
			: memory_type(type::DISPLACEMENT), value(displacement{reg, disp}) {
		}
		assembly_memory(machine::register_t base, machine::register_t index, int8_t scale)
			: memory_type(type::SCALED_INDEX), value(scaled_index{base, index, scale}) {
		}
		assembly_memory(machine::register_t base, machine::register_t index, int8_t scale, assembly_literal disp)
			: memory_type(type::SCALED_INDEX_DISPLACEMENT), value(scaled_index_displacement{base, index, scale, disp}) {
		}
		assembly_memory with_size(machine::data_size_t sz) const {
			assembly_memory mem = *this;
			mem.size = sz;
			return mem;
		}
		std::string to_string() const;
		friend std::ostream& operator<<(std::ostream& os, const assembly_memory& mem) {
			return os << mem.to_string();
		}
	};
	struct assembly_operand {
		enum class type : uint8_t {
			REGISTER,
			LITERAL,
			MEMORY
		} operand_type;
		std::variant<
			machine::register_t,
			assembly_literal,
			assembly_memory
		> value;

		explicit assembly_operand(machine::register_t reg)
			: operand_type(type::REGISTER), value(reg) {
		}
		explicit assembly_operand(assembly_literal lit)
			: operand_type(type::LITERAL), value(lit) {
		}
		explicit assembly_operand(assembly_memory mem)
			: operand_type(type::MEMORY), value(mem) {
		}
		friend std::ostream& operator<<(std::ostream& os, const assembly_operand& op) {
			switch (op.operand_type) {
				case type::REGISTER:
					os << std::get<machine::register_t>(op.value);
					break;
				case type::LITERAL:
					os << std::get<assembly_literal>(op.value);
					break;
				case type::MEMORY:
					os << std::get<assembly_memory>(op.value);
					break;
			}
			return os;
		}
	};
	struct assembly_result {
		enum class type : uint8_t {
			REGISTER,
			MEMORY
		} result_type;
		std::variant<
			machine::register_t,
			assembly_memory
		> value;

		explicit assembly_result(machine::register_t reg)
			: result_type(type::REGISTER), value(reg) {
		}
		explicit assembly_result(assembly_memory mem)
			: result_type(type::MEMORY), value(mem) {
		}
		friend std::ostream& operator<<(std::ostream& os, const assembly_result& res) {
			switch (res.result_type) {
				case type::REGISTER:
					os << std::get<machine::register_t>(res.value);
					break;
				case type::MEMORY:
					os << std::get<assembly_memory>(res.value);
					break;
			}
			return os;
		}
	};
	struct assembly_instruction {
		template<size_t N, bool HasResult>
		struct args_t {
			std::array<assembly_operand, N> operands;
			std::conditional_t<HasResult, assembly_result, std::monostate> result;

			args_t() = default;
			args_t(const std::array<assembly_operand, N>& ops, assembly_result res)
				: operands(ops), result(res) {
				static_assert(HasResult, "Result provided for args_t with HasResult == false");
			}
			explicit args_t(const std::array<assembly_operand, N>& ops)
				: operands(ops), result(std::monostate{}) {
				static_assert(!HasResult, "No result provided for args_t with HasResult == true");
			}

			friend std::ostream& operator<<(std::ostream& os, const args_t& args) {
				if constexpr (HasResult) {
					os << args.result;
					if (N > 0) {
						os << ", ";
					}
				}
				for (size_t i = 0; i < N; ++i) {
					os << args.operands[i];
					if (i < N - 1) {
						os << ", ";
					}
				}
				return os;
			}
		};

		machine::operation op;
		std::variant<
			args_t<2, false>, // Binary without result
			args_t<1, true>, // Unary with result
			args_t<1, false>, // Unary without result
			args_t<0, true>, // Nullary with result
			args_t<0, false> // Nullary without result
		> args;

		friend std::ostream& operator<<(std::ostream& os, const assembly_instruction& inst) {
			os << inst.op;
			os << " ";
			std::visit([&os](const auto& a) { os << a; }, inst.args);
			return os;
		}
	};
	struct assembly_component {
		enum class type : uint8_t {
			LABEL,
			INSTRUCTION
		} component_type;
		std::variant<std::string, assembly_instruction> value;
		friend std::ostream& operator<<(std::ostream& os, const assembly_component& comp) {
			switch (comp.component_type) {
				case type::LABEL:
					os << std::format("%{}:", std::get<std::string>(comp.value));
					break;
				case type::INSTRUCTION:
					os << std::get<assembly_instruction>(comp.value);
					break;
			}
			return os;
		}
	};
  typedef std::vector<assembly_component> assembly_program_t;

	machine::instruction_t assemble_instruction(const assembly_instruction& inst, const std::unordered_map<std::string, uint32_t>& label_map);
	void retrieve_labels(const assembly_program_t& assembly_program, std::unordered_map<std::string, uint32_t>& label_map, uint32_t start_address = 0);
	machine::program_t assemble(const assembly_program_t& assembly_program, uint32_t start_address = 0);
} // assembly
