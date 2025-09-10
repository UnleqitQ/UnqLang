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

			static constexpr uint32_t SIZE = 1 + 4; // reg (1) + disp (4)
		};
		struct scaled_index {
			machine::register_t base;
			machine::register_t index;
			int8_t scale; // typically 1, 2, 4, or 8, but others are allowed

			static constexpr uint32_t SIZE = 1 + 1 + 1; // base (1) + index (1) + scale (1)
		};
		struct scaled_index_displacement {
			machine::register_t base;
			machine::register_t index;
			int8_t scale;
			assembly_literal disp;

			static constexpr uint32_t SIZE = 1 + 1 + 1 + 4; // base (1) + index (1) + scale (1) + disp (4)
		};
		type memory_type;
		std::variant<assembly_literal, machine::register_t, displacement, scaled_index, scaled_index_displacement> value;
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
		std::string to_string() const;
		friend std::ostream& operator<<(std::ostream& os, const assembly_memory& mem) {
			return os << mem.to_string();
		}

		uint32_t instruction_size() const {
			switch (memory_type) {
				case type::DIRECT:
					return 4; // address (4)
				case type::REGISTER:
					return 1; // reg (1)
				case type::DISPLACEMENT:
					return displacement::SIZE;
				case type::SCALED_INDEX:
					return scaled_index::SIZE;
				case type::SCALED_INDEX_DISPLACEMENT:
					return scaled_index_displacement::SIZE;
			}
			return 0; // Should never reach here
		}
	};
	struct assembly_memory_pointer {
		machine::data_size_t size;
		assembly_memory mem;
		assembly_memory_pointer(machine::data_size_t sz, assembly_memory m)
			: size(sz), mem(m) {
		}
		std::string to_string() const {
			return std::format("{} ptr {}", size, mem.to_string());
		}
		friend std::ostream& operator<<(std::ostream& os, const assembly_memory_pointer& ptr) {
			os << ptr.size << " ptr " << ptr.mem;
			return os;
		}

		uint32_t instruction_size() const {
			return mem.instruction_size() + 1; // +1 for size and type specifier
		}
	};
	struct assembly_operand {
		enum class type : uint8_t {
			REGISTER,
			LITERAL,
			MEMORY_POINTER
		} operand_type;
		std::variant<
			machine::register_t,
			assembly_literal,
			assembly_memory_pointer
		> value;

		explicit assembly_operand(machine::register_t reg)
			: operand_type(type::REGISTER), value(reg) {
		}
		explicit assembly_operand(assembly_literal lit)
			: operand_type(type::LITERAL), value(lit) {
		}
		explicit assembly_operand(assembly_memory_pointer mem)
			: operand_type(type::MEMORY_POINTER), value(mem) {
		}
		friend std::ostream& operator<<(std::ostream& os, const assembly_operand& op) {
			switch (op.operand_type) {
				case type::REGISTER:
					os << std::get<machine::register_t>(op.value);
					break;
				case type::LITERAL:
					os << std::get<assembly_literal>(op.value);
					break;
				case type::MEMORY_POINTER:
					os << std::get<assembly_memory_pointer>(op.value);
					break;
			}
			return os;
		}

		uint32_t instruction_size() const {
			switch (operand_type) {
				case type::REGISTER:
					return 1; // reg (1)
				case type::LITERAL:
					return 4; // literal (4)
				case type::MEMORY_POINTER:
					return std::get<assembly_memory_pointer>(value).instruction_size();
			}
			return 0; // Should never reach here
		}
	};
	struct assembly_result {
		enum class type : uint8_t {
			REGISTER,
			MEMORY_POINTER
		} result_type;
		std::variant<
			machine::register_t,
			assembly_memory_pointer
		> value;

		explicit assembly_result(machine::register_t reg)
			: result_type(type::REGISTER), value(reg) {
		}
		explicit assembly_result(assembly_memory_pointer mem)
			: result_type(type::MEMORY_POINTER), value(mem) {
		}
		friend std::ostream& operator<<(std::ostream& os, const assembly_result& res) {
			switch (res.result_type) {
				case type::REGISTER:
					os << std::get<machine::register_t>(res.value);
					break;
				case type::MEMORY_POINTER:
					os << std::get<assembly_memory_pointer>(res.value);
					break;
			}
			return os;
		}

		uint32_t instruction_size() const {
			switch (result_type) {
				case type::REGISTER:
					return 1; // reg (1)
				case type::MEMORY_POINTER:
					return std::get<assembly_memory_pointer>(value).instruction_size();
			}
			return 0; // Should never reach here
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

			friend std::ostream& operator<<(std::ostream& os, const args_t& ags) {
				if constexpr (HasResult) {
					os << ags.result;
					if (N > 0) {
						os << ", ";
					}
				}
				for (size_t i = 0; i < N; ++i) {
					os << ags.operands[i];
					if (i < N - 1) {
						os << ", ";
					}
				}
				return os;
			}
		};
		struct args_mr_t {
			assembly_memory mem;
			assembly_result result;

			args_mr_t(assembly_memory m, assembly_result res)
				: mem(m), result(res) {
			}
			friend std::ostream& operator<<(std::ostream& os, const args_mr_t& ags) {
				os << ags.result << ", " << ags.mem;
				return os;
			}
		};

		machine::operation op;
		std::variant<
			args_t<2, false>, // Binary without result
			args_t<1, true>, // Unary with result
			args_t<1, false>, // Unary without result
			args_t<0, true>, // Nullary with result
			args_t<0, false>, // Nullary without result
			args_mr_t // Memory to result (for LEA)
		> args;

		assembly_instruction(machine::operation operation, assembly_result result, assembly_operand op1)
			: op(operation), args(args_t<1, true>{{op1}, result}) {
		}
		assembly_instruction(machine::operation operation, assembly_operand op1)
			: op(operation), args(args_t<1, false>{{op1}}) {
		}
		assembly_instruction(machine::operation operation, assembly_operand op1, assembly_operand op2)
			: op(operation), args(args_t<2, false>{{op1, op2}}) {
		}
		assembly_instruction(machine::operation operation, assembly_result result)
			: op(operation), args(args_t<0, true>{{}, result}) {
		}
		assembly_instruction(machine::operation operation, assembly_result result, assembly_memory mem)
			: op(operation), args(args_mr_t{mem, result}) {
			if (operation != machine::operation::LEA) {
				throw std::invalid_argument("Only LEA instruction can use memory-to-result args");
			}
		}
		explicit assembly_instruction(machine::operation operation)
			: op(operation), args(args_t<0, false>{{}}) {
		}

		template<size_t N, bool HasResult>
		assembly_instruction(machine::operation operation, const args_t<N, HasResult>& arguments)
			: op(operation), args(arguments) {
		}
		assembly_instruction(machine::operation operation, const args_mr_t& arguments)
			: op(operation), args(arguments) {
			if (operation != machine::operation::LEA) {
				throw std::invalid_argument("Only LEA instruction can use memory-to-result args");
			}
		}

		friend std::ostream& operator<<(std::ostream& os, const assembly_instruction& inst) {
			os << inst.op;
			os << " ";
			std::visit([&os](const auto& a) { os << a; }, inst.args);
			return os;
		}

		uint32_t instruction_size() const {
			uint32_t size = 1; // 1 byte for operation
			if (std::holds_alternative<args_t<2, false>>(args)) {
				size += 1; // 1 byte for args types
				size += std::get<args_t<2, false>>(args).operands[0].instruction_size();
				size += std::get<args_t<2, false>>(args).operands[1].instruction_size();
			}
			else if (std::holds_alternative<args_t<1, true>>(args)) {
				size += 1; // 1 byte for args types
				size += std::get<args_t<1, true>>(args).result.instruction_size();
				size += std::get<args_t<1, true>>(args).operands[0].instruction_size();
			}
			else if (std::holds_alternative<args_t<1, false>>(args)) {
				size += 1; // 1 byte for args types
				size += std::get<args_t<1, false>>(args).operands[0].instruction_size();
			}
			else if (std::holds_alternative<args_t<0, true>>(args)) {
				size += std::get<args_t<0, true>>(args).result.instruction_size();
			}
			else if (std::holds_alternative<args_mr_t>(args)) {
				size += std::get<args_mr_t>(args).mem.instruction_size();
				size += std::get<args_mr_t>(args).result.instruction_size();
			}
			return size;
		}
	};
	struct assembly_component {
		enum class type : uint8_t {
			LABEL,
			INSTRUCTION,
			RAW_DATA
		} component_type;
		std::variant<
			std::string,
			assembly_instruction,
			std::vector<uint8_t> // raw data
		> value;

		assembly_component(const std::string& label)
			: component_type(type::LABEL), value(label) {
		}
		assembly_component(const assembly_instruction& inst)
			: component_type(type::INSTRUCTION), value(inst) {
		}
		assembly_component(const std::vector<uint8_t>& data)
			: component_type(type::RAW_DATA), value(data) {
		}

		friend std::ostream& operator<<(std::ostream& os, const assembly_component& comp) {
			switch (comp.component_type) {
				case type::LABEL:
					os << std::format("%{}:", std::get<std::string>(comp.value));
					break;
				case type::INSTRUCTION:
					os << std::get<assembly_instruction>(comp.value);
					break;
				case type::RAW_DATA: {
					const auto& data = std::get<std::vector<uint8_t>>(comp.value);
					os << "db ";
					for (size_t i = 0; i < data.size(); ++i) {
						os << std::format("0x{:02X}", data[i]);
						if (i < data.size() - 1) {
							os << " ";
						}
					}
					break;
				}
			}
			return os;
		}

		uint32_t instruction_size() const {
			if (component_type == type::INSTRUCTION) {
				return std::get<assembly_instruction>(value).instruction_size();
			}
			return 0; // Labels do not contribute to instruction size
		}
	};
	typedef std::vector<assembly_component> assembly_program_t;

	machine::instruction_t assemble_instruction(const assembly_instruction& inst,
		const std::unordered_map<std::string, uint32_t>& label_map);
	void retrieve_labels(const assembly_program_t& assembly_program, std::unordered_map<std::string, uint32_t>& label_map,
		bool byte_addressing,
		uint32_t start_address = 0);
	machine::simple_program_t assemble_simple(const assembly_program_t& assembly_program, bool byte_addressing,
		uint32_t start_address = 0);
	machine::program_t assemble(const assembly_program_t& assembly_program, bool byte_addressing,
		uint32_t start_address = 0);
} // assembly
