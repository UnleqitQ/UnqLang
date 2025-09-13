#pragma once
#include <optional>
#include <vector>
#include <string>
#include <memory>
#include <unordered_map>

#include "../analysis/types.hpp"

namespace unqlang::compiler {
	struct function_signature;
	struct assembly_function_signature;

	struct parameter_info {
		std::optional<std::string> name;
		analysis::types::type_node type;
		uint32_t index; // index in parameter list

		parameter_info() : name(std::nullopt), type(analysis::types::primitive_type::VOID), index(0) {
		}
		parameter_info(std::optional<std::string> n, analysis::types::type_node t, uint32_t i)
			: name(n), type(std::move(t)), index(i) {
		}
	};
	struct function_signature {
		analysis::types::type_node return_type;
		std::vector<parameter_info> parameters;
		bool is_variadic = false; // true if function is variadic (e.g., printf)

		function_signature() : return_type(analysis::types::primitive_type::VOID), parameters(), is_variadic(false) {
		}
		function_signature(analysis::types::type_node rt, std::vector<parameter_info> params, bool variadic = false)
			: return_type(std::move(rt)), parameters(std::move(params)), is_variadic(variadic) {
			if (is_variadic) {
				throw std::runtime_error("Variadic functions are not supported yet");
			}
		}

		std::shared_ptr<assembly_function_signature> build_assembly_signature(
			const analysis::types::type_system& type_system
		) const;
	};

	struct assembly_parameter_info : parameter_info {
		// offset from base pointer where this parameter is located (in the caller's stack frame - positive offset)
		// this starts at 8 (return address + old base pointer)
		uint32_t offset;

		assembly_parameter_info() : parameter_info(), offset(0) {
		}
		assembly_parameter_info(
			std::optional<std::string> n,
			analysis::types::type_node t,
			uint32_t i,
			uint32_t off
		)
			: parameter_info(std::move(n), std::move(t), i), offset(off) {
		}
	};

	struct assembly_function_signature {
		// the stack region for parameters is reused for the return value
		// this means the region must also be large enough to hold the return value
		analysis::types::type_node return_type;
		std::vector<assembly_parameter_info> parameters;
		std::unordered_map<std::string, uint32_t> name_index_map; // map from parameter name to index
		bool is_variadic = false; // true if function is variadic (e.g., printf)
		uint32_t parameter_stack_size = 0; // total size of parameters on the stack (for caller to allocate)
		uint32_t return_value_size = 0; // size of return value (0 if void)
		uint32_t stack_size = 0; // the maximum of parameter_stack_size and return_value_size

		assembly_function_signature()
			: return_type(analysis::types::primitive_type::VOID), parameters(), is_variadic(false) {
		}
		assembly_function_signature(
			analysis::types::type_node rt,
			std::vector<assembly_parameter_info> params,
			bool variadic = false
		)
			: return_type(std::move(rt)), parameters(std::move(params)), is_variadic(variadic) {
			if (is_variadic) {
				throw std::runtime_error("Variadic functions are not supported yet");
			}
		}
	};
} // unqlang::compiler
