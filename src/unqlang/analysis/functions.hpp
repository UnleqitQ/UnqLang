#pragma once

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>

#include "types.hpp"

namespace unqlang::analysis::functions {
	struct function_info {
		std::string name;
		types::type_node return_type;
		std::vector<types::type_node> parameter_types;
		// bool is_variadic = false; // true if function is variadic (e.g., printf)
		bool is_defined = false; // true if function has a body (not just a declaration)

		function_info() : name(""), return_type(types::primitive_type::VOID), parameter_types() {
		}
		function_info(std::string n, types::type_node rt, std::vector<types::type_node> pt)
			: name(std::move(n)), return_type(std::move(rt)), parameter_types(std::move(pt)) {
		}
	};

	struct storage {
		std::unordered_map<std::string, function_info> functions;

		storage() : functions() {
		}

		bool declare_function(
			const std::string& name,
			const types::type_node& return_type,
			const std::vector<types::type_node>& parameter_types,
			// bool is_variadic = false,
			bool is_defined = false
		);
		function_info get_function(const std::string& name) const {
			if (functions.contains(name)) {
				return functions.at(name);
			}
			throw std::runtime_error("Function not declared: " + name);
		}
		bool is_function_declared(const std::string& name) const {
			return functions.contains(name);
		}
	};
} // unqlang::analysis::functions
