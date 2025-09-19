#pragma once

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>

#include "types.hpp"
#include "../../assembly/assembly.hpp"
#include "../../machine/register.hpp"

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

	struct inline_function {
		struct parameter_info {
			types::type_node type;
			machine::register_t reg;
			parameter_info() : type(types::primitive_type::VOID), reg(machine::register_id::eax) {
			}
			parameter_info(const types::type_node& t, const machine::register_t r)
				: type(t), reg(r) {
			}
		};
		parameter_info return_value;
		std::vector<parameter_info> parameters;
		assembly::assembly_program_t implementation;
		inline_function()
			: return_value(), parameters(), implementation() {
		}
		inline_function(
			const parameter_info& rv,
			const std::vector<parameter_info>& params,
			const assembly::assembly_program_t& implementation
		)
			: return_value(rv), parameters(params), implementation(implementation) {
		}
	};

	struct inline_storage {
		std::unordered_map<std::string, inline_function> functions;

		inline_storage() : functions() {
		}

		void add_function(const std::string& name, const inline_function& func) {
			if (functions.contains(name)) {
				throw std::runtime_error("Inline function already defined: " + name);
			}
			functions[name] = func;
		}
		inline_function get_function(const std::string& name) const {
			if (functions.contains(name)) {
				return functions.at(name);
			}
			throw std::runtime_error("Inline function not defined: " + name);
		}
		bool is_function_defined(const std::string& name) const {
			return functions.contains(name);
		}
	};
} // unqlang::analysis::functions
