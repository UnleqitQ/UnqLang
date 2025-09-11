#pragma once

#include <memory>
#include <string>
#include <unordered_map>

#include "types.hpp"

namespace unqlang::analysis::variables {
	struct variable_info {
		std::string name;
		types::type_node type;
		bool is_mutable = true; // true if variable is mutable (not const)

		variable_info() : name(""), type(types::primitive_type::VOID) {
		}
		variable_info(std::string n, types::type_node t) : name(std::move(n)), type(std::move(t)) {
		}
	};

	struct storage {
		enum class storage_type_t {
			Global,
			Function,
			Block,
		} storage_type;
		std::shared_ptr<storage> parent; // nullptr if global scope
		std::unordered_map<std::string, variable_info> variables;

		storage() : storage_type(storage_type_t::Global), parent(nullptr) {
		}
		explicit storage(storage_type_t st, std::shared_ptr<storage> p = nullptr)
			: storage_type(st), parent(std::move(p)), variables() {
		}

		bool declare_variable(const std::string& name, const types::type_node& type, bool is_mutable = true) {
			if (variables.contains(name)) {
				return false; // already declared in this scope
			}
			variables[name] = variable_info(name, type);
			variables[name].is_mutable = is_mutable;
			return true;
		}
		variable_info get_variable(const std::string& name, bool search_parent = true) const {
			if (variables.contains(name)) {
				return variables.at(name);
			}
			if (search_parent && parent != nullptr) {
				return parent->get_variable(name, true);
			}
			throw std::runtime_error("Variable not declared: " + name);
		}
		bool is_variable_declared(const std::string& name, bool search_parent = true) const {
			if (variables.contains(name)) {
				return true;
			}
			if (search_parent && parent != nullptr) {
				return parent->is_variable_declared(name, true);
			}
			return false;
		}
	};
} // unqlang::analysis::variables
