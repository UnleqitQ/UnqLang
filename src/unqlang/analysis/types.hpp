#pragma once

#include <memory>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>
#include <unordered_map>

#include "types.hpp"
#include "../ast.hpp"

namespace unqlang::analysis::types {
	struct type_node;
	enum class primitive_type {
		VOID,
		BOOL,
		CHAR,
		INT,
	};
	struct array_type {
		std::shared_ptr<type_node> element_type;
		size_t size;
		array_type() : element_type(std::make_shared<type_node>(primitive_type::VOID)), size(0) {
		}
		array_type(std::shared_ptr<type_node> et, size_t s) : element_type(std::move(et)), size(s) {
		}
		array_type(primitive_type et, size_t s)
			: element_type(std::make_shared<type_node>(et)), size(s) {
		}
	};
	struct pointer_type {
		std::shared_ptr<type_node> pointee_type;

		pointer_type() : pointee_type(std::make_shared<type_node>(primitive_type::VOID)) {
		}
		explicit pointer_type(std::shared_ptr<type_node> pt) : pointee_type(std::move(pt)) {
		}
		explicit pointer_type(primitive_type pt)
			: pointee_type(std::make_shared<type_node>(pt)) {
		}
	};
	struct function_type {
		std::shared_ptr<type_node> return_type;
		std::vector<std::shared_ptr<type_node>> parameter_types;

		function_type() : return_type(std::make_shared<type_node>(primitive_type::VOID)), parameter_types() {
		}
		function_type(std::shared_ptr<type_node> rt, std::vector<std::shared_ptr<type_node>> pt)
			: return_type(std::move(rt)), parameter_types(std::move(pt)) {
		}
		function_type(const std::vector<std::shared_ptr<type_node>>& param_types)
			: return_type(std::make_shared<type_node>(primitive_type::VOID)), parameter_types(param_types) {
		}
		function_type(primitive_type rt, const std::vector<std::shared_ptr<type_node>>& param_types)
			: return_type(std::make_shared<type_node>(rt)), parameter_types(param_types) {
		}
		function_type(primitive_type rt, const std::vector<primitive_type>& param_types)
			: return_type(std::make_shared<type_node>(rt)) {
			for (const auto& pt : param_types) {
				parameter_types.push_back(std::make_shared<type_node>(pt));
			}
		}
	};
	struct struct_type {
		struct member {
			std::string name;
			std::shared_ptr<type_node> type;
			member() : name(""), type(std::make_shared<type_node>(primitive_type::VOID)) {
			}
			member(std::string n, std::shared_ptr<type_node> t) : name(std::move(n)), type(std::move(t)) {
			}
			member(std::string n, primitive_type t) : name(std::move(n)), type(std::make_shared<type_node>(t)) {
			}
		};
		std::vector<member> members;
	};
	struct union_type {
		struct member {
			std::string name;
			std::shared_ptr<type_node> type;

			member() : name(""), type(std::make_shared<type_node>(primitive_type::VOID)) {
			}
			member(std::string n, std::shared_ptr<type_node> t) : name(std::move(n)), type(std::move(t)) {
			}
			member(std::string n, primitive_type t) : name(std::move(n)), type(std::make_shared<type_node>(t)) {
			}
		};
		std::vector<member> members;
	};
	struct type_node {
		enum class kind_t {
			PRIMITIVE,
			ARRAY,
			POINTER,
			FUNCTION,
			STRUCT,
			UNION,
			CUSTOM
		} kind;
		std::variant<
			primitive_type, // Primitive types
			array_type, // Array types
			pointer_type, // Pointer types
			function_type, // Function types
			struct_type, // Struct types
			union_type, // Union types
			std::string, // Custom types (by name)
			std::monostate // For uninitialized types
		> value;

		type_node() : kind(kind_t::PRIMITIVE), value(primitive_type::VOID) {
		}
		explicit type_node(kind_t type) : kind(type), value(std::monostate{}) {
			if (type != kind_t::STRUCT && type != kind_t::UNION) {
				throw std::runtime_error("Only struct and union types can be uninitialized");
			}
		}
		type_node(primitive_type pt) : kind(kind_t::PRIMITIVE), value(pt) {
		}
		type_node(array_type at) : kind(kind_t::ARRAY), value(at) {
		}
		type_node(pointer_type pt) : kind(kind_t::POINTER), value(pt) {
		}
		type_node(function_type ft) : kind(kind_t::FUNCTION), value(ft) {
		}
		type_node(struct_type st) : kind(kind_t::STRUCT), value(st) {
		}
		type_node(union_type ut) : kind(kind_t::UNION), value(ut) {
		}
		type_node(std::string ct) : kind(kind_t::CUSTOM), value(ct) {
		}

		/**
		 * Compares two type_nodes for equality. This does not resolve custom types. Use type_system::is_equivalent instead.
		 * @param other The other type_node to compare with
		 * @return True if the types are equal, false otherwise
		 */
		bool operator==(const type_node& other) const {
			if (kind != other.kind) {
				return false;
			}
			switch (kind) {
				case kind_t::PRIMITIVE:
					return std::get<primitive_type>(value) == std::get<primitive_type>(other.value);
				case kind_t::ARRAY: {
					const auto& a = std::get<array_type>(value);
					const auto& b = std::get<array_type>(other.value);
					return a.size == b.size && *a.element_type == *b.element_type;
				}
				case kind_t::POINTER: {
					const auto& a = std::get<pointer_type>(value);
					const auto& b = std::get<pointer_type>(other.value);
					return *a.pointee_type == *b.pointee_type;
				}
				case kind_t::FUNCTION: {
					const auto& a = std::get<function_type>(value);
					const auto& b = std::get<function_type>(other.value);
					if (*a.return_type != *b.return_type) {
						return false;
					}
					if (a.parameter_types.size() != b.parameter_types.size()) {
						return false;
					}
					for (size_t i = 0; i < a.parameter_types.size(); i++) {
						if (*a.parameter_types[i] != *b.parameter_types[i]) {
							return false;
						}
					}
					return true;
				}
				case kind_t::STRUCT: {
					const auto& a = std::get<struct_type>(value);
					const auto& b = std::get<struct_type>(other.value);
					if (a.members.size() != b.members.size()) {
						return false;
					}
					for (size_t i = 0; i < a.members.size(); i++) {
						if (*a.members[i].type != *b.members[i].type) {
							return false;
						}
					}
					return true;
				}
				case kind_t::UNION: {
					const auto& a = std::get<union_type>(value);
					const auto& b = std::get<union_type>(other.value);
					if (a.members.size() != b.members.size()) {
						return false;
					}
					for (size_t i = 0; i < a.members.size(); i++) {
						if (*a.members[i].type != *b.members[i].type) {
							return false;
						}
					}
					return true;
				}
				case kind_t::CUSTOM: {
					return std::get<std::string>(value) == std::get<std::string>(other.value);
				}
			}
			return false;
		}
		bool operator!=(const type_node& other) const {
			return !(*this == other);
		}
	};

	class type_system {
		struct type_info {
			size_t size;
		};
		std::unordered_map<std::string, type_node> m_custom_types;
		mutable std::unordered_map<std::string, type_info> m_type_info;
		bool m_arch_64bit = false;

	public:
		void declare_type(const std::string& name, const type_node::kind_t kind) {
			if (m_custom_types.contains(name)) {
				if (!std::holds_alternative<std::monostate>(m_custom_types[name].value)) {
					throw std::runtime_error("Type already declared and initialized: " + name);
				}
				if (m_custom_types[name].kind != kind) {
					throw std::runtime_error("Type kind mismatch for type: " + name);
				}
				return;
			}
			m_custom_types[name] = type_node(kind);
		}
		void declare_initialized_type(const std::string& name, const type_node& type) {
			if (m_custom_types.contains(name)) {
				if (!std::holds_alternative<std::monostate>(m_custom_types[name].value)) {
					throw std::runtime_error("Type already declared and initialized: " + name);
				}
				if (m_custom_types[name].kind != type.kind) {
					throw std::runtime_error("Type kind mismatch for type: " + name);
				}
			}
			m_custom_types[name] = type;
		}
		type_node get_type(const std::string& name) const {
			if (!m_custom_types.contains(name)) {
				throw std::runtime_error("Type not declared: " + name);
			}
			return m_custom_types.at(name);
		}
		bool is_type_declared(const std::string& name) const {
			return m_custom_types.contains(name);
		}
		bool is_type_initialized(const std::string& name) const {
			if (!m_custom_types.contains(name)) {
				return false;
			}
			return !std::holds_alternative<std::monostate>(m_custom_types.at(name).value);
		}
		void validate_type(const type_node& type, bool allow_incomplete = false) const;
		/**
		 * Unwraps a type by resolving custom types to their definitions. This does not
		 * unwrap pointers or functions.
		 * @param type The type to unwrap
		 * @return The unwrapped type
		 */
		type_node unwrap_type(const type_node& type) const;
		size_t get_type_size(const type_node& type) const;
		size_t get_type_size(const std::string& name) const;
		struct member_info {
			size_t index;
			size_t offset;
			std::shared_ptr<type_node> type;
		};

		member_info get_struct_member_info(const type_node& type, const std::string& member_name) const;
		member_info get_struct_member_info(const struct_type& type, const std::string& member_name) const;
		member_info get_union_member_info(const type_node& type, const std::string& member_name) const;
		member_info get_union_member_info(const union_type& type, const std::string& member_name) const;

		struct compare_options {
			bool ignore_pointers = false;
			bool ignore_functions = false;
			bool check_member_names = true;

			compare_options() {
			}
			compare_options(bool ignore_pointers, bool ignore_functions, bool check_member_names)
				: ignore_pointers(ignore_pointers), ignore_functions(ignore_functions), check_member_names(check_member_names) {
			}
		};

		bool is_equivalent(const type_node& a, const type_node& b, compare_options options = compare_options()) const;

		static type_node from_ast(const unqlang::ast_type_node& ast_type);
	};
} // namespace compiler::analysis::types
