#pragma once

#include <memory>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>
#include <unordered_map>

#include "types.hpp"
#include "../ast.hpp"
#include "../../machine/ram.hpp"

namespace unqlang::analysis::types {
	struct type_node;
	enum class primitive_type {
		// void type (only for functions that do not return a value, invalid otherwise)
		VOID,

		// bool type (pseudo type for true/false, essentially equivalent to char, but may allow some optimizations)
		BOOL,

		// char (8-bit)
		// signed char (8-bit signed integer type)
		SIGNED_CHAR,
		SCHAR = SIGNED_CHAR,
		// unsigned char (8-bit unsigned integer type)
		UNSIGNED_CHAR,
		UCHAR = UNSIGNED_CHAR,
		// char (8-bit without specified signedness, treated as unsigned char)
		CHAR = UNSIGNED_CHAR,

		// short (16-bit)
		// signed short int (16-bit signed integer type)
		SIGNED_SHORT,
		SHORT = SIGNED_SHORT,
		// unsigned short int (16-bit unsigned integer type)
		UNSIGNED_SHORT,
		USHORT = UNSIGNED_SHORT,

		// int (32-bit)
		// signed int (32-bit signed integer type)
		SIGNED_INT,
		INT = SIGNED_INT,
		// unsigned int (32-bit unsigned integer type)
		UNSIGNED_INT,
		UINT = UNSIGNED_INT,

		// long (64-bit) (long is used in place of long long, bc there is no point to have both imo)
		// signed long int (64-bit signed integer type)
		SIGNED_LONG,
		LONG = SIGNED_LONG,
		// unsigned long int (64-bit unsigned integer type)
		UNSIGNED_LONG,
		ULONG = UNSIGNED_LONG,

		// float (32-bit floating point type)
		FLOAT,
		// double (64-bit floating point type)
		DOUBLE,
	};

	inline machine::data_size_t to_data_size(primitive_type pt) {
		switch (pt) {
			case primitive_type::VOID:
				throw std::logic_error("Void type has no data size");
			case primitive_type::BOOL:
			case primitive_type::SIGNED_CHAR:
			case primitive_type::UNSIGNED_CHAR:
				return machine::data_size_t::BYTE;
			case primitive_type::SIGNED_SHORT:
			case primitive_type::UNSIGNED_SHORT:
				return machine::data_size_t::WORD;
			case primitive_type::SIGNED_INT:
			case primitive_type::UNSIGNED_INT:
			case primitive_type::FLOAT:
				return machine::data_size_t::DWORD;
			case primitive_type::SIGNED_LONG:
			case primitive_type::UNSIGNED_LONG:
			case primitive_type::DOUBLE:
				throw std::logic_error("64-bit types are not supported in the current machine model");
			default:
				throw std::logic_error("Unknown primitive type");
		}
	}

	inline primitive_type upper_type(primitive_type a, primitive_type b) {
		if (a == primitive_type::VOID || b == primitive_type::VOID) {
			throw std::logic_error("Cannot determine upper type with void type");
		}
		// return the larger type (enum values are ordered by size)
		return (a > b) ? a : b;
	}
	inline bool is_integral_type(primitive_type a) {
		return
			a == primitive_type::SCHAR || a == primitive_type::UCHAR ||
			a == primitive_type::SHORT || a == primitive_type::USHORT ||
			a == primitive_type::INT || a == primitive_type::UINT ||
			a == primitive_type::LONG || a == primitive_type::ULONG;
	}
	inline bool is_signed_integral_type(primitive_type a) {
		return
			a == primitive_type::SCHAR ||
			a == primitive_type::SHORT ||
			a == primitive_type::INT ||
			a == primitive_type::LONG;
	}
	inline bool is_unsigned_integral_type(primitive_type a) {
		return
			a == primitive_type::UCHAR ||
			a == primitive_type::USHORT ||
			a == primitive_type::UINT ||
			a == primitive_type::ULONG;
	}
	inline bool is_floating_point_type(primitive_type a) {
		return a == primitive_type::FLOAT || a == primitive_type::DOUBLE;
	}
	inline bool is_pseudo_integral_type(primitive_type a) {
		return a == primitive_type::BOOL || is_integral_type(a);
	}
	inline bool is_arithmetic_type(primitive_type a) {
		return is_integral_type(a) || is_floating_point_type(a);
	}
	inline bool is_numeric_type(primitive_type a) {
		return is_arithmetic_type(a) || a == primitive_type::BOOL;
	}

	inline bool can_implicitly_convert(primitive_type from, primitive_type to) {
		if (from == to) {
			return true;
		}
		if (to == primitive_type::VOID) {
			return false; // cannot convert to void
		}
		if (from == primitive_type::VOID) {
			return false; // cannot convert from void
		}
		if (from == primitive_type::BOOL) {
			// bool can be converted to any integral type
			return is_integral_type(to);
		}
		if (to == primitive_type::BOOL) {
			// only integral types can be converted to bool
			return is_integral_type(from);
		}
		if (is_integral_type(from) && is_integral_type(to)) {
			// integral types can be converted to other integral types
			return true;
		}
		if (is_floating_point_type(from) && is_floating_point_type(to)) {
			// float can be converted to double, but not vice versa
			return from != primitive_type::DOUBLE || to == primitive_type::DOUBLE;
		}
		if (is_integral_type(from) && is_floating_point_type(to)) {
			// integral to floating point conversion is allowed
			return true;
		}
		return false; // no other implicit conversions allowed
	}

	inline bool allow_pointer_arithmetic(primitive_type a) {
		return is_integral_type(a);
	}

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
			member(std::string n, const type_node& t) : name(std::move(n)), type(std::make_shared<type_node>(std::move(t))) {
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
			member(std::string n, const type_node& t) : name(std::move(n)), type(std::make_shared<type_node>(std::move(t))) {
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

		bool is_void() const {
			return kind == kind_t::PRIMITIVE && std::get<primitive_type>(value) == primitive_type::VOID;
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
		type_node resolved_type(const type_node& type) const {
			type_node result = type;
			while (result.kind == type_node::kind_t::CUSTOM) {
				result = get_type(std::get<std::string>(result.value));
			}
			return result;
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
		static member_info get_union_member_info(const union_type& type, const std::string& member_name);

		type_node get_result_type_binary(ast_expression_binary::type_t op, const type_node& left,
			const type_node& right) const;
		type_node get_result_type_unary(ast_expression_unary::type_t op, const type_node& operand) const;
		static type_node get_result_type_literal(const ast_expression_literal& literal);
		type_node get_result_type_member_access(const type_node& object_type, const std::string& member_name,
			bool pointer) const;
		type_node get_result_type_ternary(const type_node& then_type,
			const type_node& else_type) const;
		//type_node get_result_type_function_call(const type_node& function_type, const std::vector<type_node>& argument_types) const;

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

	inline type_node pointer_of(const type_node& base) {
		return type_node(pointer_type(std::make_shared<type_node>(base)));
	}
	inline type_node array_of(const type_node& element_type, size_t size) {
		return type_node(array_type(std::make_shared<type_node>(element_type), size));
	}
	inline type_node function_type_of(const type_node& return_type, const std::vector<type_node>& param_types) {
		std::vector<std::shared_ptr<type_node>> param_types_ptrs;
		for (const auto& pt : param_types) {
			param_types_ptrs.push_back(std::make_shared<type_node>(pt));
		}
		return type_node(function_type(std::make_shared<type_node>(return_type), param_types_ptrs));
	}
	inline type_node struct_of(const std::initializer_list<std::pair<std::string, type_node>>& members_list) {
		struct_type st;
		for (const auto& [name, type] : members_list) {
			st.members.emplace_back(name, std::make_shared<type_node>(type));
		}
		return type_node(st);
	}
} // namespace compiler::analysis::types
template<>
struct std::formatter<unqlang::analysis::types::primitive_type> : std::formatter<std::string> {
	auto format(const unqlang::analysis::types::primitive_type& pt, std::format_context& ctx) const {
		std::string type_str;
		switch (pt) {
			case unqlang::analysis::types::primitive_type::VOID:
				type_str = "void";
				break;
			case unqlang::analysis::types::primitive_type::BOOL:
				type_str = "bool";
				break;
			case unqlang::analysis::types::primitive_type::SIGNED_CHAR:
				type_str = "signed char";
				break;
			case unqlang::analysis::types::primitive_type::UNSIGNED_CHAR:
				type_str = "unsigned char";
				break;
			case unqlang::analysis::types::primitive_type::SIGNED_SHORT:
				type_str = "short";
				break;
			case unqlang::analysis::types::primitive_type::UNSIGNED_SHORT:
				type_str = "unsigned short";
				break;
			case unqlang::analysis::types::primitive_type::SIGNED_INT:
				type_str = "int";
				break;
			case unqlang::analysis::types::primitive_type::UNSIGNED_INT:
				type_str = "unsigned int";
				break;
			case unqlang::analysis::types::primitive_type::SIGNED_LONG:
				type_str = "long";
				break;
			case unqlang::analysis::types::primitive_type::UNSIGNED_LONG:
				type_str = "unsigned long";
				break;
			case unqlang::analysis::types::primitive_type::FLOAT:
				type_str = "float";
				break;
			case unqlang::analysis::types::primitive_type::DOUBLE:
				type_str = "double";
				break;
			default:
				type_str = "unknown";
				break;
		}
		return std::formatter<std::string>::format(type_str, ctx);
	}
};
template<>
struct std::formatter<unqlang::analysis::types::type_node> : std::formatter<std::string> {
	auto format(const unqlang::analysis::types::type_node& type, std::format_context& ctx) const {
		std::string type_str;
		switch (type.kind) {
			case unqlang::analysis::types::type_node::kind_t::PRIMITIVE:
				type_str = std::format("{}", std::get<unqlang::analysis::types::primitive_type>(type.value));
				break;
			case unqlang::analysis::types::type_node::kind_t::ARRAY: {
				const auto& at = std::get<unqlang::analysis::types::array_type>(type.value);
				type_str = std::format("{}[{}]", *at.element_type, at.size);
				break;
			}
			case unqlang::analysis::types::type_node::kind_t::POINTER: {
				const auto& pt = std::get<unqlang::analysis::types::pointer_type>(type.value);
				type_str = std::format("{}*", *pt.pointee_type);
				break;
			}
			case unqlang::analysis::types::type_node::kind_t::FUNCTION: {
				const auto& ft = std::get<unqlang::analysis::types::function_type>(type.value);
				type_str = std::format("{}(", *ft.return_type);
				for (size_t i = 0; i < ft.parameter_types.size(); i++) {
					if (i > 0) {
						type_str += ", ";
					}
					type_str += std::format("{}", *ft.parameter_types[i]);
				}
				type_str += ")";
				break;
			}
			case unqlang::analysis::types::type_node::kind_t::STRUCT: {
				const auto& st = std::get<unqlang::analysis::types::struct_type>(type.value);
				type_str = "struct { ";
				for (size_t i = 0; i < st.members.size(); i++) {
					if (i > 0) {
						type_str += "; ";
					}
					type_str += std::format("{} {}", *st.members[i].type, st.members[i].name);
				}
				type_str += " }";
				break;
			}
			case unqlang::analysis::types::type_node::kind_t::UNION: {
				const auto& ut = std::get<unqlang::analysis::types::union_type>(type.value);
				type_str = "union { ";
				for (size_t i = 0; i < ut.members.size(); i++) {
					if (i > 0) {
						type_str += "; ";
					}
					type_str += std::format("{} {}", *ut.members[i].type, ut.members[i].name);
				}
				type_str += " }";
				break;
			}
			case unqlang::analysis::types::type_node::kind_t::CUSTOM:
				type_str = std::format("{}", std::get<std::string>(type.value));
				break;
		}
		return std::formatter<std::string>::format(type_str, ctx);
	}
};
