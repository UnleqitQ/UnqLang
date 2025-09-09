#pragma once

#include <string>

#include "ast.hpp"

namespace compiler {
	namespace common_types {
		// Common types
		static const ast_type_node void_type = ast_type_node(ast_type_node::type_t::Void, std::monostate{});
		static const ast_type_node int_type = ast_type_node(ast_type_node::type_t::Int, std::monostate{});
		static const ast_type_node char_type = ast_type_node(ast_type_node::type_t::Char, std::monostate{});
		static const ast_type_node bool_type = ast_type_node(ast_type_node::type_t::Bool, std::monostate{});

		// shared pointers to common types
		static const std::shared_ptr<ast_type_node> void_type_ptr = std::make_shared<ast_type_node>(void_type);
		static const std::shared_ptr<ast_type_node> int_type_ptr = std::make_shared<ast_type_node>(int_type);
		static const std::shared_ptr<ast_type_node> char_type_ptr = std::make_shared<ast_type_node>(char_type);
		static const std::shared_ptr<ast_type_node> bool_type_ptr = std::make_shared<ast_type_node>(bool_type);
	}

	namespace type_helpers {
		uint16_t get_member_index(const ast_type_members& members, const std::string& name);

		inline ast_type_node pointer_to(const std::shared_ptr<ast_type_node>& base) {
			return ast_type_node(ast_type_node::type_t::Pointer, ast_type_pointer(base));
		}
		inline ast_type_node pointer_to(const ast_type_node& base) {
			return ast_type_node(ast_type_node::type_t::Pointer, ast_type_pointer(std::make_shared<ast_type_node>(base)));
		}
		inline ast_type_node array_of(const std::shared_ptr<ast_type_node>& base, uint32_t size) {
			return ast_type_node(ast_type_node::type_t::Array, ast_type_array{base, size});
		}
		inline ast_type_node array_of(const ast_type_node& base, uint32_t size) {
			return ast_type_node(ast_type_node::type_t::Array,
				ast_type_array{std::make_shared<ast_type_node>(base), size});
		}

		template<typename T>
		constexpr ast_type_node from_cpp_type() {
			if constexpr (std::is_same_v<T, void>) {
				return common_types::void_type;
			}
			else if constexpr (std::is_same_v<T, int32_t>) {
				return common_types::int_type;
			}
			else if constexpr (std::is_same_v<T, char>) {
				return common_types::char_type;
			}
			else if constexpr (std::is_same_v<T, bool>) {
				return common_types::bool_type;
			}
			else if constexpr (std::is_pointer_v<T>) {
				using base_t = std::remove_pointer_t<T>;
				return pointer_to(std::make_shared<ast_type_node>(from_cpp_type<base_t>()));
			}
			else if constexpr (std::is_array_v<T>) {
				using base_t = std::remove_extent_t<T>;
				constexpr size_t array_size = std::extent_v<T>;
				return array_of(std::make_shared<ast_type_node>(from_cpp_type<base_t>()), static_cast<uint32_t>(array_size));
			}
			else if constexpr (std::is_same_v<T, std::string> || std::is_same_v<T, std::string_view>) {
				// Represent string as char pointer for simplicity
				return pointer_to(common_types::char_type_ptr);
			}
			else if constexpr (std::is_class_v<T>) {
				// For user-defined types, we assume they are defined elsewhere and return a placeholder
				return ast_type_node(ast_type_node::type_t::Struct, ast_type_members{});
			}
			else {
				static_assert(!sizeof(T*), "Unsupported C++ type for conversion to ast_type_node");
			}
			throw std::runtime_error("Unsupported C++ type for conversion to ast_type_node");
		}
	} // namespace type_helpers
} // namespace compiler
