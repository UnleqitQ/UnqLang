#pragma once

#include <string>

#include "ast.hpp"
#include "analysis/types.hpp"

namespace compiler {
	namespace common_types {
		// Common types
		static const analysis::types::type_node void_type = analysis::types::primitive_type::VOID;
		static const analysis::types::type_node int_type = analysis::types::primitive_type::INT;
		static const analysis::types::type_node char_type = analysis::types::primitive_type::CHAR;
		static const analysis::types::type_node bool_type = analysis::types::primitive_type::BOOL;

		// shared pointers to common types
		static const std::shared_ptr<analysis::types::type_node> void_type_ptr
			= std::make_shared<analysis::types::type_node>(void_type);
		static const std::shared_ptr<analysis::types::type_node> int_type_ptr
			= std::make_shared<analysis::types::type_node>(int_type);
		static const std::shared_ptr<analysis::types::type_node> char_type_ptr
			= std::make_shared<analysis::types::type_node>(char_type);
		static const std::shared_ptr<analysis::types::type_node> bool_type_ptr
			= std::make_shared<analysis::types::type_node>(bool_type);
	}

	namespace type_helpers {
		template<typename T>
		constexpr analysis::types::type_node from_cpp_type() {
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
				return analysis::types::pointer_type(from_cpp_type<base_t>());
			}
			else if constexpr (std::is_array_v<T>) {
				using base_t = std::remove_extent_t<T>;
				constexpr size_t array_size = std::extent_v<T>;
				return analysis::types::array_type(from_cpp_type<base_t>(), array_size);
			}
			else if constexpr (std::is_same_v<T, std::string> || std::is_same_v<T, std::string_view>) {
				// Represent string as char pointer for simplicity
				return analysis::types::pointer_type(analysis::types::primitive_type::CHAR);
			}
			else if constexpr (std::is_class_v<T>) {
				// For user-defined types, we assume they are defined elsewhere and return a placeholder
				return analysis::types::struct_type{};
			}
			else {
				static_assert(!sizeof(T*), "Unsupported C++ type for conversion to ast_type_node");
			}
			throw std::runtime_error("Unsupported C++ type for conversion to ast_type_node");
		}
	} // namespace type_helpers
} // namespace compiler
