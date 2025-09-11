#pragma once
#include "common.hpp"
#include "../analysis/types.hpp"
#include "../../machine/register.hpp"


namespace unqlang::compiler {
	struct variable_info {
		std::string name;
		analysis::types::type_node type;

		mutable struct {
			bool calculated_size = false;
			uint32_t size = 0;

			/*
			 * Alignment is not currently used, but may be useful in the future.
			 * bool calculated_alignment = false;
			 * uint32_t alignment = 0;
			 */

			uint32_t offset = 0; // offset from base pointer
		} cache;

		variable_info(std::string name, analysis::types::type_node type)
			: name(std::move(name)), type(type) {
		}

		uint32_t get_size(const compilation_context& context) const {
			if (!cache.calculated_size) {
				cache.size = context.type_system->get_type_size(type);
				cache.calculated_size = true;
			}
			return cache.size;
		}
	};
	struct assembly_variable_info {
		std::string name;
		analysis::types::type_node type;
		uint32_t offset; // offset from base pointer
		uint32_t size; // size in bytes
		// uint32_t alignment; // alignment in bytes (not currently used)
	};
} // unqlang::compiler
