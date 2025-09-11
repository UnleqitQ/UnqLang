#include "scope.hpp"

#include <algorithm>
#include <ranges>

namespace unqlang::compiler {
	uint32_t scope::get_stack_size(const compilation_context& context) const {
		if (cache.calculated_stack_size)
			return cache.stack_size;
		calculate_stack_size(context);
		return cache.stack_size;
	}
	uint32_t scope::get_cumulative_stack_size(const compilation_context& context) const {
		if (cache.calculated_stack_size)
			return cache.cumulative_stack_size;
		calculate_stack_size(context);
		return cache.cumulative_stack_size;
	}
	void scope::calculate_stack_size(const compilation_context& context) const {
		if (cache.calculated_stack_size)
			return;
		uint32_t base_stack_size = 0;
		uint32_t max_stack_size = 0;
		uint32_t current_statement_index = 0;
		while (true) {
			// get next variables declared at or after current_statement_index
			auto sym_it = symbols_by_statement.lower_bound(current_statement_index);
			// get next child scope at or after current_statement_index
			auto child_it = children.lower_bound(current_statement_index);
			// if both are at the end, we're done
			if (sym_it == symbols_by_statement.end() && child_it == children.end())
				break;
			// determine which comes first (if equal, variables come first)
			if (sym_it != symbols_by_statement.end() &&
				(child_it == children.end() || sym_it->first <= child_it->first)) {
				current_statement_index = sym_it->first;
				// process variables
				for (const auto& var_name : sym_it->second) {
					const auto& var_info = symbol_table.at(var_name);
					uint32_t var_size = var_info.var_info.get_size(context);
					// store variable offset (positive value because it's always negative relative to base pointer)
					var_info.var_info.cache.offset = base_stack_size;
					// increase base stack size
					base_stack_size += var_size;
				}
				if (base_stack_size > max_stack_size)
					max_stack_size = base_stack_size;
			}
			// if child scope comes first, or they are equal (variables already processed)
			if (child_it != children.end() &&
				(sym_it == symbols_by_statement.end() || child_it->first <= sym_it->first)) {
				current_statement_index = child_it->first;
				// process child scopes
				for (const auto& child_info : child_it->second) {
					uint32_t child_cumulative_size = child_info.child->get_cumulative_stack_size(context);
					uint32_t combined_size = base_stack_size + child_cumulative_size;
					if (combined_size > max_stack_size)
						max_stack_size = combined_size;
					// assign base offset for child scope
					child_info.base_offset = base_stack_size;
				}
			}
			// move to next statement index
			current_statement_index++;
		}
		cache.stack_size = base_stack_size;
		cache.cumulative_stack_size = max_stack_size;
		cache.calculated_stack_size = true;
	}
	std::shared_ptr<assembly_scope> scope::build_assembly_scope(
		const compilation_context& context,
		const std::shared_ptr<assembly_scope>& parent_scope,
		uint32_t base_offset
	) const {
		auto asm_scope = std::make_shared<assembly_scope>();
		asm_scope->parent = parent_scope;
		calculate_stack_size(context);
		asm_scope->stack_size = cache.stack_size;
		asm_scope->cumulative_stack_size = cache.cumulative_stack_size;
		asm_scope->base_offset = base_offset;
		// reserve space
		asm_scope->symbol_table.reserve(symbol_table.size());

		// add variables
		for (const auto& [name, var_info] : symbol_table) {
			assembly_variable_info asm_var_info;
			asm_var_info.name = name;
			asm_var_info.type = var_info.var_info.type;
			asm_var_info.size = var_info.var_info.get_size(context);
			asm_var_info.offset = base_offset + var_info.var_info.cache.offset;
			// asm_var_info.alignment = var_info.var_info.get_alignment(context); // not currently used
			asm_scope->symbol_table[name] = asm_var_info;
			uint32_t stmt_idx = var_info.statement_index;
			asm_scope->symbols_by_statement[stmt_idx].push_back(name);
		}

		// add child scopes
		for (const auto& child_list : children | std::views::values) {
			for (const auto& child_info : child_list) {
				auto child_asm_scope = child_info.child->build_assembly_scope(
					context,
					asm_scope,
					base_offset + child_info.base_offset
				);
				asm_scope->children[child_info.key] = assembly_scope::child_scope_info(child_asm_scope, child_info.key);
			}
		}
		return asm_scope;
	}
} // unqlang::compiler
