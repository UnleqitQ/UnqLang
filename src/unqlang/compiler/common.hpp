#pragma once

#include "../../machine/register.hpp"
#include "../analysis/types.hpp"
#include "../analysis/functions.hpp"
#include "../analysis/variables.hpp"
#include "../analysis/complex_literals.hpp"

namespace unqlang::compiler {
	struct assembly_function_signature;
}

namespace unqlang::compiler {
	union regmask {
		struct {
			uint8_t eax : 1;
			uint8_t ebx : 1;
			uint8_t ecx : 1;
			uint8_t edx : 1;
			uint8_t esi : 1;
			uint8_t edi : 1;
			uint8_t ebp : 1;
			uint8_t esp : 1;
			// eip is not included as there is no way to use it directly
		};
		uint16_t raw;

		regmask() : raw(0) {
		}
		void set(machine::register_id r, bool used) {
			switch (r) {
				case machine::register_id::eax:
					eax = used;
					break;
				case machine::register_id::ebx:
					ebx = used;
					break;
				case machine::register_id::ecx:
					ecx = used;
					break;
				case machine::register_id::edx:
					edx = used;
					break;
				case machine::register_id::esi:
					esi = used;
					break;
				case machine::register_id::edi:
					edi = used;
					break;
				case machine::register_id::ebp:
					ebp = used;
					break;
				case machine::register_id::esp:
					esp = used;
					break;
				default:
					throw std::runtime_error("Cannot set usage for this register");
			}
		}
		bool get(machine::register_id r) const {
			switch (r) {
				case machine::register_id::eax:
					return eax;
				case machine::register_id::ebx:
					return ebx;
				case machine::register_id::ecx:
					return ecx;
				case machine::register_id::edx:
					return edx;
				case machine::register_id::esi:
					return esi;
				case machine::register_id::edi:
					return edi;
				case machine::register_id::ebp:
					return ebp;
				case machine::register_id::esp:
					return esp;
				default:
					throw std::runtime_error("Cannot get usage for this register");
			}
		}
		regmask operator|(const regmask& other) const {
			regmask result;
			result.raw = raw | other.raw;
			return result;
		}
		regmask& operator|=(const regmask& other) {
			raw |= other.raw;
			return *this;
		}
		regmask operator&(const regmask& other) const {
			regmask result;
			result.raw = raw & other.raw;
			return result;
		}
		regmask& operator&=(const regmask& other) {
			raw &= other.raw;
			return *this;
		}
		regmask operator~() const {
			regmask result;
			result.raw = ~raw;
			return result;
		}

		static constexpr std::array<machine::register_id, 6> USABLE_REGISTERS = {
			machine::register_id::eax,
			machine::register_id::ebx,
			machine::register_id::ecx,
			machine::register_id::edx,
			machine::register_id::esi,
			machine::register_id::edi
		};
	};
	struct compilation_context {
		// type system for type information
		std::shared_ptr<analysis::types::type_system> type_system;

		// function storage (for global functions)
		std::shared_ptr<analysis::functions::storage> function_storage;

		// inline function storage (for global inline assembly functions)
		std::shared_ptr<analysis::functions::inline_storage> inline_function_storage;

		// variable storage (for global variables)
		std::shared_ptr<analysis::variables::storage> variable_storage;

		// complex literal storage (for global complex literals)
		std::shared_ptr<analysis::complex_literals::storage> complex_literal_storage;

		compilation_context()
			: type_system(std::make_shared<analysis::types::type_system>()),
			  function_storage(std::make_shared<analysis::functions::storage>()),
			  inline_function_storage(std::make_shared<analysis::functions::inline_storage>()),
			  variable_storage(std::make_shared<analysis::variables::storage>()),
			  complex_literal_storage(std::make_shared<analysis::complex_literals::storage>()) {
		}

		compilation_context(const std::shared_ptr<analysis::types::type_system>& ts,
			const std::shared_ptr<analysis::functions::storage>& fs,
			const std::shared_ptr<analysis::functions::inline_storage>& ifs,
			const std::shared_ptr<analysis::variables::storage>& vs,
			const std::shared_ptr<analysis::complex_literals::storage>& cls)
			: type_system(ts), function_storage(fs), inline_function_storage(ifs), variable_storage(vs),
			  complex_literal_storage(cls) {
			if (!type_system) {
				throw std::runtime_error("Type system cannot be null");
			}
			if (!function_storage) {
				throw std::runtime_error("Function storage cannot be null");
			}
			if (!inline_function_storage) {
				throw std::runtime_error("Inline function storage cannot be null");
			}
			if (!variable_storage) {
				throw std::runtime_error("Variable storage cannot be null");
			}
			if (!complex_literal_storage) {
				throw std::runtime_error("Complex literal storage cannot be null");
			}
		}
	};

	struct scoped_compilation_context {
		// global context
		std::shared_ptr<compilation_context> global_context;

		// parent context
		const scoped_compilation_context* parent_context;

		// variable storage for this scope
		std::shared_ptr<analysis::variables::storage> variable_storage;

		// current function being compiled, nullptr if not in a function
		std::shared_ptr<assembly_function_signature> current_function_signature = nullptr;

		scoped_compilation_context(
			const std::shared_ptr<compilation_context>& global_ctx,
			const std::shared_ptr<analysis::variables::storage>& var_storage,
			const std::shared_ptr<assembly_function_signature>& func_sig,
			const scoped_compilation_context* parent_ctx = nullptr)
			: global_context(global_ctx),
			  parent_context(parent_ctx),
			  variable_storage(var_storage),
			  current_function_signature(func_sig) {
			if (!global_context) {
				throw std::runtime_error("Global context cannot be null");
			}
		}

		scoped_compilation_context(
			const std::shared_ptr<compilation_context>& global_ctx,
			const std::shared_ptr<analysis::variables::storage>& var_storage = nullptr,
			const scoped_compilation_context* parent_ctx = nullptr)
			: global_context(global_ctx),
			  parent_context(parent_ctx),
			  variable_storage(var_storage ? var_storage
			                  : std::make_shared<analysis::variables::storage>()),
			  current_function_signature(parent_ctx ? parent_ctx->current_function_signature : nullptr) {
			if (!global_context) {
				throw std::runtime_error("Global context cannot be null");
			}
		}
		scoped_compilation_context(
			const scoped_compilation_context* parent_ctx,
			const std::shared_ptr<analysis::variables::storage>& var_storage)
			: global_context(parent_ctx->global_context),
			  parent_context(parent_ctx),
			  variable_storage(var_storage),
			  current_function_signature(parent_ctx->current_function_signature) {
			if (!global_context) {
				throw std::runtime_error("Global context cannot be null");
			}
			if (!variable_storage) {
				throw std::runtime_error("Variable storage cannot be null");
			}
		}
	};

	struct multi_if_statement {
		struct branch {
			// condition, nullptr for else branch
			std::shared_ptr<ast_expression_node> condition;
			// block to execute if condition is true (or else branch)
			ast_statement_block block;
			branch(ast_statement_block blk, std::shared_ptr<ast_expression_node> cond = nullptr)
				: condition(cond), block(blk) {
			}
		};
		std::vector<branch> branches;

		multi_if_statement() : branches() {
		}
		multi_if_statement(std::vector<branch> branches) : branches(branches) {
		}

		void add_branch(ast_statement_block block, std::shared_ptr<ast_expression_node> condition = nullptr) {
			if (condition == nullptr && (branches.empty() || branches.back().condition == nullptr)) {
				if (branches.empty())
					throw std::runtime_error("Cannot add else branch to multi_if_statement without any prior branches");
				throw std::runtime_error("Cannot add multiple else branches to multi_if_statement");
			}
			branches.emplace_back(block, condition);
		}

		static multi_if_statement build_from_ast(const ast_statement_if& if_stmt) {
			multi_if_statement mif;
			const ast_statement_if* current = &if_stmt;
			while (true) {
				const auto& if_node = current->then_branch;
				if (if_node->type != ast_statement_node::type_t::BlockStatement) {
					throw std::runtime_error("If statement then branch is not a block");
				}
				mif.add_branch(std::get<ast_statement_block>(if_node->value), current->condition);
				if (current->else_branch == nullptr) {
					break;
				}
				if (current->else_branch->type == ast_statement_node::type_t::IfStatement) {
					current = &std::get<ast_statement_if>(current->else_branch->value);
				}
				else if (current->else_branch->type == ast_statement_node::type_t::BlockStatement) {
					mif.add_branch(std::get<ast_statement_block>(current->else_branch->value), nullptr);
					break;
				}
				else {
					throw std::runtime_error("If statement else branch is not an if statement or block");
				}
			}
			return mif;
		}
	};
} // unqlang::compiler

template<>
struct std::formatter<unqlang::compiler::regmask> : std::formatter<std::string> {
	auto format(const unqlang::compiler::regmask& rm, std::format_context& ctx) const {
		std::string regs;
		if (rm.eax)
			regs += "AX ";
		else
			regs += "-- ";
		if (rm.ebx)
			regs += "BX ";
		else
			regs += "-- ";
		if (rm.ecx)
			regs += "CX ";
		else
			regs += "-- ";
		if (rm.edx)
			regs += "DX ";
		else
			regs += "-- ";
		if (rm.esi)
			regs += "SI ";
		else
			regs += "-- ";
		if (rm.edi)
			regs += "DI ";
		else
			regs += "-- ";
		if (rm.ebp)
			regs += "BP ";
		else
			regs += "-- ";
		if (rm.esp)
			regs += "SP ";
		else
			regs += "-- ";
		return std::formatter<std::string>::format(regs, ctx);
	}
};
