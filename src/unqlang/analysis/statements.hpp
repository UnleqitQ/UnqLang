#pragma once
#include <optional>

#include "expressions.hpp"
#include "types.hpp"


namespace unqlang::analysis::statements {
	struct statement_node;

	struct block_statement {
		std::vector<std::shared_ptr<statement_node>> statements;

		block_statement() : statements() {
		}
		explicit block_statement(std::vector<std::shared_ptr<statement_node>> stmts)
			: statements(std::move(stmts)) {
		}

		static block_statement from_ast(const ast_statement_block& ast_block);
	};

	struct declaration_variable_statement {
		types::type_node type;
		std::string name;
		std::optional<expressions::expression_node> initializer;

		bool is_constant = false; // true if 'const' qualifier is present
		bool is_extern = false; // true if 'extern' storage class is present
		bool is_static = false; // true if 'static' storage class is present

		declaration_variable_statement()
			: type(types::primitive_type::VOID), name(""), initializer(std::nullopt) {
		}
		declaration_variable_statement(
			types::type_node t,
			std::string n,
			std::optional<expressions::expression_node> init = std::nullopt,
			bool constant = false,
			bool ext = false,
			bool stat = false
		)
			: type(std::move(t)),
			  name(std::move(n)),
			  initializer(std::move(init)),
			  is_constant(constant),
			  is_extern(ext),
			  is_static(stat) {
		}

		static declaration_variable_statement from_ast(const ast_statement_variable_declaration& ast_var_decl);
	};

	struct declaration_function_statement {
		struct parameter {
			std::optional<std::string> name; // nullopt for unnamed parameters
			types::type_node type;

			parameter() : name(std::nullopt), type(types::primitive_type::VOID) {
			}
			parameter(std::optional<std::string> n, types::type_node t)
				: name(std::move(n)), type(std::move(t)) {
			}
		};
		std::string name;
		std::vector<parameter> parameters;
		types::type_node return_type;
		std::optional<block_statement> body; // nullopt if function is only declared, not defined

		bool is_extern = false; // true if 'extern' storage class is present
		bool is_static = false; // true if 'static' storage class is present

		declaration_function_statement()
			: name(""),
			  parameters(),
			  return_type(types::primitive_type::VOID),
			  body(std::nullopt),
			  is_extern(false),
			  is_static(false) {
		}
		declaration_function_statement(
			std::string n,
			std::vector<parameter> params,
			types::type_node ret_type,
			std::optional<block_statement> b = std::nullopt,
			bool ext = false,
			bool stat = false
		)
			: name(std::move(n)),
			  parameters(std::move(params)),
			  return_type(std::move(ret_type)),
			  body(std::move(b)),
			  is_extern(ext),
			  is_static(stat) {
		}

		static declaration_function_statement from_ast(const ast_statement_function_declaration& ast_func_decl);
	};

	struct declaration_struct_statement {
		std::string name;
		std::optional<types::struct_type> type; // nullopt if only forward-declared

		declaration_struct_statement() : name(""), type(std::nullopt) {
		}
		declaration_struct_statement(std::string n, std::optional<types::struct_type> t = std::nullopt)
			: name(std::move(n)), type(std::move(t)) {
		}

		static declaration_struct_statement from_ast(const ast_statement_struct_declaration& ast_struct_decl);
	};

	struct declaration_union_statement {
		std::string name;
		std::optional<types::union_type> type; // nullopt if only forward-declared

		declaration_union_statement() : name(""), type(std::nullopt) {
		}
		declaration_union_statement(std::string n, std::optional<types::union_type> t = std::nullopt)
			: name(std::move(n)), type(std::move(t)) {
		}

		static declaration_union_statement from_ast(const ast_statement_union_declaration& ast_union_decl);
	};

	struct declaration_typedef_statement {
		std::string alias_name;
		types::type_node aliased_type;

		declaration_typedef_statement() : alias_name(""), aliased_type(types::primitive_type::VOID) {
		}
		declaration_typedef_statement(std::string alias, types::type_node type)
			: alias_name(std::move(alias)), aliased_type(std::move(type)) {
		}

		static declaration_typedef_statement from_ast(const ast_statement_type_declaration& ast_typedef_decl);
	};

	struct declaration_statement {
		enum class kind_t {
			VARIABLE,
			FUNCTION,
			STRUCT,
			UNION,
			TYPEDEF
		} kind;

		std::variant<
			declaration_variable_statement,
			declaration_function_statement,
			declaration_struct_statement,
			declaration_union_statement,
			declaration_typedef_statement
		> declaration;

		declaration_statement() : kind(kind_t::VARIABLE), declaration(declaration_variable_statement()) {
		}
		declaration_statement(kind_t k, auto&& decl) : kind(k), declaration(std::forward<decltype(decl)>(decl)) {
		}
		declaration_statement(declaration_variable_statement var_decl)
			: kind(kind_t::VARIABLE), declaration(std::move(var_decl)) {
		}
		declaration_statement(declaration_function_statement func_decl)
			: kind(kind_t::FUNCTION), declaration(std::move(func_decl)) {
		}
		declaration_statement(declaration_struct_statement struct_decl)
			: kind(kind_t::STRUCT), declaration(std::move(struct_decl)) {
		}
		declaration_statement(declaration_union_statement union_decl)
			: kind(kind_t::UNION), declaration(std::move(union_decl)) {
		}
		declaration_statement(declaration_typedef_statement typedef_decl)
			: kind(kind_t::TYPEDEF), declaration(std::move(typedef_decl)) {
		}
	};

	struct while_statement {
		expressions::expression_node condition;
		block_statement body;
		bool is_do_while = false; // true if 'do-while' loop, false if 'while' loop

		while_statement()
			: condition(expressions::expression_node()), body(block_statement()) {
		}
		while_statement(
			expressions::expression_node cond,
			block_statement body_stmt,
			bool do_while = false
		)
			: condition(std::move(cond)), body(std::move(body_stmt)), is_do_while(do_while) {
			if (is_do_while)
				throw std::runtime_error("Do-while loops are not supported yet");
		}

		static while_statement from_ast(const ast_statement_while& ast_while);
	};

	struct if_statement {
		struct clause {
			block_statement body;
			std::optional<expressions::expression_node> condition; // nullopt for 'else' clause

			clause() : body(block_statement()), condition(std::nullopt) {
			}
			clause(block_statement b, std::optional<expressions::expression_node> cond = std::nullopt)
				: body(std::move(b)), condition(std::move(cond)) {
			}
		};
		std::vector<clause> clauses; // last clause may have nullopt condition for 'else'
		if_statement() : clauses() {
		}
		explicit if_statement(std::vector<clause> cls) : clauses(std::move(cls)) {
		}
		if_statement(clause if_clause) : clauses({std::move(if_clause)}) {
		}
		if_statement(clause if_clause, clause else_clause)
			: clauses({std::move(if_clause), std::move(else_clause)}) {
		}

		static if_statement from_ast(const ast_statement_if& ast_if);
	};

	struct return_statement {
		std::optional<expressions::expression_node> value; // nullopt for 'return;' with no value

		return_statement() : value(std::nullopt) {
		}
		explicit return_statement(std::optional<expressions::expression_node> val) : value(std::move(val)) {
		}

		static return_statement from_ast(const ast_statement_return& ast_return);
	};

	struct statement_node {
		enum class kind_t {
			DECLARATION,
			IF,
			WHILE,
			RETURN,
			EXPRESSION,
			BLOCK
		} kind;
		std::variant<
			declaration_statement,
			if_statement,
			while_statement,
			return_statement,
			expressions::expression_node,
			block_statement
		> value;

		statement_node() : kind(kind_t::BLOCK), value(block_statement()) {
		}
		statement_node(kind_t k, auto&& v) : kind(k), value(std::forward<decltype(v)>(v)) {
		}
		statement_node(declaration_statement decl) : kind(kind_t::DECLARATION), value(std::move(decl)) {
		}
		statement_node(if_statement if_stmt) : kind(kind_t::IF), value(std::move(if_stmt)) {
		}
		statement_node(while_statement while_stmt) : kind(kind_t::WHILE), value(std::move(while_stmt)) {
		}
		statement_node(return_statement ret_stmt) : kind(kind_t::RETURN), value(std::move(ret_stmt)) {
		}
		statement_node(expressions::expression_node expr) : kind(kind_t::EXPRESSION), value(std::move(expr)) {
		}
		statement_node(block_statement block) : kind(kind_t::BLOCK), value(std::move(block)) {
		}

		static statement_node from_ast(const ast_statement_node& ast_stmt);
	};
} // unqlang::analysis::statements
