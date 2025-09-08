#include "ast.hpp"
#include <iostream>
#include <numeric>

#include "../parser.hpp"
#include "../shift_reduce_parser.hpp"

namespace compiler {
	// utility functions
	namespace util {
		std::string lexer_token_type_to_string(const lexer_token::type_t type) {
			switch (type) {
				case lexer_token::type_t::Identifier: return "IDENTIFIER";
				case lexer_token::type_t::Integer: return "INTEGER";
				case lexer_token::type_t::Float: return "FLOAT";
				case lexer_token::type_t::String: return "STRING";
				case lexer_token::type_t::Operator: return "OPERATOR";
				case lexer_token::type_t::Punctuation: return "PUNCTUATION";
				case lexer_token::type_t::Keyword: return "KEYWORD";
				case lexer_token::type_t::Comment: return "COMMENT";
				default: return "UNKNOWN";
			}
		}

		template<typename T>
		std::shared_ptr<ast_node> make_ast_node(ast_node::type_t type, T value) {
			return std::make_shared<ast_node>(type, value);
		}

		Parser<lexer_token, lexer_token> token_type(lexer_token::type_t type) {
			return Parser<lexer_token, lexer_token>(
				[type](const std::vector<lexer_token>& input, std::vector<std::pair<lexer_token, size_t>>& output,
				ParserTable&) {
					if (!input.empty() && input[0].type == type) {
						output.emplace_back(input[0], 1);
					}
				},
				std::format("(token_type {})", lexer_token_type_to_string(type))
			);
		}

		Parser<lexer_token, lexer_token> keyword(const std::string& kw) {
			return Parser<lexer_token, lexer_token>(
				[kw](const std::vector<lexer_token>& input, std::vector<std::pair<lexer_token, size_t>>& output, ParserTable&) {
					if (!input.empty() && input[0].type == lexer_token::type_t::Keyword &&
						std::get<std::string>(input[0].value) == kw) {
						output.emplace_back(input[0], 1);
					}
				},
				std::format("(keyword \"{}\")", kw)
			);
		}
		Parser<lexer_token, lexer_token> identifier() {
			return token_type(lexer_token::type_t::Identifier);
		}
		Parser<lexer_token, lexer_token> integer() {
			return token_type(lexer_token::type_t::Integer);
		}
		Parser<lexer_token, lexer_token> op(const operator_type_t o) {
			return Parser<lexer_token, lexer_token>(
				[o](const std::vector<lexer_token>& input, std::vector<std::pair<lexer_token, size_t>>& output, ParserTable&) {
					if (!input.empty() && input[0].type == lexer_token::type_t::Operator &&
						std::get<operator_type_t>(input[0].value) == o) {
						output.emplace_back(input[0], 1);
					}
				},
				std::format("(operator '{}')", o)
			);
		}
		Parser<lexer_token, lexer_token> op(const std::string_view o) {
			return op(lexer_parse_operator_type(std::string(o)));
		}
		Parser<lexer_token, lexer_token> op(const std::vector<operator_type_t> ops) {
			return Parser<lexer_token, lexer_token>(
				[ops](const std::vector<lexer_token>& input, std::vector<std::pair<lexer_token, size_t>>& output,
				ParserTable&) {
					if (!input.empty() && input[0].type == lexer_token::type_t::Operator) {
						operator_type_t o = std::get<operator_type_t>(input[0].value);
						if (std::ranges::find(ops, o) != ops.end()) {
							output.emplace_back(input[0], 1);
						}
					}
				},
				std::format("(operator [{}])", std::accumulate(std::next(ops.begin()), ops.end(),
					std::format("{}", *ops.begin()),
					[](const std::string& a, const operator_type_t b) { return a + ", " + std::format("{}", b); }))
			);
		}
		Parser<lexer_token, lexer_token> op(const std::vector<std::string_view> ops) {
			std::vector<operator_type_t> op_types;
			for (const auto& op : ops) {
				op_types.push_back(lexer_parse_operator_type(std::string(op)));
			}
			return op(op_types);
		}
		Parser<lexer_token, lexer_token> op(const std::initializer_list<std::string_view> ops) {
			return op(std::vector<std::string_view>(ops));
		}
		Parser<lexer_token, lexer_token> punctuation(const punctuation_type_t p) {
			return Parser<lexer_token, lexer_token>(
				[p](const std::vector<lexer_token>& input, std::vector<std::pair<lexer_token, size_t>>& output, ParserTable&) {
					if (!input.empty() && input[0].type == lexer_token::type_t::Punctuation &&
						std::get<punctuation_type_t>(input[0].value) == p) {
						output.emplace_back(input[0], 1);
					}
				},
				std::format("(punctuation '{}')", p)
			);
		}
		Parser<lexer_token, lexer_token> punctuation(char p) {
			return punctuation(lexer_parse_punctuation_type(p));
		}
	} // util

	namespace type_parser {
		typedef Parser<lexer_token, std::shared_ptr<ast_type_node>> ast_type_parser_t;

		// Forward declarations for recursive parsers
		const ast_type_parser_t ref_ast_type_parser = ref_parser<lexer_token,
			std::shared_ptr<ast_type_node>>("ast_type_parser");

		enum class ast_type_symbol_t {
			Array,
			Pointer,
			Builtin,
			Custom,

			Type,

			InBracketOpen,
			InBracketClose,
			InParenOpen,
			InParenClose,
			InAsterisk,
			InInt,

			TmpArrayBrackets
		};
		const ShiftReduceParser<lexer_token, ast_type_symbol_t> ast_type_symbol_parser = [] {
			ShiftReduceParser<lexer_token, ast_type_symbol_t> parser(
				[](const lexer_token& tok, ast_type_symbol_t& sym) {
					switch (tok.type) {
						case lexer_token::type_t::Punctuation: {
							const auto p = std::get<punctuation_type_t>(tok.value);
							switch (p) {
								case punctuation_type_t::LeftBracket: return (sym = ast_type_symbol_t::InBracketOpen, true);
								case punctuation_type_t::RightBracket: return (sym = ast_type_symbol_t::InBracketClose, true);
								case punctuation_type_t::LeftParen: return (sym = ast_type_symbol_t::InParenOpen, true);
								case punctuation_type_t::RightParen: return (sym = ast_type_symbol_t::InParenClose, true);
								default: return false;
							}
						}
						case lexer_token::type_t::Operator: {
							const auto o = std::get<operator_type_t>(tok.value);
							if (o == operator_type_t::Asterisk) {
								return (sym = ast_type_symbol_t::InAsterisk, true);
							}
							return false;
						}
						case lexer_token::type_t::Integer: {
							return (sym = ast_type_symbol_t::InInt, true);
						}
						case lexer_token::type_t::Keyword: {
							const auto kw = std::get<std::string>(tok.value);
							if (kw == "int" || kw == "void" || kw == "bool") {
								return (sym = ast_type_symbol_t::Builtin, true);
							}
							return false;
						}
						case lexer_token::type_t::Identifier: {
							return (sym = ast_type_symbol_t::Custom, true);
						}
						default: return false;
					}
				}
			);
			parser.add_rule({
				ast_type_symbol_t::TmpArrayBrackets, {ast_type_symbol_t::InBracketOpen, ast_type_symbol_t::InBracketClose}
			});
			parser.add_rule({
				ast_type_symbol_t::TmpArrayBrackets,
				{ast_type_symbol_t::InBracketOpen, ast_type_symbol_t::InInt, ast_type_symbol_t::InBracketClose}
			});
			parser.add_rule({ast_type_symbol_t::Array, {ast_type_symbol_t::Type, ast_type_symbol_t::TmpArrayBrackets}});
			parser.add_rule({ast_type_symbol_t::Pointer, {ast_type_symbol_t::Type, ast_type_symbol_t::InAsterisk}});
			parser.add_rule({ast_type_symbol_t::Type, {ast_type_symbol_t::Builtin}});
			parser.add_rule({ast_type_symbol_t::Type, {ast_type_symbol_t::Custom}});
			parser.add_rule({
				ast_type_symbol_t::Type,
				{ast_type_symbol_t::InParenOpen, ast_type_symbol_t::Type, ast_type_symbol_t::InParenClose}
			});
			parser.add_rule({ast_type_symbol_t::Type, {ast_type_symbol_t::Array}});
			parser.add_rule({ast_type_symbol_t::Type, {ast_type_symbol_t::Pointer}});
			return parser;
		}();

		ast_type_node build_type_node(const ShiftReduceParser<lexer_token, ast_type_symbol_t>::Reduced& reduced) {
			switch (reduced.symbol) {
				case ast_type_symbol_t::Builtin: {
					const lexer_token& tok = std::get<lexer_token>(reduced.children);
					const std::string kw = std::get<std::string>(tok.value);
					if (kw == "int") {
						return ast_type_node(ast_type_node::type_t::Int, std::monostate{});
					}
					else if (kw == "void") {
						return ast_type_node(ast_type_node::type_t::Void, std::monostate{});
					}
					else if (kw == "bool") {
						return ast_type_node(ast_type_node::type_t::Bool, std::monostate{});
					}
					throw std::runtime_error("Unknown builtin type keyword: " + kw);
				}
				case ast_type_symbol_t::Custom: {
					const lexer_token& tok = std::get<lexer_token>(reduced.children);
					const std::string name = std::get<std::string>(tok.value);
					return ast_type_node(ast_type_node::type_t::Custom, name);
				}
				case ast_type_symbol_t::Array: {
					const auto& children = std::get<std::vector<ShiftReduceParser<lexer_token, ast_type_symbol_t>::Reduced>>(
						reduced.children);
					ast_type_node base_type = build_type_node(children[0]);
					const auto& array_brackets = children[1];
					if (array_brackets.children.index() == 0) {
						// []
						ast_type_array arr;
						arr.base = std::make_shared<ast_type_node>(base_type);
						arr.size = 0;
						return ast_type_node(ast_type_node::type_t::Array, arr);
					}
					else if (array_brackets.children.index() == 1) {
						// [N]
						const lexer_token& size_tok = std::get<lexer_token>(
							std::get<std::vector<ShiftReduceParser<lexer_token, ast_type_symbol_t>::Reduced>>(array_brackets.children)
							[1].children);
						size_t size = static_cast<size_t>(std::get<int>(size_tok.value));
						ast_type_array arr;
						arr.base = std::make_shared<ast_type_node>(base_type);
						arr.size = size;
						return ast_type_node(ast_type_node::type_t::Array, arr);
					}
					throw std::runtime_error("Invalid array brackets parse");
				}
				case ast_type_symbol_t::Pointer: {
					const auto& children = std::get<std::vector<ShiftReduceParser<lexer_token, ast_type_symbol_t>::Reduced>>(
						reduced.children);
					ast_type_node base_type = build_type_node(children[0]);
					ast_type_pointer ptr;
					ptr.base = std::make_shared<ast_type_node>(base_type);
					return ast_type_node(ast_type_node::type_t::Pointer, ptr);
				}
				case ast_type_symbol_t::Type: {
					if (reduced.children.index() == 0) {
						throw std::runtime_error("Invalid type parse");
					}
					if (reduced.children.index() == 1) {
						const auto& child = std::get<std::vector<ShiftReduceParser<lexer_token, ast_type_symbol_t>::Reduced>>(
							reduced.children)[0];
						return build_type_node(child);
					}
					throw std::runtime_error("Invalid type parse");
				}
				default:
					throw std::runtime_error("Invalid type parse");
			}
		}

		const ast_type_parser_t ast_type_definition_parser = Parser<lexer_token, std::shared_ptr<ast_type_node>>(
			[](const std::vector<lexer_token>& input, std::vector<std::pair<std::shared_ptr<ast_type_node>, size_t>>& output,
			ParserTable&) {
				int consumed = 0;
				std::vector<ShiftReduceParser<lexer_token, ast_type_symbol_t>::Reduced> reduced = ast_type_symbol_parser.parse(
					input, consumed);
				if (reduced.empty()) {
					return;
				}
				const auto& first = reduced.front();
				if (first.symbol != ast_type_symbol_t::Type) {
					return;
				}
				ast_type_node type_node = build_type_node(first);
				output.emplace_back(std::make_shared<ast_type_node>(type_node), first.consumed_terminal_count);
			},
			"TypeDefinition"
		);

		const Parser<lexer_token, std::pair<std::string, std::shared_ptr<ast_type_node>>> ast_type_struct_member_parser =
			(ast_type_definition_parser + util::identifier() < util::punctuation(';'))
			.map<std::pair<std::string, std::shared_ptr<ast_type_node>>>(
				[](const auto& p) {
					return std::make_pair(std::get<std::string>(p.second.value), p.first);
				},
				"StructMember"
			).rename("StructMember");
		const ast_type_parser_t ast_type_struct_parser =
		(util::keyword("struct") > util::identifier() +
			(util::punctuation('{') >
				+ast_type_struct_member_parser
				< util::punctuation('}')
				< util::punctuation(';')
			)
		).map<std::shared_ptr<ast_type_node>>(
			[](const auto& p) {
				ast_type_struct strct;
				strct.name = std::get<std::string>(p.first.value);
				strct.members = p.second;
				return std::make_shared<ast_type_node>(ast_type_node::type_t::Struct, strct);
			},
			"StructType"
		).rename("StructType");
		const ast_type_parser_t ast_type_parser = (
			ast_type_definition_parser ||
			ast_type_struct_parser
		).rename("Type");
	} // type_parser


	typedef Parser<lexer_token, std::shared_ptr<ast_node>> ast_parser_t;

	// Forward declarations for recursive parsers
	const ast_parser_t ref_ast_expression_parser = ref_parser<lexer_token,
		std::shared_ptr<ast_node>>("ast_expression_parser");
	const ast_parser_t ref_ast_statement_parser = ref_parser<lexer_token,
		std::shared_ptr<ast_node>>("ast_statement_parser");
	const ast_parser_t ref_ast_block_parser = ref_parser<lexer_token,
		std::shared_ptr<ast_node>>("ast_block_parser");
	const ast_parser_t ref_ast_l0_expression_parser = ref_parser<lexer_token,
		std::shared_ptr<ast_node>>("ast_l0_expression_parser");
	const ast_parser_t ref_ast_l1_expression_parser = ref_parser<lexer_token,
		std::shared_ptr<ast_node>>("ast_l1_expression_parser");
	const ast_parser_t ref_ast_l2_expression_parser = ref_parser<lexer_token,
		std::shared_ptr<ast_node>>("ast_l2_expression_parser");
	const ast_parser_t ref_ast_l3_expression_parser = ref_parser<lexer_token,
		std::shared_ptr<ast_node>>("ast_l3_expression_parser");
	const ast_parser_t ref_ast_l4_expression_parser = ref_parser<lexer_token,
		std::shared_ptr<ast_node>>("ast_l4_expression_parser");
	const ast_parser_t ref_ast_l5_expression_parser = ref_parser<lexer_token,
		std::shared_ptr<ast_node>>("ast_l5_expression_parser");
	const ast_parser_t ref_ast_l6_expression_parser = ref_parser<lexer_token,
		std::shared_ptr<ast_node>>("ast_l6_expression_parser");
	const ast_parser_t ref_ast_l7_expression_parser = ref_parser<lexer_token,
		std::shared_ptr<ast_node>>("ast_l7_expression_parser");
	const ast_parser_t ref_ast_l8_expression_parser = ref_parser<lexer_token,
		std::shared_ptr<ast_node>>("ast_l8_expression_parser");
	const ast_parser_t ref_ast_l9_expression_parser = ref_parser<lexer_token,
		std::shared_ptr<ast_node>>("ast_l9_expression_parser");
	const ast_parser_t ref_ast_l10_expression_parser = ref_parser<lexer_token,
		std::shared_ptr<ast_node>>("ast_l10_expression_parser");
	const ast_parser_t ref_ast_l11_expression_parser = ref_parser<lexer_token,
		std::shared_ptr<ast_node>>("ast_l11_expression_parser");
	const ast_parser_t ref_ast_l12_expression_parser = ref_parser<lexer_token,
		std::shared_ptr<ast_node>>("ast_l12_expression_parser");
	const ast_parser_t ref_ast_l13_expression_parser = ref_parser<lexer_token,
		std::shared_ptr<ast_node>>("ast_l13_expression_parser");
	const ast_parser_t ref_ast_l14_expression_parser = ref_parser<lexer_token,
		std::shared_ptr<ast_node>>("ast_l14_expression_parser");

	const ast_parser_t ast_integer_parser =
		util::integer().map<std::shared_ptr<ast_node>>(
			[](const lexer_token& tok) {
				return util::make_ast_node(ast_node::type_t::IntegerLiteral, std::get<int>(tok.value));
			},
			"IntegerLiteral"
		);

	const ast_parser_t ast_identifier_parser =
		util::identifier().map<std::shared_ptr<ast_node>>(
			[](const lexer_token& tok) {
				return util::make_ast_node(ast_node::type_t::Identifier, std::get<std::string>(tok.value));
			},
			"Identifier"
		);

	// I need to have this split into multiple levels to handle precedence and associativity correctly
	/*
	 * Order:
	 * 0:
	 *  - parenthesized expressions
	 *  - identifiers
	 *  - literals
	 * 1: (left associative)
	 *  - postfix increment/decrement
	 *  - function calls
	 *  - array subscripting
	 *  - member access (.), pointer to member access (->)
	 * 2: (right associative)
	 *  - prefix increment/decrement
	 *  - unary +/-, logical not (!), bitwise not (~), dereference (*), address-of (&)
	 *  - sizeof
	 *  - cast
	 * 3: (left associative)
	 *  - multiplicative (*, /, %)
	 * 4: (left associative)
	 *  - additive (+, -)
	 * 5: (left associative)
	 *  - shift (<<, >>)
	 * 6: (left associative)
	 *  - relational (<, <=, >, >=)
	 * 7: (left associative)
	 *  - equality (==, !=)
	 * 8: (left associative)
	 *  - bitwise AND (&)
	 * 9: (left associative)
	 *  - bitwise XOR (^)
	 * 10: (left associative)
	 *  - bitwise OR (|)
	 * 11: (left associative)
	 *  - logical AND (&&)
	 * 12: (left associative)
	 *  - logical OR (||)
	 * 13: (right associative)
	 *  - ternary (?:)
	 * 14: (right associative)
	 *  - assignment (=, (+=, -=, *=, /=, %=, <<=, >>=, &=, ^=, |=)) for now only =
	 * 15: (left associative)
	 *  - comma operator (,)
	 */

	// Level 0
	const ast_parser_t ast_l0_parenthesized_expression_parser =
		(util::punctuation('(') > ref_ast_expression_parser < util::punctuation(')')).rename("ParenthesizedExpression");
	const ast_parser_t ast_l0_identifier_parser = ast_identifier_parser.rename("Identifier");
	const ast_parser_t ast_l0_integer_parser = ast_integer_parser.rename("IntegerLiteral");
	const ast_parser_t ast_l0_expression_parser = (
		ast_l0_parenthesized_expression_parser ||
		ast_l0_identifier_parser ||
		ast_l0_integer_parser
	).rename("ExpressionLevel0");

	// Level 1
	struct ast_l1_element {
		enum class type_t {
			FunctionCall,
			PostfixIncrement,
			PostfixDecrement,
			ArraySubscript,
			MemberAccess
		} type;
		std::variant<
			std::vector<std::shared_ptr<ast_node>>, // FunctionCall
			std::shared_ptr<ast_node>, // ArraySubscript
			std::monostate, // PostfixIncrement, PostfixDecrement
			std::pair<bool, std::string> // MemberAccess (bool is pointer access)
		> value;
	};
	typedef Parser<lexer_token, ast_l1_element> ast_l1_element_parser_t;
	const ast_l1_element_parser_t ast_l1_function_call_element_parser =
		(util::punctuation('(') >
			(ref_ast_expression_parser % util::punctuation(',')) <
			util::punctuation(')')
		)
		.map<ast_l1_element>(
			[](const auto& args) {
				ast_l1_element elem;
				elem.type = ast_l1_element::type_t::FunctionCall;
				elem.value = args;
				return elem;
			},
			"FunctionCallElement"
		).rename("FunctionCallElement");
	const ast_l1_element_parser_t ast_l1_postfix_element_parser =
		(util::op({"++", "--"}))
		.map<ast_l1_element>(
			[](const lexer_token& tok) {
				ast_l1_element elem;
				operator_type_t op_type = std::get<operator_type_t>(tok.value);
				switch (op_type) {
					case operator_type_t::PlusPlus:
						elem.type = ast_l1_element::type_t::PostfixIncrement;
						break;
					case operator_type_t::MinusMinus:
						elem.type = ast_l1_element::type_t::PostfixDecrement;
						break;
					default:
						throw std::runtime_error("Unknown postfix operator");
				}
				elem.value = std::monostate{};
				return elem;
			},
			"PostfixElement"
		).rename("PostfixElement");
	const ast_l1_element_parser_t ast_l1_array_subscript_element_parser =
		(util::punctuation('[') > ref_ast_expression_parser < util::punctuation(']'))
		.map<ast_l1_element>(
			[](const std::shared_ptr<ast_node>& index) {
				ast_l1_element elem;
				elem.type = ast_l1_element::type_t::ArraySubscript;
				elem.value = index;
				return elem;
			},
			"ArraySubscriptElement"
		).rename("ArraySubscriptElement");
	const ast_l1_element_parser_t ast_l1_member_access_element_parser =
	((util::punctuation('.').map<bool>([](const lexer_token&) {
				return false;
			}, "dot") ||
			util::op("->").map<bool>([](const lexer_token&) {
				return true;
			}, "arrow")) +
		ast_identifier_parser
	).map<ast_l1_element>(
		[](const auto& p) {
			ast_l1_element elem;
			elem.type = ast_l1_element::type_t::MemberAccess;
			elem.value = std::make_pair(p.first, std::get<std::string>(p.second->value));
			return elem;
		},
		"MemberAccessElement"
	).rename("MemberAccessElement");
	const ast_parser_t ast_l1_expression_parser =
	(ref_ast_l0_expression_parser +
		*(ast_l1_postfix_element_parser ||
			ast_l1_array_subscript_element_parser ||
			ast_l1_member_access_element_parser ||
			ast_l1_function_call_element_parser)
	).map<std::shared_ptr<ast_node>>(
		[](const auto& p) {
			std::shared_ptr<ast_node> base = p.first;
			for (const auto& elem : p.second) {
				switch (elem.type) {
					case ast_l1_element::type_t::FunctionCall: {
						ast_expression_call expr;
						expr.callee = base;
						expr.arguments = std::get<std::vector<std::shared_ptr<ast_node>>>(elem.value);
						base = util::make_ast_node(ast_node::type_t::FunctionCall, expr);
						break;
					}
					case ast_l1_element::type_t::PostfixIncrement: {
						ast_expression_unary expr;
						expr.type = ast_expression_unary::type_t::PostfixIncrement;
						expr.operand = base;
						base = util::make_ast_node(ast_node::type_t::UnaryExpression, expr);
						break;
					}
					case ast_l1_element::type_t::PostfixDecrement: {
						ast_expression_unary expr;
						expr.type = ast_expression_unary::type_t::PostfixDecrement;
						expr.operand = base;
						base = util::make_ast_node(ast_node::type_t::UnaryExpression, expr);
						break;
					}
					case ast_l1_element::type_t::ArraySubscript: {
						ast_expression_binary expr;
						expr.type = ast_expression_binary::type_t::ArraySubscript;
						expr.left = base;
						expr.right = std::get<std::shared_ptr<ast_node>>(elem.value);
						base = util::make_ast_node(ast_node::type_t::BinaryExpression, expr);
						break;
					}
					case ast_l1_element::type_t::MemberAccess: {
						ast_member_access expr;
						expr.object = base;
						auto [is_pointer, member_name] = std::get<std::pair<bool, std::string>>(elem.value);
						expr.property = member_name;
						expr.pointer = is_pointer;
						base = util::make_ast_node(ast_node::type_t::MemberAccess, expr);
						break;
					}
					default:
						throw std::runtime_error("Unknown L1 element type");
				}
			}
			return base;
		},
		"ExpressionLevel1"
	).rename("ExpressionLevel1");

	// Level 2
	const ast_parser_t ast_l2_prefix_parser =
		(+util::op({"++", "--", "+", "-", "!", "~", "*", "&"}) +
			ref_ast_l1_expression_parser)
		.map<std::shared_ptr<ast_node>>(
			[](const auto& p) {
				std::shared_ptr<ast_node> right = p.second;
				// Apply operators in reverse order (right associative)
				const auto& ops = p.first;
				for (auto it = ops.rbegin(); it != ops.rend(); ++it) {
					ast_expression_unary expr;
					operator_type_t op_type = std::get<operator_type_t>(it->value);
					expr.operand = right;
					switch (op_type) {
						case operator_type_t::PlusPlus:
							expr.type = ast_expression_unary::type_t::PrefixIncrement;
							break;
						case operator_type_t::MinusMinus:
							expr.type = ast_expression_unary::type_t::PrefixDecrement;
							break;
						case operator_type_t::Plus:
							expr.type = ast_expression_unary::type_t::Positive;
							break;
						case operator_type_t::Minus:
							expr.type = ast_expression_unary::type_t::Negate;
							break;
						case operator_type_t::Exclamation:
							expr.type = ast_expression_unary::type_t::LogicalNot;
							break;
						case operator_type_t::Tilde:
							expr.type = ast_expression_unary::type_t::BitwiseNot;
							break;
						case operator_type_t::Asterisk:
							expr.type = ast_expression_unary::type_t::Dereference;
							break;
						case operator_type_t::Ampersand:
							expr.type = ast_expression_unary::type_t::AddressOf;
							break;
						default:
							// Should not happen
							throw std::runtime_error("Unknown unary operator");
					}
					right = util::make_ast_node(ast_node::type_t::UnaryExpression, expr);
				}
				return right;
			}, "PrefixExpression"
		).rename("PrefixExpression");
	const ast_parser_t ast_l2_sizeof_parser =
	(util::keyword("sizeof") >
		(ref_ast_l1_expression_parser || (util::punctuation('(') > ast_identifier_parser < util::punctuation(')')))
	).map<std::shared_ptr<ast_node>>(
		[](const std::shared_ptr<ast_node>& operand) {
			ast_expression_unary expr;
			expr.type = ast_expression_unary::type_t::SizeOf;
			expr.operand = operand;
			return util::make_ast_node(ast_node::type_t::UnaryExpression, expr);
		},
		"SizeOfExpression"
	).rename("SizeOfExpression");
	const ast_parser_t ast_l2_expression_parser = (
		ast_l2_prefix_parser ||
		ast_l2_sizeof_parser ||
		ref_ast_l1_expression_parser
	).rename("ExpressionLevel2");

	// Level 3
	const ast_parser_t ast_l3_multiplicative_parser =
	(ref_ast_l2_expression_parser +
		*(util::op({"*", "/", "%"}) + ref_ast_l2_expression_parser)
	).map<std::shared_ptr<ast_node>>(
		[](const auto& p) {
			std::shared_ptr<ast_node> left = p.first;
			for (const auto& op_pair : p.second) {
				ast_expression_binary expr;
				operator_type_t op_type = std::get<operator_type_t>(op_pair.first.value);
				switch (op_type) {
					case operator_type_t::Asterisk:
						expr.type = ast_expression_binary::type_t::Multiply;
						break;
					case operator_type_t::Slash:
						expr.type = ast_expression_binary::type_t::Divide;
						break;
					case operator_type_t::Percent:
						expr.type = ast_expression_binary::type_t::Modulo;
						break;
					default:
						// Should not happen
						throw std::runtime_error("Unknown multiplicative operator");
				}
				expr.left = left;
				expr.right = op_pair.second;
				left = util::make_ast_node(ast_node::type_t::BinaryExpression, expr);
			}
			return left;
		},
		"MultiplicativeExpression"
	).rename("MultiplicativeExpression");
	const ast_parser_t ast_l3_expression_parser = ast_l3_multiplicative_parser.rename("ExpressionLevel3");

	// Level 4
	const ast_parser_t ast_l4_additive_parser =
	(ref_ast_l3_expression_parser +
		*(util::op({"+", "-"}) + ref_ast_l3_expression_parser)
	).map<std::shared_ptr<ast_node>>(
		[](const auto& p) {
			std::shared_ptr<ast_node> left = p.first;
			for (const auto& op_pair : p.second) {
				ast_expression_binary expr;
				operator_type_t op_type = std::get<operator_type_t>(op_pair.first.value);
				switch (op_type) {
					case operator_type_t::Plus:
						expr.type = ast_expression_binary::type_t::Add;
						break;
					case operator_type_t::Minus:
						expr.type = ast_expression_binary::type_t::Subtract;
						break;
					default:
						// Should not happen
						throw std::runtime_error("Unknown additive operator");
				}
				expr.left = left;
				expr.right = op_pair.second;
				left = util::make_ast_node(ast_node::type_t::BinaryExpression, expr);
			}
			return left;
		},
		"AdditiveExpression"
	).rename("AdditiveExpression");
	const ast_parser_t ast_l4_expression_parser = ast_l4_additive_parser.rename("ExpressionLevel4");

	// Level 5
	const ast_parser_t ast_l5_shift_parser =
	(ref_ast_l4_expression_parser +
		*(util::op({"<<", ">>"}) + ref_ast_l4_expression_parser)
	).map<std::shared_ptr<ast_node>>(
		[](const auto& p) {
			std::shared_ptr<ast_node> left = p.first;
			for (const auto& op_pair : p.second) {
				ast_expression_binary expr;
				operator_type_t op_type = std::get<operator_type_t>(op_pair.first.value);
				switch (op_type) {
					case operator_type_t::ShiftLeft:
						expr.type = ast_expression_binary::type_t::ShiftLeft;
						break;
					case operator_type_t::ShiftRight:
						expr.type = ast_expression_binary::type_t::ShiftRight;
						break;
					default:
						// Should not happen
						throw std::runtime_error("Unknown shift operator");
				}
				expr.left = left;
				expr.right = op_pair.second;
				left = util::make_ast_node(ast_node::type_t::BinaryExpression, expr);
			}
			return left;
		},
		"ShiftExpression"
	).rename("ShiftExpression");
	const ast_parser_t ast_l5_expression_parser = ast_l5_shift_parser.rename("ExpressionLevel5");

	// Level 6
	const ast_parser_t ast_l6_relational_parser =
	(ref_ast_l5_expression_parser +
		*(util::op({"<", "<=", ">", ">="}) + ref_ast_l5_expression_parser)
	).map<std::shared_ptr<ast_node>>(
		[](const auto& p) {
			std::shared_ptr<ast_node> left = p.first;
			if (p.second.empty()) {
				return left;
			}
			std::vector<std::shared_ptr<ast_node>> terms;
			for (const auto& op_pair : p.second) {
				ast_expression_binary expr;
				operator_type_t op_type = std::get<operator_type_t>(op_pair.first.value);
				switch (op_type) {
					case operator_type_t::LessThan:
						expr.type = ast_expression_binary::type_t::Less;
						break;
					case operator_type_t::LessEqual:
						expr.type = ast_expression_binary::type_t::LessEqual;
						break;
					case operator_type_t::GreaterThan:
						expr.type = ast_expression_binary::type_t::Greater;
						break;
					case operator_type_t::GreaterEqual:
						expr.type = ast_expression_binary::type_t::GreaterEqual;
						break;
					default:
						// Should not happen
						throw std::runtime_error("Unknown relational operator");
				}
				expr.left = left;
				expr.right = op_pair.second;
				terms.push_back(util::make_ast_node(ast_node::type_t::BinaryExpression, expr));
				left = op_pair.second;
			}
			if (terms.size() == 1) {
				return terms[0];
			}
			else {
				// Chain relational expressions into a series of logical ANDs
				std::shared_ptr<ast_node> result = terms[0];
				for (size_t i = 1; i < terms.size(); ++i) {
					ast_expression_binary expr;
					expr.type = ast_expression_binary::type_t::LogicalAnd;
					expr.left = result;
					expr.right = terms[i];
					result = util::make_ast_node(ast_node::type_t::BinaryExpression, expr);
				}
				return result;
			}
		},
		"RelationalExpression"
	).rename("RelationalExpression");
	const ast_parser_t ast_l6_expression_parser = ast_l6_relational_parser.rename("ExpressionLevel6");

	// Level 7
	const ast_parser_t ast_l7_equality_parser =
	(ref_ast_l6_expression_parser +
		*(util::op({"==", "!="}) + ref_ast_l6_expression_parser)
	).map<std::shared_ptr<ast_node>>(
		[](const auto& p) {
			std::shared_ptr<ast_node> left = p.first;
			for (const auto& op_pair : p.second) {
				ast_expression_binary expr;
				operator_type_t op_type = std::get<operator_type_t>(op_pair.first.value);
				switch (op_type) {
					case operator_type_t::EqualEqual:
						expr.type = ast_expression_binary::type_t::Equal;
						break;
					case operator_type_t::NotEqual:
						expr.type = ast_expression_binary::type_t::NotEqual;
						break;
					default:
						// Should not happen
						throw std::runtime_error("Unknown equality operator");
				}
				expr.left = left;
				expr.right = op_pair.second;
				left = util::make_ast_node(ast_node::type_t::BinaryExpression, expr);
			}
			return left;
		},
		"EqualityExpression"
	).rename("EqualityExpression");
	const ast_parser_t ast_l7_expression_parser = ast_l7_equality_parser.rename("ExpressionLevel7");

	// Level 8
	const ast_parser_t ast_l8_bitwise_and_parser =
	(ref_ast_l7_expression_parser +
		*(util::op("&") + ref_ast_l7_expression_parser)
	).map<std::shared_ptr<ast_node>>(
		[](const auto& p) {
			std::shared_ptr<ast_node> left = p.first;
			for (const auto& op_pair : p.second) {
				ast_expression_binary expr;
				expr.type = ast_expression_binary::type_t::BitwiseAnd;
				expr.left = left;
				expr.right = op_pair.second;
				left = util::make_ast_node(ast_node::type_t::BinaryExpression, expr);
			}
			return left;
		},
		"BitwiseAndExpression"
	).rename("BitwiseAndExpression");
	const ast_parser_t ast_l8_expression_parser = ast_l8_bitwise_and_parser.rename("ExpressionLevel8");

	// Level 9
	const ast_parser_t ast_l9_bitwise_xor_parser =
	(ref_ast_l8_expression_parser +
		*(util::op("^") + ref_ast_l8_expression_parser)
	).map<std::shared_ptr<ast_node>>(
		[](const auto& p) {
			std::shared_ptr<ast_node> left = p.first;
			for (const auto& op_pair : p.second) {
				ast_expression_binary expr;
				expr.type = ast_expression_binary::type_t::BitwiseXor;
				expr.left = left;
				expr.right = op_pair.second;
				left = util::make_ast_node(ast_node::type_t::BinaryExpression, expr);
			}
			return left;
		},
		"BitwiseXorExpression"
	).rename("BitwiseXorExpression");
	const ast_parser_t ast_l9_expression_parser = ast_l9_bitwise_xor_parser.rename("ExpressionLevel9");

	// Level 10
	const ast_parser_t ast_l10_bitwise_or_parser =
	(ref_ast_l9_expression_parser +
		*(util::op("|") + ref_ast_l9_expression_parser)
	).map<std::shared_ptr<ast_node>>(
		[](const auto& p) {
			std::shared_ptr<ast_node> left = p.first;
			for (const auto& op_pair : p.second) {
				ast_expression_binary expr;
				expr.type = ast_expression_binary::type_t::BitwiseOr;
				expr.left = left;
				expr.right = op_pair.second;
				left = util::make_ast_node(ast_node::type_t::BinaryExpression, expr);
			}
			return left;
		},
		"BitwiseOrExpression"
	).rename("BitwiseOrExpression");
	const ast_parser_t ast_l10_expression_parser = ast_l10_bitwise_or_parser.rename("ExpressionLevel10");

	// Level 11 (left associative)
	const ast_parser_t ast_l11_logical_and_parser =
	(ref_ast_l10_expression_parser +
		*(util::op("&&") + ref_ast_l10_expression_parser)
	).map<std::shared_ptr<ast_node>>(
		[](const auto& p) {
			std::shared_ptr<ast_node> left = p.first;
			for (const auto& op_pair : p.second) {
				ast_expression_binary expr;
				expr.type = ast_expression_binary::type_t::LogicalAnd;
				expr.left = left;
				expr.right = op_pair.second;
				left = util::make_ast_node(ast_node::type_t::BinaryExpression, expr);
			}
			return left;
		},
		"LogicalAndExpression"
	).rename("LogicalAndExpression");
	const ast_parser_t ast_l11_expression_parser = ast_l11_logical_and_parser.rename("ExpressionLevel11");

	// Level 12 (left associative)
	const ast_parser_t ast_l12_logical_or_parser =
	(ref_ast_l11_expression_parser +
		*(util::op("||") + ref_ast_l11_expression_parser)
	).map<std::shared_ptr<ast_node>>(
		[](const auto& p) {
			std::shared_ptr<ast_node> left = p.first;
			for (const auto& op_pair : p.second) {
				ast_expression_binary expr;
				expr.type = ast_expression_binary::type_t::LogicalOr;
				expr.left = left;
				expr.right = op_pair.second;
				left = util::make_ast_node(ast_node::type_t::BinaryExpression, expr);
			}
			return left;
		},
		"LogicalOrExpression"
	).rename("LogicalOrExpression");
	const ast_parser_t ast_l12_expression_parser = ast_l12_logical_or_parser.rename("ExpressionLevel12");

	// Level 13 (right associative)
	const ast_parser_t ast_l13_ternary_parser =
	(ref_ast_l12_expression_parser +
		~((util::op("?") > ref_ast_expression_parser) +
			(util::punctuation(':') > ref_ast_expression_parser))
	).map<std::shared_ptr<ast_node>>(
		[](const auto& p) {
			if (!p.second.has_value()) {
				return p.first;
			}
			ast_expression_ternary expr;
			expr.condition = p.first;
			expr.then_branch = p.second.value().first;
			expr.else_branch = p.second.value().second;
			return util::make_ast_node(ast_node::type_t::TernaryExpression, expr);
		},
		"TernaryExpression"
	).rename("TernaryExpression");
	const ast_parser_t ast_l13_expression_parser = ast_l13_ternary_parser.rename("ExpressionLevel13");

	// Level 14 (right associative)
	const ast_parser_t ast_l14_assignment_parser =
	(ref_ast_l13_expression_parser +
		*(util::op({"="}) + ref_ast_expression_parser)
	).map<std::shared_ptr<ast_node>>(
		[](const auto& p) {
			std::shared_ptr<ast_node> left = p.first;
			for (const auto& op_pair : p.second) {
				ast_expression_binary expr;
				operator_type_t op_type = std::get<operator_type_t>(op_pair.first.value);
				switch (op_type) {
					case operator_type_t::Equal:
						expr.type = ast_expression_binary::type_t::Assignment;
						break;
					default:
						// Should not happen
						throw std::runtime_error("Unknown assignment operator");
				}
				expr.left = left;
				expr.right = op_pair.second;
				left = util::make_ast_node(ast_node::type_t::BinaryExpression, expr);
			}
			return left;
		},
		"AssignmentExpression"
	).rename("AssignmentExpression");
	const ast_parser_t ast_l14_expression_parser = ast_l14_assignment_parser.rename("ExpressionLevel14");

	// Level 15 (left associative)
	const ast_parser_t ast_l15_comma_parser =
		(ref_ast_l14_expression_parser % util::punctuation(',')
		).filter(
			[](const std::vector<std::shared_ptr<ast_node>>& exprs) {
				return !exprs.empty();
			},
			"NonEmptyCommaExpression"
		)
		.map<std::shared_ptr<ast_node>>(
			[](const auto& p) {
				if (p.size() == 1) {
					return p[0];
				}
				ast_expression_binary expr;
				expr.type = ast_expression_binary::type_t::Comma;
				std::shared_ptr<ast_node> left = p[0];
				for (size_t i = 1; i < p.size(); ++i) {
					expr.left = left;
					expr.right = p[i];
					left = util::make_ast_node(ast_node::type_t::BinaryExpression, expr);
				}
				return left;
			},
			"CommaExpression"
		).rename("CommaExpression");

	// Expression parser
	const ast_parser_t ast_expression_parser = ast_l15_comma_parser.rename("Expression");

	// Statements
	const ast_parser_t ast_variable_declaration_parser =
		(type_parser::ast_type_definition_parser +
			util::identifier() +
			~(util::op("=") > ref_ast_expression_parser) < util::punctuation(';'))
		.map<std::shared_ptr<ast_node>>(
			[](const auto& p) {
				ast_statement_variable_declaration var_decl;
				var_decl.var_type = p.first.first;
				var_decl.name = std::get<std::string>(p.first.second.value);
				if (p.second.has_value()) {
					var_decl.initializer = p.second.value();
				}
				else {
					var_decl.initializer = nullptr;
				}
				return util::make_ast_node(ast_node::type_t::VariableDeclaration, var_decl);
			},
			"VariableDeclaration"
		).rename("VariableDeclaration");

	const Parser<lexer_token, std::pair<std::string, std::shared_ptr<ast_type_node>>> ast_function_parameter_parser =
		(type_parser::ast_type_definition_parser + util::identifier())
		.map<std::pair<std::string, std::shared_ptr<ast_type_node>>>(
			[](const auto& p) {
				return std::make_pair(std::get<std::string>(p.second.value), p.first);
			},
			"FunctionParameter"
		).rename("FunctionParameter");
	const ast_parser_t ast_function_declaration_parser =
		(type_parser::ast_type_definition_parser +
			util::identifier() +
			(util::punctuation('(') >
				(ast_function_parameter_parser % util::punctuation(',')) < util::punctuation(')')) +
			ref_ast_block_parser)
		.map<std::tuple<std::shared_ptr<ast_type_node>, std::string, std::vector<std::pair<std::string, std::shared_ptr<
			ast_type_node>>>, std::shared_ptr<ast_node>>>(
			[](const auto& p) {
				return std::make_tuple(
					p.first.first.first, std::get<std::string>(p.first.first.second.value), p.first.second, p.second
				);
			},
			"FunctionDeclarationTuple"
		).rename("FunctionDeclarationTuple")
		.map<std::shared_ptr<ast_node>>(
			[](const auto& p) {
				ast_statement_function_declaration func_decl;
				func_decl.return_type = std::get<0>(p);
				func_decl.name = std::get<1>(p);
				func_decl.parameters = std::get<2>(p);
				func_decl.body = std::get<3>(p);
				return util::make_ast_node(ast_node::type_t::FunctionDeclaration, func_decl);
			},
			"FunctionDeclaration"
		).rename("FunctionDeclaration");


	const ast_parser_t ref_ast_if_statement_parser = ref_parser<lexer_token,
		std::shared_ptr<ast_node>>("ast_if_statement_parser");
	const Parser<lexer_token, std::pair<std::shared_ptr<ast_node>, std::shared_ptr<ast_node>>> ast_if_clause_parser =
		((util::keyword("if") >
				util::punctuation('(') > ref_ast_expression_parser < util::punctuation(')')) +
			ref_ast_block_parser)
		.rename("IfStatement");
	const Parser<lexer_token, std::shared_ptr<ast_node>> ast_else_clause_parser =
		(util::keyword("else") > (ref_ast_if_statement_parser || ref_ast_block_parser))
		.rename("ElseClause");
	const ast_parser_t ast_if_statement_parser =
		(ast_if_clause_parser + ~ast_else_clause_parser)
		.map<std::shared_ptr<ast_node>>(
			[](const auto& p) {
				ast_statement_if if_stmt;
				if_stmt.condition = p.first.first;
				if_stmt.then_branch = p.first.second;
				if (p.second.has_value()) {
					if_stmt.else_branch = p.second.value();
				}
				else {
					if_stmt.else_branch = nullptr;
				}
				return util::make_ast_node(ast_node::type_t::IfStatement, if_stmt);
			},
			"IfStatement"
		).rename("IfStatement");

	const ast_parser_t ast_while_statement_parser =
		((util::keyword("while") >
				util::punctuation('(') > ref_ast_expression_parser < util::punctuation(')')) +
			ref_ast_block_parser)
		.map<std::shared_ptr<ast_node>>(
			[](const auto& p) {
				ast_statement_while while_stmt;
				while_stmt.condition = p.first;
				while_stmt.body = p.second;
				return util::make_ast_node(ast_node::type_t::WhileStatement, while_stmt);
			},
			"WhileStatement"
		).rename("WhileStatement");
	const ast_parser_t ast_return_statement_parser =
		(util::keyword("return") > ~ref_ast_expression_parser < util::punctuation(';'))
		.map<std::shared_ptr<ast_node>>(
			[](const std::optional<std::shared_ptr<ast_node>>& expr_opt) {
				ast_statement_return return_stmt;
				if (expr_opt.has_value()) {
					return_stmt.value = expr_opt.value();
				}
				else {
					return_stmt.value = nullptr;
				}
				return util::make_ast_node(ast_node::type_t::ReturnStatement, return_stmt);
			},
			"ReturnStatement"
		).rename("ReturnStatement");
	const ast_parser_t ast_expression_statement_parser =
		(ref_ast_expression_parser < util::punctuation(';'))
		.map<std::shared_ptr<ast_node>>(
			[](const std::shared_ptr<ast_node>& expr) {
				ast_statement_expression expr_stmt;
				expr_stmt.expression = expr;
				return util::make_ast_node(ast_node::type_t::ExpressionStatement, expr_stmt);
			},
			"ExpressionStatement"
		).rename("ExpressionStatement");
	const ast_parser_t ast_statement_parser = (
		ast_variable_declaration_parser ||
		ast_if_statement_parser ||
		ast_while_statement_parser ||
		ast_return_statement_parser ||
		ast_expression_statement_parser ||
		ref_ast_block_parser
	).rename("Statement");

	const ast_parser_t ast_block_parser =
		(util::punctuation('{') > *ast_statement_parser < util::punctuation('}'))
		.map<std::shared_ptr<ast_node>>(
			[](const std::vector<std::shared_ptr<ast_node>>& statements) {
				ast_statement_block block;
				block.statements = statements;
				return util::make_ast_node(ast_node::type_t::BlockStatement, block);
			},
			"Block"
		).rename("Block");

	ParserTable get_ast_parsers() {
		ParserTable table;
		table["ast_expression_parser"] = std::make_shared<ast_parser_t>(ast_expression_parser);
		table["ast_block_parser"] = std::make_shared<ast_parser_t>(ast_block_parser);
		table["ast_statement_parser"] = std::make_shared<ast_parser_t>(ast_statement_parser);
		table["ast_if_statement_parser"] = std::make_shared<ast_parser_t>(ast_if_statement_parser);
		table["ast_function_declaration_parser"] = std::make_shared<ast_parser_t>(ast_function_declaration_parser);
		table["ast_variable_declaration_parser"] = std::make_shared<ast_parser_t>(ast_variable_declaration_parser);
		table["ast_l0_expression_parser"] = std::make_shared<ast_parser_t>(ast_l0_expression_parser);
		table["ast_l1_expression_parser"] = std::make_shared<ast_parser_t>(ast_l1_expression_parser);
		table["ast_l2_expression_parser"] = std::make_shared<ast_parser_t>(ast_l2_expression_parser);
		table["ast_l3_expression_parser"] = std::make_shared<ast_parser_t>(ast_l3_expression_parser);
		table["ast_l4_expression_parser"] = std::make_shared<ast_parser_t>(ast_l4_expression_parser);
		table["ast_l5_expression_parser"] = std::make_shared<ast_parser_t>(ast_l5_expression_parser);
		table["ast_l6_expression_parser"] = std::make_shared<ast_parser_t>(ast_l6_expression_parser);
		table["ast_l7_expression_parser"] = std::make_shared<ast_parser_t>(ast_l7_expression_parser);
		table["ast_l8_expression_parser"] = std::make_shared<ast_parser_t>(ast_l8_expression_parser);
		table["ast_l9_expression_parser"] = std::make_shared<ast_parser_t>(ast_l9_expression_parser);
		table["ast_l10_expression_parser"] = std::make_shared<ast_parser_t>(ast_l10_expression_parser);
		table["ast_l11_expression_parser"] = std::make_shared<ast_parser_t>(ast_l11_expression_parser);
		table["ast_l12_expression_parser"] = std::make_shared<ast_parser_t>(ast_l12_expression_parser);
		table["ast_l13_expression_parser"] = std::make_shared<ast_parser_t>(ast_l13_expression_parser);
		table["ast_l14_expression_parser"] = std::make_shared<ast_parser_t>(ast_l14_expression_parser);
		return table;
	}

	// Program
	typedef Parser<lexer_token, std::variant<
		ast_statement_function_declaration,
		ast_type_struct
	>> ast_program_element_parser_t;


	const ast_program_element_parser_t ast_program_function_declaration_parser =
		ast_function_declaration_parser.map<ast_statement_function_declaration>(
			[](const std::shared_ptr<ast_node>& node) {
				const auto& func_decl = std::get<ast_statement_function_declaration>(node->value);
				return func_decl;
			},
			"FunctionDeclarationElement"
		).map<std::variant<
			ast_statement_function_declaration,
			ast_type_struct
		>>(
			[](const ast_statement_function_declaration& func_decl) {
				return std::variant<
					ast_statement_function_declaration,
					ast_type_struct
				>(func_decl);
			},
			"FunctionDeclarationVariant"
		);
	const ast_program_element_parser_t ast_program_struct_declaration_parser =
		type_parser::ast_type_struct_parser.map<ast_type_struct>(
			[](const std::shared_ptr<ast_type_node>& type_node) {
				return std::get<ast_type_struct>(type_node->value);
			},
			"StructDeclarationElement"
		).map<std::variant<
			ast_statement_function_declaration,
			ast_type_struct
		>>(
			[](const ast_type_struct& struct_decl) {
				return std::variant<
					ast_statement_function_declaration,
					ast_type_struct
				>(struct_decl);
			},
			"StructDeclarationVariant"
		);

	const ast_program_element_parser_t ast_program_element_parser = (
		ast_program_function_declaration_parser ||
		ast_program_struct_declaration_parser
	);

	const Parser<lexer_token, ast_program> ast_program_parser =
		(*ast_program_element_parser)
		.map<ast_program>(
			[](const auto& elements) {
				ast_program program;
				program.body = elements;
				return program;
			},
			"ASTProgram"
		);

	std::shared_ptr<ast_type_node> parse_ast_type(const std::vector<lexer_token>& tokens) {
		ParserTable table;
		auto result = type_parser::ast_type_parser.parse(tokens, table);
		if (result.empty()) {
			std::cerr << "Failed to parse type" << std::endl;
			return nullptr;
		}
		if (result.size() > 1) {
			std::cerr << "Ambiguous parse for type" << std::endl;
		}
		return result[0].first;
	}

	std::shared_ptr<ast_node> parse_ast(const std::vector<lexer_token>& tokens) {
		auto table = get_ast_parsers();
		auto result = ast_block_parser.parse(tokens, table);
		if (result.empty()) {
			std::cerr << "Failed to parse AST" << std::endl;
			return nullptr;
		}
		if (result.size() > 1) {
			std::cerr << "Ambiguous parse for AST" << std::endl;
		}
		return result[0].first;
	}

	ast_program parse_ast_program(const std::vector<lexer_token>& tokens) {
		auto table = get_ast_parsers();
		auto result = ast_program_parser.parse(tokens, table);
		if (result.empty()) {
			std::cerr << "Failed to parse AST Program" << std::endl;
			return ast_program{};
		}
		if (result.size() > 1) {
			std::cerr << "Ambiguous parse for AST Program" << std::endl;
		}
		return result[0].first;
	}

	std::ostream& operator<<(std::ostream& os, const ast_type_node& node) {
		os << "Type(";
		switch (node.type) {
			case ast_type_node::type_t::Int:
				os << "int";
				break;
			case ast_type_node::type_t::Void:
				os << "void";
				break;
			case ast_type_node::type_t::Bool:
				os << "bool";
				break;
			case ast_type_node::type_t::Array: {
				const auto& arr = std::get<ast_type_array>(node.value);
				os << "Array(ElementType: " << *arr.base << ", Size: " << arr.size << ")";
				break;
			}
			case ast_type_node::type_t::Pointer: {
				const auto& ptr = std::get<ast_type_pointer>(node.value);
				os << "Pointer(BaseType: " << *ptr.base << ")";
				break;
			}
			case ast_type_node::type_t::Function: {
				const auto& func = std::get<ast_type_function>(node.value);
				os << "Function(ReturnType: " << *func.return_type << ", Parameters: [";
				for (size_t i = 0; i < func.parameters.size(); ++i) {
					os << *func.parameters[i];
					if (i + 1 < func.parameters.size()) {
						os << ", ";
					}
				}
				os << "])";
				break;
			}
			case ast_type_node::type_t::Struct: {
				const auto& strct = std::get<ast_type_struct>(node.value);
				os << "Struct(Name: " << strct.name << ", Members: {";
				for (auto it = strct.members.begin(); it != strct.members.end(); ++it) {
					os << it->first << ": " << *it->second;
					auto next_it = std::next(it);
					if (next_it != strct.members.end()) {
						os << ", ";
					}
				}
				os << "})";
				break;
			}
			case ast_type_node::type_t::Custom:
				os << "Custom(Name: " << std::get<std::string>(node.value) << ")";
				break;
		}
		os << ")";
		return os;
	}

	std::ostream& operator<<(std::ostream& os, const ast_node& node) {
		os << "AST Node(Type: ";
		switch (node.type) {
			case ast_node::type_t::IntegerLiteral:
				os << "IntegerLiteral, Value: " << std::get<int>(node.value);
				break;
			case ast_node::type_t::Identifier:
				os << "Identifier, Value: " << std::get<std::string>(node.value);
				break;
			case ast_node::type_t::BinaryExpression: {
				const auto& expr = std::get<ast_expression_binary>(node.value);
				os << "BinaryExpression(Operator: '" << expr.type << "', Left: " << *expr.left << ", Right: " << *expr.right <<
					")";
				break;
			}
			case ast_node::type_t::UnaryExpression: {
				const auto& expr = std::get<ast_expression_unary>(node.value);
				os << "UnaryExpression(Operator: '" << expr.type << "', Operand: " << *expr.operand << ")";
				break;
			}
			case ast_node::type_t::FunctionCall: {
				const auto& call = std::get<ast_expression_call>(node.value);
				os << "FunctionCall(Callee: " << *call.callee << ", Arguments: [";
				for (size_t i = 0; i < call.arguments.size(); ++i) {
					os << *call.arguments[i];
					if (i + 1 < call.arguments.size()) {
						os << ", ";
					}
				}
				os << "])";
				break;
			}
			case ast_node::type_t::VariableDeclaration: {
				const auto& var_decl = std::get<ast_statement_variable_declaration>(node.value);
				os << "VariableDeclaration(Name: " << var_decl.name << ", Type: " << *var_decl.var_type;
				if (var_decl.initializer) {
					os << ", Initializer: " << *var_decl.initializer;
				}
				os << ")";
				break;
			}
			case ast_node::type_t::FunctionDeclaration: {
				const auto& func_decl = std::get<ast_statement_function_declaration>(node.value);
				os << "FunctionDeclaration(Name: " << func_decl.name << ", ReturnType: " << *func_decl.return_type <<
					", Parameters: [";
				for (size_t i = 0; i < func_decl.parameters.size(); ++i) {
					os << "(" << func_decl.parameters[i].first << ": " << *func_decl.parameters[i].second << ")";
					if (i + 1 < func_decl.parameters.size()) {
						os << ", ";
					}
				}
				os << "], Body: " << *func_decl.body << ")";
				break;
			}
			case ast_node::type_t::IfStatement: {
				const auto& if_stmt = std::get<ast_statement_if>(node.value);
				os << "IfStatement(Condition: " << *if_stmt.condition << ", Then: " << *if_stmt.then_branch;
				if (if_stmt.else_branch) {
					os << ", Else: " << *if_stmt.else_branch;
				}
				os << ")";
				break;
			}
			case ast_node::type_t::WhileStatement: {
				const auto& while_stmt = std::get<ast_statement_while>(node.value);
				os << "WhileStatement(Condition: " << *while_stmt.condition << ", Body: " << *while_stmt.body << ")";
				break;
			}
			case ast_node::type_t::ReturnStatement: {
				const auto& return_stmt = std::get<ast_statement_return>(node.value);
				os << "ReturnStatement";
				if (return_stmt.value) {
					os << "(Value: " << *return_stmt.value << ")";
				}
				else {
					os << "(Value: void)";
				}
				break;
			}
			case ast_node::type_t::ExpressionStatement: {
				const auto& expr_stmt = std::get<ast_statement_expression>(node.value);
				os << "ExpressionStatement(Expression: " << *expr_stmt.expression << ")";
				break;
			}
			case ast_node::type_t::BlockStatement: {
				const auto& block = std::get<ast_statement_block>(node.value);
				os << "BlockStatement(Statements: [";
				for (size_t i = 0; i < block.statements.size(); ++i) {
					os << *block.statements[i];
					if (i + 1 < block.statements.size()) {
						os << ", ";
					}
				}
				os << "])";
				break;
			}
			case ast_node::type_t::MemberAccess: {
				const auto& member_access = std::get<ast_member_access>(node.value);
				os << "MemberAccess(Object: " << *member_access.object << ", Property: " << member_access.property <<
					", Pointer: "
					<< (member_access.pointer ? "true" : "false") << ")";
				break;
			}
			case ast_node::type_t::TernaryExpression: {
				const auto& ternary = std::get<ast_expression_ternary>(node.value);
				os << "TernaryExpression(Condition: " << *ternary.condition << ", Then: " << *ternary.then_branch << ", Else: "
					<< *ternary.else_branch << ")";
				break;
			}
			case ast_node::type_t::Unknown:
				os << "Unknown";
				break;
		}
		os << ")";
		return os;
	}

	std::ostream& operator<<(std::ostream& os, const ast_program& program) {
		os << "Program:\n";
		for (const auto& elem : program.body) {
			std::visit([&os]<typename T0>(const T0& node) {
				if constexpr (std::is_same_v<T0, ast_statement_function_declaration>) {
					os << "  Function Declaration: " << node.name << "\n  Return Type: " << *node.return_type <<
						"\n  Parameters:\n";
					for (const auto& param : node.parameters) {
						os << "    " << param.first << ": " << *param.second << "\n";
					}
					os << "  Body:\n" << *node.body << "\n";
				}
				else if constexpr (std::is_same_v<T0, ast_type_struct>) {
					os << "  Struct Declaration: " << node.name << "\n  Members:\n";
					for (const auto& member : node.members) {
						os << "    " << member.first << ": " << *member.second << "\n";
					}
				}
			}, elem);
		}
		return os;
	}

	void ast_type_pointer::print(int indent) const {
		std::cout << std::string(indent, ' ') << "[PointerType] Base Type:\n";
		base->print(indent + 1);
	}
	void ast_type_array::print(int indent) const {
		std::cout << std::string(indent, ' ') << "[ArrayType] Size: " << size << "\n";
		std::cout << std::string(indent, ' ') << "Base Type:\n";
		base->print(indent + 1);
	}
	void ast_type_function::print(int indent) const {
		std::cout << std::string(indent, ' ') << "[FunctionType] Return Type:\n";
		return_type->print(indent + 1);
		std::cout << std::string(indent, ' ') << "Parameters:\n";
		for (const auto& param : parameters) {
			param->print(indent + 1);
		}
	}
	void ast_type_struct::print(int indent) const {
		std::cout << std::string(indent, ' ') << "[StructType] Name: " << name << "\n";
		std::cout << std::string(indent, ' ') << "Members:\n";
		for (const auto& member : members) {
			std::cout << std::string(indent + 1, ' ') << member.first << ": \n";
			member.second->print(indent + 2);
		}
	}
	void ast_type_node::print(int indent) const {
		switch (type) {
			case type_t::Int:
				std::cout << std::string(indent, ' ') << "[Type] int\n";
				break;
			case type_t::Void:
				std::cout << std::string(indent, ' ') << "[Type] void\n";
				break;
			case type_t::Bool:
				std::cout << std::string(indent, ' ') << "[Type] bool\n";
				break;
			case type_t::Array:
				std::get<ast_type_array>(value).print(indent);
				break;
			case type_t::Pointer:
				std::get<ast_type_pointer>(value).print(indent);
				break;
			case type_t::Function:
				std::get<ast_type_function>(value).print(indent);
				break;
			case type_t::Struct:
				std::get<ast_type_struct>(value).print(indent);
				break;
			case type_t::Custom:
				std::cout << std::string(indent, ' ') << "[Type] Custom: " << std::get<std::string>(value) << "\n";
				break;
		}
	}

	void ast_member_access::print(int indent) const {
		std::cout << std::string(indent, ' ') << "[MemberAccess] Type: " << (pointer ? "->" : ".") << " Property: " <<
			property << "\n";
		object->print(indent + 1);
	}
	void ast_expression_ternary::print(int indent) const {
		const std::string indent_str(indent, ' ');
		std::cout << indent_str << "[TernaryExpression] Condition:\n";
		condition->print(indent + 1);
		std::cout << indent_str << "Then Branch:\n";
		then_branch->print(indent + 1);
		std::cout << indent_str << "Else Branch:\n";
		else_branch->print(indent + 1);
	}
	void ast_expression_binary::print(int indent) const {
		const std::string indent_str(indent, ' ');
		std::cout << indent_str << "[BinaryExpression] Operator: '" << type << "'\n";
		std::cout << indent_str << "Left:\n";
		left->print(indent + 1);
		std::cout << indent_str << "Right:\n";
		right->print(indent + 1);
	}
	void ast_expression_unary::print(int indent) const {
		const std::string indent_str(indent, ' ');
		std::cout << indent_str << "[UnaryExpression] Operator: '" << type << "'\n";
		std::cout << indent_str << "Operand:\n";
		operand->print(indent + 1);
	}
	void ast_expression_call::print(int indent) const {
		const std::string indent_str(indent, ' ');
		std::cout << indent_str << "[FunctionCall] Callee:\n";
		callee->print(indent + 1);
		std::cout << indent_str << "Arguments:\n";
		for (const auto& arg : arguments) {
			arg->print(indent + 1);
		}
	}
	void ast_statement_variable_declaration::print(int indent) const {
		const std::string indent_str(indent, ' ');
		std::cout << indent_str << "[VariableDeclaration] Name: " << name << "\n";
		std::cout << indent_str << "Type: \n";
		var_type->print(indent + 1);
		if (initializer) {
			std::cout << indent_str << "Initializer:\n";
			initializer->print(indent + 1);
		}
		else {
			std::cout << indent_str << "No Initializer\n";
		}
	}
	void ast_statement_function_declaration::print(int indent) const {
		const std::string indent_str(indent, ' ');
		std::cout << indent_str << "[FunctionDeclaration] Name: " << name << "\n";
		std::cout << indent_str << "Return Type:\n";
		return_type->print(indent + 1);
		std::cout << indent_str << "Parameters:\n";
		for (const auto& param : parameters) {
			std::cout << indent_str << " " << param.first << ": \n";
			param.second->print(indent + 2);
		}
		std::cout << indent_str << "Body:\n";
		body->print(indent + 1);
	}
	void ast_statement_if::print(int indent) const {
		const std::string indent_str(indent, ' ');
		std::cout << indent_str << "[IfStatement] Condition:\n";
		condition->print(indent + 1);
		std::cout << indent_str << "Then Branch:\n";
		then_branch->print(indent + 1);
		if (else_branch) {
			std::cout << indent_str << "Else Branch:\n";
			else_branch->print(indent + 1);
		}
		else {
			std::cout << indent_str << "No Else Branch\n";
		}
	}
	void ast_statement_while::print(int indent) const {
		const std::string indent_str(indent, ' ');
		std::cout << indent_str << "[WhileStatement] Condition:\n";
		condition->print(indent + 1);
		std::cout << indent_str << "Body:\n";
		body->print(indent + 1);
	}
	void ast_statement_return::print(int indent) const {
		const std::string indent_str(indent, ' ');
		std::cout << indent_str << "[ReturnStatement]";
		if (value) {
			std::cout << " Value:\n";
			value->print(indent + 1);
		}
		else {
			std::cout << " No Value\n";
		}
	}
	void ast_statement_expression::print(int indent) const {
		const std::string indent_str(indent, ' ');
		std::cout << indent_str << "[ExpressionStatement] Expression:\n";
		expression->print(indent + 1);
	}
	void ast_statement_block::print(int indent) const {
		const std::string indent_str(indent, ' ');
		std::cout << indent_str << "[BlockStatement] Statements:\n";
		for (const auto& stmt : statements) {
			stmt->print(indent + 1);
		}
	}
	void ast_node::print(int indent) const {
		switch (type) {
			case type_t::IntegerLiteral:
				std::cout << std::string(indent, ' ') << "[IntegerLiteral] Value: " << std::get<int>(value) << "\n";
				break;
			case type_t::Identifier:
				std::cout << std::string(indent, ' ') << "[Identifier] Name: " << std::get<std::string>(value) << "\n";
				break;
			case type_t::BinaryExpression:
				std::get<ast_expression_binary>(value).print(indent);
				break;
			case type_t::UnaryExpression:
				std::get<ast_expression_unary>(value).print(indent);
				break;
			case type_t::FunctionCall:
				std::get<ast_expression_call>(value).print(indent);
				break;
			case type_t::VariableDeclaration:
				std::get<ast_statement_variable_declaration>(value).print(indent);
				break;
			case type_t::FunctionDeclaration:
				std::get<ast_statement_function_declaration>(value).print(indent);
				break;
			case type_t::IfStatement:
				std::get<ast_statement_if>(value).print(indent);
				break;
			case type_t::WhileStatement:
				std::get<ast_statement_while>(value).print(indent);
				break;
			case type_t::ReturnStatement:
				std::get<ast_statement_return>(value).print(indent);
				break;
			case type_t::ExpressionStatement:
				std::get<ast_statement_expression>(value).print(indent);
				break;
			case type_t::BlockStatement:
				std::get<ast_statement_block>(value).print(indent);
				break;
			case type_t::MemberAccess:
				std::get<ast_member_access>(value).print(indent);
				break;
			case type_t::TernaryExpression:
				std::get<ast_expression_ternary>(value).print(indent);
				break;
			case type_t::Unknown:
				std::cout << std::string(indent, ' ') << "[Unknown Node]\n";
				break;
		}
	}

	void ast_program::print(int indent) const {
		const std::string indent_str(indent, ' ');
		std::cout << indent_str << "[Program] Elements:\n" << std::flush;
		for (const auto& elem : body) {
			std::visit([&indent]<typename T0>(const T0& node) {
				if constexpr (std::is_same_v<T0, ast_statement_function_declaration>) {
					node.print(indent + 1);
				}
				else if constexpr (std::is_same_v<T0, ast_type_struct>) {
					node.print(indent + 1);
				}
			}, elem);
		}
	}
} // compiler
