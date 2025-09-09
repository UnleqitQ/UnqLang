#include "assembly_parser.hpp"

#include "../parser.hpp"

namespace assembly {
	namespace lexer {
		const Parser<char, assembly_token> instruction_parser =
			tokens<char>({
				"nop"_t, "mov"_t, "push"_t, "pop"_t, "lea"_t,
				"add"_t, "sub"_t, "mul"_t, "imul"_t, "div"_t, "idiv"_t, "mod"_t, "imod"_t, "inc"_t, "dec"_t, "neg"_t, "adc"_t,
				"sbb"_t,
				"cmp"_t,
				"and"_t, "or"_t, "xor"_t, "not"_t, "shl"_t, "shr"_t, "sar"_t, "rol"_t, "ror"_t, "rcl"_t, "rcr"_t,
				"test"_t,
				"jmp"_t, "jz"_t, "je"_t, "jnz"_t, "jne"_t, "jc"_t, "jnc"_t, "jo"_t, "jno"_t, "jp"_t, "jnp"_t, "js"_t, "jns"_t,
				"jg"_t, "jl"_t, "jge"_t, "jle"_t, "ja"_t, "jae"_t, "jb"_t, "jbe"_t,
				"call"_t, "ret"_t,
				"pusba"_t, "popa"_t, "pushf"_t, "popf"_t,
				"clc"_t, "stc"_t, "hlt"_t, "end"_t,
				"in"_t, "out"_t
			}, "inst").map<assembly_token>([](const std::vector<char>& text) {
				return assembly_token{assembly_token::type::INSTRUCTION, std::string(text.begin(), text.end())};
			}, "to_token");
		const Parser<char, assembly_token> register_parser =
			tokens<char>({
				"eax"_t, "ax"_t, "ah"_t, "al"_t,
				"ebx"_t, "bx"_t, "bh"_t, "bl"_t,
				"ecx"_t, "cx"_t, "ch"_t, "cl"_t,
				"edx"_t, "dx"_t, "dh"_t, "dl"_t,
				"esi"_t, "si"_t,
				"edi"_t, "di"_t,
				"esp"_t, "sp"_t,
				"ebp"_t, "bp"_t,
			}, "reg").map<assembly_token>([](const std::vector<char>& text) {
				return assembly_token{assembly_token::type::REGISTER, std::string(text.begin(), text.end())};
			}, "to_token");
		const Parser<char, assembly_token> data_size_parser =
			tokens<char>({"dword"_t, "word"_t, "byte"_t}, "data_size").map<assembly_token>(
				[](const std::vector<char>& text) {
					return assembly_token{assembly_token::type::DATA_SIZE, std::string(text.begin(), text.end())};
				}, "to_token");
		const Parser<char, assembly_token> decimal_number_parser =
			(+satisfy<char>([](char c) { return c >= '0' && c <= '9'; }, "is_dec")).map<assembly_token>(
				[](const std::vector<char>& digits) {
					return assembly_token{assembly_token::type::NUMBER, std::string(digits.begin(), digits.end())};
				}, "to_token");
		const Parser<char, assembly_token> hex_number_parser =
		(token("0x"_t) > +satisfy<char>([](char c) {
			return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
		}, "is_hex")).map<assembly_token>([](const std::vector<char>& parts) {
			std::string text = "0x";
			text += std::string(parts.begin(), parts.end());
			return assembly_token{assembly_token::type::NUMBER, text};
		}, "to_token");
		const Parser<char, assembly_token> number_parser =
			hex_number_parser || decimal_number_parser;
		const Parser<char, assembly_token> operator_parser =
			symbols<char>({'+', '-', '*'}, "op").map<assembly_token>([](const char& c) {
				return assembly_token{assembly_token::type::OPERATOR, std::string(1, c)};
			}, "to_token");
		const Parser<char, assembly_token> left_paren_parser =
			symbol<char>('(').map<assembly_token>([](const char& c) {
				return assembly_token{assembly_token::type::LEFT_PAREN, std::string(1, c)};
			}, "to_token");
		const Parser<char, assembly_token> right_paren_parser =
			symbol<char>(')').map<assembly_token>([](const char& c) {
				return assembly_token{assembly_token::type::RIGHT_PAREN, std::string(1, c)};
			}, "to_token");
		const Parser<char, assembly_token> left_bracket_parser =
			symbol<char>('[').map<assembly_token>([](const char& c) {
				return assembly_token{assembly_token::type::LEFT_BRACKET, std::string(1, c)};
			}, "to_token");
		const Parser<char, assembly_token> right_bracket_parser =
			symbol<char>(']').map<assembly_token>([](const char& c) {
				return assembly_token{assembly_token::type::RIGHT_BRACKET, std::string(1, c)};
			}, "to_token");
		const Parser<char, assembly_token> comma_parser =
			symbol<char>(',').map<assembly_token>([](const char& c) {
				return assembly_token{assembly_token::type::COMMA, std::string(1, c)};
			}, "to_token");
		const Parser<char, assembly_token> colon_parser =
			symbol<char>(':').map<assembly_token>([](const char& c) {
				return assembly_token{assembly_token::type::COLON, std::string(1, c)};
			}, "to_token");
		const Parser<char, assembly_token> identifier_parser =
		(satisfy<char>([](char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'; }, "is_id_start") +
			*(satisfy<char>([](char c) {
				return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
			}, "is_id_part"))).map<assembly_token>(
			[](const std::pair<char, std::vector<char>>& parts) {
				std::string text;
				text += parts.first;
				text += std::string(parts.second.begin(), parts.second.end());
				return assembly_token{assembly_token::type::IDENTIFIER, text};
			}, "to_token");
		const Parser<char, assembly_token> comment_parser =
			(symbol<char>(';') > *(satisfy<char>([](char c) { return c != '\n' && c != '\r'; }, "is_not_newline"))).map<
				assembly_token>([](const std::vector<char>& chars) {
				return assembly_token{assembly_token::type::COMMENT, std::string(chars.begin(), chars.end())};
			}, "to_token");
		const Parser<char, assembly_token> space_parser =
			symbols<char>({' ', '\t'}, "space").map<assembly_token>([](const char& c) {
				return assembly_token{assembly_token::type::UNKNOWN, std::string(1, c)};
			}, "to_token");
		const Parser<char, assembly_token> newline_parser =
			(tokens<char>({"\r\n"_t, "\n"_t, "\r"_t}, "newline")).map<assembly_token>(
				[](const std::vector<char>& chars) {
					return assembly_token{assembly_token::type::NEWLINE, std::string(chars.begin(), chars.end())};
				}, "to_token");
		const Parser<char, assembly_token> end_of_file_parser =
			!succeed<char, assembly_token>(assembly_token{assembly_token::type::END_OF_FILE, ""});

		const Parser<char, assembly_token> assembly_token_parser =
		(instruction_parser || register_parser || data_size_parser || number_parser || operator_parser || left_paren_parser
			||
			right_paren_parser || left_bracket_parser || right_bracket_parser || comma_parser || colon_parser ||
			identifier_parser || comment_parser || space_parser || newline_parser);
		const Parser<char, std::vector<assembly_token>> assembly_tokenization_parser =
		((*(space_parser || newline_parser)) > (+(assembly_token_parser < (*space_parser)) < *(space_parser ||
			newline_parser))).map<std::vector<assembly_token>>(
			[](const std::vector<assembly_token>& p) {
				return p;
			}, "collect_tokens");
	} // namespace lexer

	std::vector<assembly_token> run_lexer(const std::string& input) {
		std::vector<char> chars(input.begin(), input.end());
		ParserTable empty_table;
		auto result = lexer::assembly_tokenization_parser.parse(chars, empty_table);
		if (!result.empty()) {
			if (result.size() > 1) {
				std::cerr << "Warning: Multiple parse results, using the first one." << std::endl;
			}
			return result[0].first;
		}
		return {};
	}
	void remove_comments(std::vector<assembly_token>& tokens) {
		std::erase_if(tokens, [](const assembly_token& tok) {
			return tok.token_type == assembly_token::type::COMMENT;
		});
	}
	void join_newlines(const std::vector<assembly_token>& tokens, std::vector<assembly_token>& result) {
		bool last_was_newline = false;
		for (const auto& tok : tokens) {
			if (tok.token_type == assembly_token::type::NEWLINE) {
				if (!last_was_newline) {
					result.push_back(tok);
					last_was_newline = true;
				}
			}
			else {
				result.push_back(tok);
				last_was_newline = false;
			}
		}
	}

	namespace component_parser {
		Parser<assembly_token, assembly_token> is_token_type(assembly_token::type type) {
			auto type_parse_func = [type](const std::vector<assembly_token>& input,
				std::vector<std::pair<assembly_token, size_t>>& output, ParserTable&) {
				if (!input.empty() && input[0].token_type == type) {
					output.emplace_back(input[0], 1);
				}
			};
			std::string type_name;
			switch (type) {
				case assembly_token::type::INSTRUCTION:
					type_name = "INSTRUCTION";
					break;
				case assembly_token::type::REGISTER:
					type_name = "REGISTER";
					break;
				case assembly_token::type::DATA_SIZE:
					type_name = "DATA_SIZE";
					break;
				case assembly_token::type::NUMBER:
					type_name = "NUMBER";
					break;
				case assembly_token::type::OPERATOR:
					type_name = "OPERATOR";
					break;
				case assembly_token::type::LEFT_PAREN:
					type_name = "LEFT_PAREN";
					break;
				case assembly_token::type::RIGHT_PAREN:
					type_name = "RIGHT_PAREN";
					break;
				case assembly_token::type::LEFT_BRACKET:
					type_name = "LEFT_BRACKET";
					break;
				case assembly_token::type::RIGHT_BRACKET:
					type_name = "RIGHT_BRACKET";
					break;
				case assembly_token::type::COMMA:
					type_name = "COMMA";
					break;
				case assembly_token::type::COLON:
					type_name = "COLON";
					break;
				case assembly_token::type::IDENTIFIER:
					type_name = "IDENTIFIER";
					break;
				case assembly_token::type::NEWLINE:
					type_name = "NEWLINE";
					break;
				case assembly_token::type::COMMENT:
					type_name = "COMMENT";
					break;
				case assembly_token::type::END_OF_FILE:
					type_name = "END_OF_FILE";
					break;
				case assembly_token::type::UNKNOWN:
					type_name = "UNKNOWN";
					break;
			}
			return Parser<assembly_token, assembly_token>(type_parse_func, std::format("(is_token_type {})", type_name));
		};
		const Parser<assembly_token, assembly_parse_component> instruction_parser =
			is_token_type(assembly_token::type::INSTRUCTION).map<assembly_parse_component>([](const assembly_token& tok) {
				return assembly_parse_component{machine::operation_from_string(tok.text)};
			}, "to_component");
		const Parser<assembly_token, assembly_parse_component> register_parser =
			is_token_type(assembly_token::type::REGISTER).map<assembly_parse_component>([](const assembly_token& tok) {
				return assembly_parse_component{machine::register_t::from_string(tok.text)};
			}, "to_component");
		const Parser<assembly_token, assembly_parse_component> data_size_parser =
			is_token_type(assembly_token::type::DATA_SIZE).map<assembly_parse_component>([](const assembly_token& tok) {
				return assembly_parse_component{machine::data_size_from_string(tok.text)};
			}, "to_component");
		const Parser<assembly_token, assembly_parse_component> number_literal_parser =

			(is_token_type(assembly_token::type::OPERATOR).filter([](assembly_token tok) {
				return tok.text == "-" || tok.text == "+";
			}) + is_token_type(assembly_token::type::NUMBER)).map<assembly_parse_component>(
				[](const std::pair<assembly_token, assembly_token>& parts) {
					assembly_token sign_token = parts.first;
					assembly_token number_token = parts.second;
					int32_t value = 0;
					if (number_token.text.size() > 2 && number_token.text[0] == '0' && (number_token.text[1] == 'x' ||
						number_token.text[1] == 'X')) {
						value = std::stoi(number_token.text, nullptr, 16);
					}
					else {
						value = std::stoi(number_token.text, nullptr, 10);
					}
					if (sign_token.text == "-") {
						value = -value;
					}
					return assembly_parse_component{assembly_literal(value)};
				}, "to_component") ||
			is_token_type(assembly_token::type::NUMBER).map<assembly_parse_component>([](const assembly_token& tok) {
				int32_t value = 0;
				if (tok.text.size() > 2 && tok.text[0] == '0' && (tok.text[1] == 'x' || tok.text[1] == 'X')) {
					value = std::stoi(tok.text, nullptr, 16);
				}
				else {
					value = std::stoi(tok.text, nullptr, 10);
				}
				return assembly_parse_component{assembly_literal(value)};
			}, "to_component");
		const Parser<assembly_token, assembly_parse_component> label_parser =
			(is_token_type(assembly_token::type::IDENTIFIER) < is_token_type(assembly_token::type::COLON)).map<
				assembly_parse_component>(
				[](const assembly_token& tok) {
					return assembly_parse_component{tok.text};
				}, "to_component");
		const Parser<assembly_token, assembly_parse_component> label_literal_parser =
			is_token_type(assembly_token::type::IDENTIFIER).map<assembly_parse_component>([](const assembly_token& tok) {
				return assembly_parse_component{assembly_literal(tok.text)};
			}, "to_component");
		const Parser<assembly_token, assembly_parse_component> literal_parser =
			number_literal_parser || label_literal_parser;
		const Parser<assembly_token, assembly_parse_component> label_definition_parser =
			(is_token_type(assembly_token::type::IDENTIFIER) < is_token_type(assembly_token::type::COLON)).map<
				assembly_parse_component>(
				[](const assembly_token& tok) {
					return assembly_parse_component{tok.text};
				}, "to_component");
		const Parser<assembly_token, assembly_memory> direct_memory_parser =
			literal_parser.map<assembly_memory>([](const assembly_parse_component& comp) {
				return assembly_memory(std::get<assembly_literal>(comp.value));
			}, "to_memory");
		const Parser<assembly_token, assembly_memory> register_memory_parser =
			register_parser.map<assembly_memory>([](const assembly_parse_component& comp) {
				return assembly_memory(std::get<machine::register_t>(comp.value));
			}, "to_memory");
		const Parser<assembly_token, assembly_memory> displacement_memory_parser =
		(register_parser + is_token_type(assembly_token::type::OPERATOR).filter(
			[](assembly_token tok) { return tok.text == "+" || tok.text == "-"; }) + literal_parser).filter(
			[](const std::pair<std::pair<assembly_parse_component, assembly_token>, assembly_parse_component>& p) {
				// Disallow negative displacement for labels
				return !(p.first.second.text == "-" && std::get<assembly_literal>(p.second.value).literal_type
					==
					assembly_literal::type::LABEL);
			}).map<assembly_memory>(
			[](const std::pair<std::pair<assembly_parse_component, assembly_token>, assembly_parse_component>& parts) {
				assembly_parse_component base_comp = parts.first.first;
				assembly_token sign_token = parts.first.second;
				assembly_parse_component disp_comp = parts.second;
				assembly_literal disp_lit = std::get<assembly_literal>(disp_comp.value);
				if (sign_token.text == "-") {
					if (disp_lit.literal_type == assembly_literal::type::NUMBER) {
						disp_lit.value = -std::get<int32_t>(disp_lit.value);
					}
					else {
						throw std::invalid_argument("Negative displacement for labels is not allowed");
					}
				}
				return assembly_memory(std::get<machine::register_t>(base_comp.value), disp_lit);
			}, "to_memory");
		const Parser<assembly_token, assembly_memory> scaled_index_memory_parser =
			(register_parser
				+ is_token_type(assembly_token::type::OPERATOR).filter(
					[](assembly_token tok) { return tok.text == "+" || tok.text == "-"; })
				+ register_parser
				+ is_token_type(assembly_token::type::OPERATOR).filter(
					[](assembly_token tok) { return tok.text == "*"; })
				+ number_literal_parser)
			.map<std::tuple<assembly_parse_component, assembly_token, assembly_parse_component, assembly_token,
				assembly_parse_component>>(
				[](const auto& p) {
					return std::make_tuple(p.first.first.first.first, p.first.first.first.second, p.first.first.second,
						p.first.second, p.second);
				})
			.map<assembly_memory>(
				[](const std::tuple<assembly_parse_component, assembly_token, assembly_parse_component, assembly_token,
				assembly_parse_component>& parts) {
					assembly_parse_component base_comp = std::get<0>(parts);
					assembly_token sign_token = std::get<1>(parts);
					assembly_parse_component index_comp = std::get<2>(parts);
					assembly_token mul_token = std::get<3>(parts);
					assembly_parse_component scale_comp = std::get<4>(parts);
					int8_t scale = static_cast<int8_t>(std::get<int32_t>(std::get<assembly_literal>(
						scale_comp.value).value));
					if (sign_token.text == "-") {
						scale = -scale;
					}
					return assembly_memory(std::get<machine::register_t>(base_comp.value),
						std::get<machine::register_t>(index_comp.value), scale);
				}, "to_memory");
		const Parser<assembly_token, assembly_memory> scaled_index_displacement_memory_parser =
		(scaled_index_memory_parser +
			(is_token_type(assembly_token::type::OPERATOR).filter(
					[](assembly_token tok) { return tok.text == "+" || tok.text == "-"; })
				+ literal_parser).filter(
				[](const std::pair<assembly_token, assembly_parse_component>& p) {
					// Disallow negative displacement for labels
					return !(p.first.text == "-" && std::get<assembly_literal>(p.second.value).literal_type ==
						assembly_literal::type::LABEL);
				})).map<assembly_memory>(
			[](const std::pair<assembly_memory, std::pair<assembly_token, assembly_parse_component>>& parts) {
				assembly_memory base_mem = parts.first;
				assembly_token sign_token = parts.second.first;
				assembly_parse_component disp_comp = parts.second.second;
				assembly_literal disp_lit = std::get<assembly_literal>(
					disp_comp.value);
				if (sign_token.text == "-" && disp_lit.literal_type == assembly_literal::type::NUMBER) {
					disp_lit.value = -std::get<int32_t>(disp_lit.value);
				}
				const assembly_memory::scaled_index& si = std::get<assembly_memory::scaled_index>(
					base_mem.value);
				return assembly_memory(si.base, si.index, si.scale, disp_lit);
			}, "to_memory");
		const Parser<assembly_token, assembly_parse_component> memory_parser =
		(is_token_type(assembly_token::type::LEFT_BRACKET) >
			(scaled_index_displacement_memory_parser || scaled_index_memory_parser || displacement_memory_parser ||
				register_memory_parser || direct_memory_parser) <
			is_token_type(assembly_token::type::RIGHT_BRACKET)).map<assembly_parse_component>(
			[](const assembly_memory& mem) {
				return assembly_parse_component{mem};
			}, "to_component");
		const Parser<assembly_token, assembly_parse_component> newline_parser =
			(+is_token_type(assembly_token::type::NEWLINE)).map<assembly_parse_component>([](const auto& /*nls*/) {
				return assembly_parse_component{assembly_parse_component::type::NEWLINE};
			}, "to_component");
		const Parser<assembly_token, assembly_parse_component> end_of_file_parser =
			!is_token_type(assembly_token::type::END_OF_FILE).map<assembly_parse_component>(
				[](const auto& /*c*/) {
					return assembly_parse_component{assembly_parse_component::type::END_OF_FILE};
				}, "to_component");
		const Parser<assembly_token, assembly_parse_component> comma_parser =
			is_token_type(assembly_token::type::COMMA).map<assembly_parse_component>([](const auto& /*c*/) {
				return assembly_parse_component{assembly_parse_component::type::COMMA};
			}, "to_component");
		const Parser<assembly_token, assembly_parse_component> assembly_component_parser =
		(instruction_parser || register_parser || data_size_parser || label_parser || literal_parser ||
			label_definition_parser
			|| memory_parser || newline_parser || end_of_file_parser || comma_parser);
		const Parser<assembly_token, std::vector<assembly_parse_component>> component_list_parser =
			+assembly_component_parser;
	} // namespace component_parser

	std::vector<assembly_parse_component> run_component_parser(const std::vector<assembly_token>& tokens) {
		ParserTable empty_table;
		auto result = component_parser::component_list_parser.parse(tokens, empty_table);
		if (!result.empty()) {
			if (result.size() > 1) {
				std::cerr << "Warning: Multiple parse results, using the first one." << std::endl;
			}
			return result[0].first;
		}
		return {};
	}

	namespace parser {
		Parser<assembly_parse_component, assembly_parse_component> is_component_type(assembly_parse_component::type type) {
			auto type_parse_func = [type](const std::vector<assembly_parse_component>& input,
				std::vector<std::pair<assembly_parse_component, size_t>>& output, ParserTable&) {
				if (!input.empty() && input[0].component_type == type) {
					output.emplace_back(input[0], 1);
				}
			};
			std::string type_name;
			switch (type) {
				case assembly_parse_component::type::INSTRUCTION:
					type_name = "INSTRUCTION";
					break;
				case assembly_parse_component::type::REGISTER:
					type_name = "REGISTER";
					break;
				case assembly_parse_component::type::DATA_SIZE:
					type_name = "DATA_SIZE";
					break;
				case assembly_parse_component::type::LITERAL:
					type_name = "LITERAL";
					break;
				case assembly_parse_component::type::LABEL:
					type_name = "LABEL";
					break;
				case assembly_parse_component::type::MEMORY:
					type_name = "MEMORY";
					break;
				case assembly_parse_component::type::NEWLINE:
					type_name = "NEWLINE";
					break;
				case assembly_parse_component::type::END_OF_FILE:
					type_name = "END_OF_FILE";
					break;
				case assembly_parse_component::type::UNKNOWN:
					type_name = "UNKNOWN";
					break;
				case assembly_parse_component::type::COMMA:
					type_name = "COMMA";
					break;
				default:
					type_name = "INVALID";
					break;
			}
			return Parser<assembly_parse_component, assembly_parse_component>(type_parse_func,
				std::format("(is_component_type {})", type_name));
		};
		const Parser<assembly_parse_component, assembly_operand> operand_parser =
			is_component_type(assembly_parse_component::type::REGISTER).map<assembly_operand>(
				[](const assembly_parse_component& comp) {
					return assembly_operand{std::get<machine::register_t>(comp.value)};
				}, "to_operand") ||
			is_component_type(assembly_parse_component::type::LITERAL).map<assembly_operand>(
				[](const assembly_parse_component& comp) {
					return assembly_operand{std::get<assembly_literal>(comp.value)};
				}, "to_operand") ||
			is_component_type(assembly_parse_component::type::MEMORY).map<assembly_operand>(
				[](const assembly_parse_component& comp) {
					return assembly_operand{std::get<assembly_memory>(comp.value)};
				}, "to_operand");
		const Parser<assembly_parse_component, assembly_result> result_parser =
			is_component_type(assembly_parse_component::type::REGISTER).map<assembly_result>(
				[](const assembly_parse_component& comp) {
					return assembly_result{std::get<machine::register_t>(comp.value)};
				}, "to_result") ||
			is_component_type(assembly_parse_component::type::MEMORY).map<assembly_result>(
				[](const assembly_parse_component& comp) {
					return assembly_result{
						std::get<assembly_memory>(comp.value)
					};
				}, "to_result");


		// Parsers for different argument patterns (0-2 operands, with/without result)

		const Parser<assembly_parse_component, assembly_instruction::args_t<0, false>> args_0n_parser =
			succeed<assembly_parse_component, assembly_instruction::args_t<0, false>>(
				assembly_instruction::args_t<0, false>{});

		const Parser<assembly_parse_component, assembly_instruction::args_t<0, true>> args_0r_parser =
			((~is_component_type(assembly_parse_component::type::DATA_SIZE)) + result_parser).map<
				assembly_instruction::args_t<0, true>>(
				[](const std::pair<std::optional<assembly_parse_component>, assembly_result>& parts) {
					if (parts.second.result_type == assembly_result::type::MEMORY) {
						if (!parts.first.has_value()) {
							throw std::invalid_argument("Memory data size not specified and cannot be inferred");
						}
						machine::data_size_t ds = std::get<machine::data_size_t>(parts.first->value);
						return assembly_instruction::args_t<0, true>{
							{}, assembly_result{
								std::get<assembly_memory>(parts.second.value).with_size(ds)
							}
						};
					}
					return assembly_instruction::args_t<0, true>{{}, parts.second};
				}, "to_args");

		const Parser<assembly_parse_component, assembly_instruction::args_t<1, false>> args_1n_parser =
			((~is_component_type(assembly_parse_component::type::DATA_SIZE)) + operand_parser).map<
				assembly_instruction::args_t<1, false>>(
				[](const std::pair<std::optional<assembly_parse_component>, assembly_operand>& parts) {
					if (parts.second.operand_type == assembly_operand::type::MEMORY) {
						if (!parts.first.has_value()) {
							throw std::invalid_argument("Memory data size not specified and cannot be inferred");
						}
						machine::data_size_t ds = std::get<machine::data_size_t>(parts.first->value);
						return assembly_instruction::args_t<1, false>{
							{assembly_operand{std::get<assembly_memory>(parts.second.value).with_size(ds)}}
						};
					}
					return assembly_instruction::args_t<1, false>{{parts.second}};
				}, "to_args");

		machine::data_size_t infer_size_from_register(const machine::register_t& reg) {
			switch (reg.access) {
				case machine::register_access::dword:
					return machine::data_size_t::DWORD;
				case machine::register_access::word:
					return machine::data_size_t::WORD;
				case machine::register_access::high_byte:
				case machine::register_access::low_byte:
					return machine::data_size_t::BYTE;
				default:
					throw std::invalid_argument("Unknown register size");
			}
		}
		machine::data_size_t max_data_size(machine::data_size_t a, machine::data_size_t b) {
			if (a == machine::data_size_t::DWORD || b == machine::data_size_t::DWORD) {
				return machine::data_size_t::DWORD;
			}
			if (a == machine::data_size_t::WORD || b == machine::data_size_t::WORD) {
				return machine::data_size_t::WORD;
			}
			return machine::data_size_t::BYTE;
		}

		assembly_instruction::args_t<1, true> parse_args_1r(std::optional<machine::data_size_t> ds, assembly_result result,
			assembly_operand operand) {
			if (result.result_type == assembly_result::type::MEMORY) {
				if (ds.has_value()) {
					result = assembly_result{std::get<assembly_memory>(result.value).with_size(ds.value())};
				}
				else {
					// Infer size from operand if it's a register
					if (operand.operand_type == assembly_operand::type::MEMORY ||
						operand.operand_type == assembly_operand::type::LITERAL) {
						throw std::invalid_argument(
							"Memory data size not specified and cannot be inferred");
					}
					machine::data_size_t inferred_size = infer_size_from_register(std::get<machine::register_t>(operand.value));
					result = assembly_result{std::get<assembly_memory>(result.value).with_size(inferred_size)};
				}
			}
			if (operand.operand_type == assembly_operand::type::MEMORY) {
				if (ds.has_value()) {
					operand = assembly_operand{std::get<assembly_memory>(operand.value).with_size(ds.value())};
				}
				else {
					// Infer size from result, which definitely is a register
					machine::data_size_t inferred_size = infer_size_from_register(std::get<machine::register_t>(result.value));
					operand = assembly_operand{std::get<assembly_memory>(operand.value).with_size(inferred_size)};
				}
			}
			return assembly_instruction::args_t<1, true>{{operand}, result};
		}
		const Parser<assembly_parse_component, assembly_instruction::args_t<1, true>> args_1r_parser =
		((~is_component_type(assembly_parse_component::type::DATA_SIZE)) + result_parser + (is_component_type(
				assembly_parse_component::type::COMMA)
			> operand_parser)).map<assembly_instruction::args_t<1, true>>(
			[](const std::pair<std::pair<std::optional<assembly_parse_component>, assembly_result>, assembly_operand>&
			parts) {
				auto dsc = parts.first.first;
				std::optional<machine::data_size_t> ds = std::nullopt;
				if (dsc.has_value()) {
					ds = std::get<machine::data_size_t>(dsc->value);
				}
				return parse_args_1r(ds, parts.first.second, parts.second);
			});

		assembly_instruction::args_t<2, false> parse_args_2n(std::optional<machine::data_size_t> ds,
			assembly_operand op1, assembly_operand op2) {
			if (op1.operand_type == assembly_operand::type::MEMORY) {
				if (ds.has_value()) {
					op1 = assembly_operand{std::get<assembly_memory>(op1.value).with_size(ds.value())};
				}
				else {
					// Infer size from op2 if it's a register
					if (op2.operand_type == assembly_operand::type::MEMORY ||
						op2.operand_type == assembly_operand::type::LITERAL) {
						throw std::invalid_argument(
							"Memory data size not specified and cannot be inferred");
					}
					machine::data_size_t inferred_size = infer_size_from_register(std::get<machine::register_t>(op2.value));
					op1 = assembly_operand{std::get<assembly_memory>(op1.value).with_size(inferred_size)};
				}
			}
			if (op2.operand_type == assembly_operand::type::MEMORY) {
				if (ds.has_value()) {
					op2 = assembly_operand{std::get<assembly_memory>(op2.value).with_size(ds.value())};
				}
				else {
					// Infer size from op1 if it's a register
					if (op1.operand_type == assembly_operand::type::MEMORY ||
						op1.operand_type == assembly_operand::type::LITERAL) {
						throw std::invalid_argument(
							"Memory data size not specified and cannot be inferred");
					}
					machine::data_size_t inferred_size = infer_size_from_register(std::get<machine::register_t>(op1.value));
					op2 = assembly_operand{std::get<assembly_memory>(op2.value).with_size(inferred_size)};
				}
			}
			return assembly_instruction::args_t<2, false>{{op1, op2}};
		}
		const Parser<assembly_parse_component, assembly_instruction::args_t<2, false>> args_2n_parser =
		((~is_component_type(assembly_parse_component::type::DATA_SIZE)) + operand_parser + (is_component_type(
				assembly_parse_component::type::COMMA)
			> operand_parser)).map<assembly_instruction::args_t<2, false>>(
			[](const auto& parts) {
				auto dsc = parts.first.first;
				std::optional<machine::data_size_t> ds = std::nullopt;
				if (dsc.has_value()) {
					ds = std::get<machine::data_size_t>(dsc->value);
				}
				return parse_args_2n(ds, parts.first.second, parts.second);
			}, "to_args");

		const std::vector<machine::operation> operations_0n = {
			machine::operation::NOP,
			machine::operation::RET,
			machine::operation::HLT,
			machine::operation::CLC,
			machine::operation::STC,
			machine::operation::PUSHF,
			machine::operation::POPF,
			machine::operation::PUSHA,
			machine::operation::POPA
		};
		const std::vector<machine::operation> operations_0r = {
			machine::operation::POP,
			machine::operation::INC,
			machine::operation::DEC,
			machine::operation::IN,
			machine::operation::NEG,
			machine::operation::NOT
		};
		const std::vector<machine::operation> operations_1n = {
			machine::operation::JMP,
			machine::operation::JZ,
			machine::operation::JNZ,
			machine::operation::JC,
			machine::operation::JNC,
			machine::operation::JO,
			machine::operation::JNO,
			machine::operation::JS,
			machine::operation::JNS,
			machine::operation::JP,
			machine::operation::JNP,
			machine::operation::JG,
			machine::operation::JGE,
			machine::operation::JL,
			machine::operation::JLE,
			machine::operation::JA,
			machine::operation::JAE,
			machine::operation::JB,
			machine::operation::JBE,
			machine::operation::CALL,
			machine::operation::PUSH,
			machine::operation::OUT,
		};
		const std::vector<machine::operation> operations_1r = {
			machine::operation::MOV,
			machine::operation::LEA,
			machine::operation::ADD,
			machine::operation::SUB,
			machine::operation::MUL,
			machine::operation::IMUL,
			machine::operation::DIV,
			machine::operation::IDIV,
			machine::operation::MOD,
			machine::operation::IMOD,
			machine::operation::ADC,
			machine::operation::SBB,
			machine::operation::AND,
			machine::operation::OR,
			machine::operation::XOR,
			machine::operation::SHL,
			machine::operation::SHR,
			machine::operation::SAR,
			machine::operation::ROL,
			machine::operation::ROR,
			machine::operation::RCL,
			machine::operation::RCR,
		};
		const std::vector<machine::operation> operations_2n = {
			machine::operation::CMP,
			machine::operation::TEST,
		};
		Parser<assembly_parse_component, assembly_parse_component> is_instruction_of_type(
			const std::vector<machine::operation>& ops) {
			auto instr_parse_func = [ops](const std::vector<assembly_parse_component>& input,
				std::vector<std::pair<assembly_parse_component, size_t>>& output, ParserTable&) {
				if (!input.empty() && input[0].component_type == assembly_parse_component::type::INSTRUCTION) {
					machine::operation op = std::get<machine::operation>(input[0].value);
					if (std::find(ops.begin(), ops.end(), op) != ops.end()) {
						output.emplace_back(input[0], 1);
					}
				}
			};
			std::string ops_list;
			return Parser<assembly_parse_component, assembly_parse_component>(instr_parse_func,
				"(is_instruction_of_type [...])");
		};
		const Parser<assembly_parse_component, assembly_instruction> instruction_parser =
		((is_instruction_of_type(operations_0n) + args_0n_parser).map<assembly_instruction>(
				[](const std::pair<assembly_parse_component, assembly_instruction::args_t<0, false>>& parts) {
					return assembly_instruction{std::get<machine::operation>(parts.first.value), parts.second};
				}, "to_instruction")
			|| (is_instruction_of_type(operations_0r) + args_0r_parser).map<assembly_instruction>(
				[](const std::pair<assembly_parse_component, assembly_instruction::args_t<0, true>>& parts) {
					return assembly_instruction{std::get<machine::operation>(parts.first.value), parts.second};
				}, "to_instruction")
			|| (is_instruction_of_type(operations_1n) + args_1n_parser).map<assembly_instruction>(
				[](const std::pair<assembly_parse_component, assembly_instruction::args_t<1, false>>& parts) {
					return assembly_instruction{std::get<machine::operation>(parts.first.value), parts.second};
				}, "to_instruction")
			|| (is_instruction_of_type(operations_1r) + args_1r_parser).map<assembly_instruction>(
				[](const std::pair<assembly_parse_component, assembly_instruction::args_t<1, true>>& parts) {
					if (std::get<machine::operation>(parts.first.value) == machine::operation::LEA) {
						// LEA requires the operand to be memory
						if (parts.second.operands[0].operand_type != assembly_operand::type::MEMORY) {
							throw std::invalid_argument("LEA instruction requires a memory operand");
						}
					}
					return assembly_instruction{std::get<machine::operation>(parts.first.value), parts.second};
				}, "to_instruction")
			|| (is_instruction_of_type(operations_2n) + args_2n_parser).map<assembly_instruction>(
				[](const std::pair<assembly_parse_component, assembly_instruction::args_t<2, false>>& parts) {
					return assembly_instruction{std::get<machine::operation>(parts.first.value), parts.second};
				}, "to_instruction"));
		Parser<assembly_parse_component, std::string> label_parser =
			is_component_type(assembly_parse_component::type::LABEL).map<std::string>(
				[](const assembly_parse_component& comp) {
					return std::get<std::string>(comp.value);
				}, "to_label");
		Parser<assembly_parse_component, assembly_parse_component> newline_parser = is_component_type(
			assembly_parse_component::type::NEWLINE);
		const Parser<assembly_parse_component, assembly_component> instruction_or_label_parser =
		(instruction_parser.map<assembly_component>([](const assembly_instruction& instr) {
				return assembly_component{instr};
			}, "to_component")
			|| label_parser.map<assembly_component>([](const std::string& label) {
				return assembly_component{label};
			}, "to_component"));
		const Parser<assembly_parse_component, std::vector<assembly_component>> instructions_parser =
			(*newline_parser > instruction_or_label_parser + *(newline_parser > instruction_or_label_parser) < *
				newline_parser)
			.map<std::vector<assembly_component>>(
				[](const std::pair<assembly_component, std::vector<assembly_component>>& parts) {
					std::vector<assembly_component> result;
					result.reserve(1 + parts.second.size());
					result.push_back(parts.first);
					result.insert(result.end(), parts.second.begin(), parts.second.end());
					return result;
				}, "to_instructions");
	}

	assembly_program_t run_parser(const std::vector<assembly_parse_component>& components) {
		ParserTable empty_table;
		auto result = parser::instructions_parser.parse(components, empty_table);
		if (!result.empty()) {
			if (result.size() > 1) {
				std::cerr << "Warning: Multiple parse results, using the first one." << std::endl;
			}
			std::vector<assembly_component> parsed_components;
			for (const auto& instr : result[0].first) {
				parsed_components.push_back(instr);
			}
			return parsed_components;
		}
		return {};
	}

	std::ostream& operator<<(std::ostream& os, const assembly_token& tok) {
		switch (tok.token_type) {
			case assembly_token::type::INSTRUCTION:
				os << "INSTRUCTION(" << tok.text << ")";
				break;
			case assembly_token::type::REGISTER:
				os << "REGISTER(" << tok.text << ")";
				break;
			case assembly_token::type::DATA_SIZE:
				os << "DATA_SIZE(" << tok.text << ")";
				break;
			case assembly_token::type::NUMBER:
				os << "NUMBER(" << tok.text << ")";
				break;
			case assembly_token::type::OPERATOR:
				os << "OPERATOR(" << tok.text << ")";
				break;
			case assembly_token::type::LEFT_PAREN:
				os << "LEFT_PAREN(" << tok.text << ")";
				break;
			case assembly_token::type::RIGHT_PAREN:
				os << "RIGHT_PAREN(" << tok.text << ")";
				break;
			case assembly_token::type::LEFT_BRACKET:
				os << "LEFT_BRACKET(" << tok.text << ")";
				break;
			case assembly_token::type::RIGHT_BRACKET:
				os << "RIGHT_BRACKET(" << tok.text << ")";
				break;
			case assembly_token::type::COMMA:
				os << "COMMA(" << tok.text << ")";
				break;
			case assembly_token::type::COLON:
				os << "COLON(" << tok.text << ")";
				break;
			case assembly_token::type::IDENTIFIER:
				os << "IDENTIFIER(" << tok.text << ")";
				break;
			case assembly_token::type::NEWLINE:
				os << "NEWLINE";
				break;
			case assembly_token::type::COMMENT:
				os << "COMMENT(" << tok.text << ")";
				break;
			case assembly_token::type::END_OF_FILE:
				os << "END_OF_FILE";
				break;
			case assembly_token::type::UNKNOWN:
				os << "UNKNOWN(" << tok.text << ")";
				break;
			default: break;
		}
		return os;
	}
	std::string assembly_parse_component::to_string() const {
		switch (component_type) {
			case type::INSTRUCTION:
				return std::format("INSTRUCTION({})", machine::operation_to_string(std::get<machine::operation>(value)));
			case type::REGISTER:
				return std::format("REGISTER({})", std::get<machine::register_t>(value).to_string());
			case type::DATA_SIZE:
				return std::format("DATA_SIZE({})", static_cast<int>(std::get<machine::data_size_t>(value)));
			case type::LITERAL:
				return std::format("LITERAL({})", std::get<assembly_literal>(value).to_string());
			case type::LABEL:
				return std::format("LABEL({})", std::get<std::string>(value));
			case type::MEMORY:
				return std::format("MEMORY({})", std::get<assembly_memory>(value).to_string());
			case type::NEWLINE:
				return "NEWLINE";
			case type::END_OF_FILE:
				return "END_OF_FILE";
			case type::COMMA:
				return "COMMA";
			case type::UNKNOWN:
				return "UNKNOWN";
			default: break;
		}
		return "";
	}
	std::ostream& operator<<(std::ostream& os, const assembly_parse_component& comp) {
		switch (comp.component_type) {
			case assembly_parse_component::type::INSTRUCTION:
				os << "INSTRUCTION(" << std::get<machine::operation>(comp.value) << ")";
				break;
			case assembly_parse_component::type::REGISTER:
				os << "REGISTER(" << std::get<machine::register_t>(comp.value).to_string() << ")";
				break;
			case assembly_parse_component::type::DATA_SIZE:
				os << "DATA_SIZE(" << static_cast<int>(std::get<machine::data_size_t>(comp.value)) << ")";
				break;
			case assembly_parse_component::type::LITERAL: {
				const assembly_literal& lit = std::get<assembly_literal>(comp.value);
				switch (lit.literal_type) {
					case assembly_literal::type::NUMBER:
						os << "LITERAL(NUMBER, " << std::get<int32_t>(lit.value) << ")";
						break;
					case assembly_literal::type::LABEL:
						os << "LITERAL(LABEL, " << std::get<std::string>(lit.value) << ")";
						break;
				}
				break;
			}
			case assembly_parse_component::type::LABEL:
				os << "LABEL(" << std::get<std::string>(comp.value) << ")";
				break;
			case assembly_parse_component::type::MEMORY: {
				const assembly_memory& mem = std::get<assembly_memory>(comp.value);
				switch (mem.memory_type) {
					case assembly_memory::type::DIRECT: {
						const assembly_literal& lit = std::get<assembly_literal>(mem.value);
						switch (lit.literal_type) {
							case assembly_literal::type::NUMBER:
								os << "MEMORY(DIRECT, NUMBER, " << std::get<int32_t>(lit.value) << ")";
								break;
							case assembly_literal::type::LABEL:
								os << "MEMORY(DIRECT, LABEL, " << std::get<std::string>(lit.value) << ")";
								break;
						}
						break;
					}
					case assembly_memory::type::REGISTER:
						os << "MEMORY(REGISTER, " << std::get<machine::register_t>(mem.value).machine::register_t::to_string() <<
							")";
						break;
					case assembly_memory::type::DISPLACEMENT: {
						const assembly_memory::displacement& disp = std::get<
							assembly_memory::displacement>(mem.value);
						os << "MEMORY(DISPLACEMENT, BASE=" << disp.reg.to_string() << ", DISP=";
						switch (disp.disp.literal_type) {
							case assembly_literal::type::NUMBER:
								os << "NUMBER, " << std::get<int32_t>(disp.disp.value);
								break;
							case assembly_literal::type::LABEL:
								os << "LABEL, " << std::get<std::string>(disp.disp.value);
								break;
						}
						os << ")";
						break;
					}
					case assembly_memory::type::SCALED_INDEX: {
						const assembly_memory::scaled_index& si = std::get<
							assembly_memory::scaled_index>(mem.value);
						os << "MEMORY(SCALED_INDEX, BASE=" << si.base.to_string() << ", INDEX=" << si.index.to_string() <<
							", SCALE=" << static_cast<int>(si.scale) << ")";
						break;
					}
					case assembly_memory::type::SCALED_INDEX_DISPLACEMENT: {
						const assembly_memory::scaled_index_displacement& sid = std::get<
							assembly_memory::scaled_index_displacement>(mem.value);
						os << "MEMORY(SCALED_INDEX_DISPLACEMENT, BASE=" << sid.base.to_string() << ", INDEX=" << sid.index.
							to_string() << ", SCALE=" << static_cast<int>(sid.scale) << ", DISP=";
						switch (sid.disp.literal_type) {
							case assembly_literal::type::NUMBER:
								os << "NUMBER, " << std::get<int32_t>(sid.disp.value);
								break;
							case assembly_literal::type::LABEL:
								os << "LABEL, " << std::get<std::string>(sid.disp.value);
								break;
						}
						os << ")";
						break;
					}
				}
				break;
			}
			case assembly_parse_component::type::NEWLINE:
				os << "NEWLINE";
				break;
			case assembly_parse_component::type::END_OF_FILE:
				os << "END_OF_FILE";
				break;
			case assembly_parse_component::type::COMMA:
				os << "COMMA";
				break;
			case assembly_parse_component::type::UNKNOWN:
				os << "UNKNOWN";
				break;
			default:
				os << "INVALID_COMPONENT";
				break;
		}
		return os;
	}
} // assembly
