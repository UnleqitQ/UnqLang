#pragma once
#include <algorithm>
#include <complex.h>
#include <functional>
#include <optional>
#include <vector>
#include <string>
#include <sstream>
#include <format>
#include <type_traits>

#include "parser.hpp"
#include "compiler/ast.hpp"

#define PRINT_CONTENT(input) for (const auto& c : input) { if constexpr (std::is_same_v<T, char>) { if (c == '\n') {std::cout << "[\\n]";}else if (c == '\r') {std::cout << "[\\r]";}else if (c == '\t') {std::cout << "[\\t]";}else {std::cout << c;}}else {std::cout << "[" << c << "]";}}std::cout << std::endl;std::cout << std::endl;

typedef std::unordered_map<std::string, std::shared_ptr<void>> ParserTable;

template<typename T, typename U>
class Parser {
public:
	static constexpr bool DO_DEBUG = false;
	using ParseFunction = std::function<void(const std::vector<T>&, std::vector<std::pair<U, size_t>>&, ParserTable&)>;

	std::string m_name;
	std::string m_original_name;

	ParseFunction m_parse_func;

	explicit Parser(ParseFunction parse_func, std::string name = "?")
		: m_name(std::move(name)), m_original_name(m_name), m_parse_func(std::move(parse_func)) {
	}
	Parser(ParseFunction parse_func, std::string name, std::string original_name)
		: m_name(std::move(name)), m_original_name(std::move(original_name)), m_parse_func(std::move(parse_func)) {
	}

	void parse(const std::vector<T>& input, std::vector<std::pair<U, size_t>>& output, ParserTable& table) const {
		m_parse_func(input, output, table);
	}
	std::vector<std::pair<U, size_t>> parse(const std::vector<T>& input, ParserTable& table) const {
		std::vector<std::pair<U, size_t>> output;
		this->parse(input, output, table);
		return output;
	}

	template<typename V>
	Parser<T, std::pair<U, V>> then(const Parser<T, V> other) const {
		auto combined_parse_func = [self=*this, other
			](const std::vector<T>& input,
			std::vector<std::pair<std::pair<U, V>, size_t>>& output, ParserTable& table) {
			if constexpr (DO_DEBUG) {
				std::cout << "Entering parser: " << self.m_name << " then " << other.m_name << " on input: ";
				PRINT_CONTENT(input);
			}
			std::vector<std::pair<U, size_t>> first_output;
			self.parse(input, first_output, table);
			for (const auto& [first_value, first_pos] : first_output) {
				std::vector<T> remaining_input(input.begin() + first_pos, input.end());
				std::vector<std::pair<V, size_t>> second_output;
				other.parse(remaining_input, second_output, table);
				for (const auto& [second_value, second_pos] : second_output) {
					output.emplace_back(std::make_pair(first_value, second_value), first_pos + second_pos);
				}
			}
		};
		return Parser<T, std::pair<U, V>>(combined_parse_func, std::format("{} + {}", m_name, other.m_name));
	}
	template<typename V>
	Parser<T, std::pair<U, V>> operator+(const Parser<T, V> other) const {
		return this->then(std::move(other));
	}

	// runs the first parser, then the second parser, both must succeed, returns only the result of the first parser
	template<typename V>
	Parser<T, U> followed_by(const Parser<T, V> other) const {
		auto followed_by_parse_func = [self=*this, other
			](const std::vector<T>& input, std::vector<std::pair<U, size_t>>& output, ParserTable& table) {
			if constexpr (DO_DEBUG) {
				std::cout << "Entering parser: " << self.m_name << " followed by " << other.m_name << " on input: ";
				PRINT_CONTENT(input);
			}
			std::vector<std::pair<U, size_t>> first_output;
			self.parse(input, first_output, table);
			for (const auto& [first_value, first_pos] : first_output) {
				std::vector<T> remaining_input(input.begin() + first_pos, input.end());
				std::vector<std::pair<V, size_t>> second_output;
				other.parse(remaining_input, second_output, table);
				for (const auto& [second_value, second_pos] : second_output) {
					output.emplace_back(first_value, first_pos + second_pos);
				}
			}
		};
		return Parser<T, U>(followed_by_parse_func, std::format("{} < {}", m_name, other.m_name));
	}
	template<typename V>
	Parser<T, U> operator<(const Parser<T, V> other) const {
		return this->followed_by(std::move(other));
	}

	// runs the first parser, then the second parser, both must succeed, returns only the result of the second parser
	template<typename V>
	Parser<T, V> preceding(const Parser<T, V> other) const {
		auto preceded_by_parse_func = [self=*this, other](const std::vector<T>& input,
			std::vector<std::pair<V, size_t>>& output, ParserTable& table) {
			if constexpr (DO_DEBUG) {
				std::cout << "Entering parser: " << self.m_name << " preceding " << other.m_name << " on input: ";
				PRINT_CONTENT(input);
			}
			std::vector<std::pair<U, size_t>> first_output;
			self.parse(input, first_output, table);
			for (const auto& [first_value, first_pos] : first_output) {
				std::vector<T> remaining_input(input.begin() + first_pos, input.end());
				std::vector<std::pair<V, size_t>> second_output;
				other.parse(remaining_input, second_output, table);
				for (const auto& [second_value, second_pos] : second_output) {
					output.emplace_back(second_value, first_pos + second_pos);
				}
			}
		};
		return Parser<T, V>(preceded_by_parse_func, std::format("{} > {}", m_name, other.m_name));
	}
	template<typename V>
	Parser<T, V> operator>(const Parser<T, V> other) const {
		return this->preceding(std::move(other));
	}

	Parser<T, U> choice(const Parser<T, U> other) const {
		auto choice_parse_func = [self=*this,other
			](const std::vector<T>& input, std::vector<std::pair<U, size_t>>& output, ParserTable& table) {
			if constexpr (DO_DEBUG) {
				std::cout << "Entering parser: " << self.m_name << " choice " << other.m_name << " on input: ";
				PRINT_CONTENT(input);
			}
			self.parse(input, output, table);
			other.parse(input, output, table);
		};
		return Parser<T, U>(choice_parse_func, std::format("{} | {}", m_name, other.m_name));
	}
	Parser<T, U> operator|(const Parser<T, U> other) const {
		return this->choice(std::move(other));
	}

	Parser<T, U> prioritized_choice(const Parser<T, U> other) const {
		auto prioritized_parse_func = [self=*this, other
			](const std::vector<T>& input, std::vector<std::pair<U, size_t>>& output, ParserTable& table) {
			if constexpr (DO_DEBUG) {
				std::cout << "Entering parser: " << self.m_name << " prioritized choice " << other.m_name << " on input: ";
				PRINT_CONTENT(input);
			}
			self.parse(input, output, table);
			if (output.empty()) {
				other.parse(input, output, table);
			}
		};
		return Parser<T, U>(prioritized_parse_func, std::format("{} || {}", m_name, other.m_name));
	}
	Parser<T, U> operator||(const Parser<T, U> other) const {
		return this->prioritized_choice(std::move(other));
	}

	template<bool empty, bool greedy = true>
	Parser<T, std::vector<U>> repetition() const {
		static_assert(greedy == true, "Non-greedy repetition not implemented yet");
		if constexpr (empty) {
			auto repetition_parse_func = [self = *this](const std::vector<T>& input,
				std::vector<std::pair<std::vector<U>, size_t>>& output, ParserTable& table) {
				if constexpr (DO_DEBUG) {
					std::cout << "Entering parser: " << self.m_name << " repetition * on input: ";
					PRINT_CONTENT(input);
				}
				std::vector<std::pair<std::vector<U>, size_t>> frontier;
				frontier.emplace_back(std::vector<U>{}, 0);
				while (!frontier.empty()) {
					auto [current_values, current_pos] = frontier.back();
					frontier.pop_back();
					std::vector<T> remaining_input(input.begin() + current_pos, input.end());
					std::vector<std::pair<U, size_t>> temp_output;
					self.parse(remaining_input, temp_output, table);
					if (temp_output.empty()) {
						output.emplace_back(current_values, current_pos);
						continue;
					}
					for (const auto& [value, pos] : temp_output) {
						auto new_values = current_values;
						new_values.push_back(value);
						frontier.emplace_back(new_values, current_pos + pos);
					}
				}
			};
			return Parser<T, std::vector<U>>(repetition_parse_func, std::format("{}*", m_name));
		}
		else {
			auto repetition_parse_func = [self = *this](const std::vector<T>& input,
				std::vector<std::pair<std::vector<U>, size_t>>& output, ParserTable& table) {
				if constexpr (DO_DEBUG) {
					std::cout << "Entering parser: " << self.m_name << " repetition + on input: ";
					PRINT_CONTENT(input);
				}
				std::vector<std::pair<std::vector<U>, size_t>> frontier;
				bool frontier_initialized = false;
				frontier.emplace_back(std::vector<U>{}, 0);
				while (!frontier.empty()) {
					auto [current_values, current_pos] = frontier.back();
					frontier.pop_back();
					std::vector<T> remaining_input(input.begin() + current_pos, input.end());
					std::vector<std::pair<U, size_t>> temp_output;
					self.parse(remaining_input, temp_output, table);
					if (temp_output.empty()) {
						if (frontier_initialized) {
							output.emplace_back(current_values, current_pos);
						}
						continue;
					}
					frontier_initialized = true;
					for (const auto& [value, pos] : temp_output) {
						auto new_values = current_values;
						new_values.push_back(value);
						frontier.emplace_back(new_values, current_pos + pos);
					}
				}
			};
			return Parser<T, std::vector<U>>(repetition_parse_func, std::format("{}+", m_name));
		}
	}
	Parser<T, std::vector<U>> operator*() const {
		return this->repetition<true>();
	}
	Parser<T, std::vector<U>> operator+() const {
		return this->repetition<false>();
	}

	template<typename V>
	Parser<T, V> map(std::function<V(U)> transform, std::string name = "?") const {
		auto map_parse_func = [self=*this, transform](const std::vector<T>& input,
			std::vector<std::pair<V, size_t>>& output, ParserTable& table) {
			std::vector<std::pair<U, size_t>> temp_output;
			self.parse(input, temp_output, table);
			for (const auto& [value, pos] : temp_output) {
				output.emplace_back(transform(value), pos);
			}
		};
		return Parser<T, V>(map_parse_func, std::format("({} -> {})", m_name, name));
	}
	template<typename V>
	Parser<T, V> operator<<(std::function<V(U)> transform) const {
		return this->map(transform);
	}

	Parser<T, U> filter(std::function<bool(U)> predicate, std::string name = "?") const {
		auto filter_parse_func = [self=*this, predicate](const std::vector<T>& input,
			std::vector<std::pair<U, size_t>>& output, ParserTable& table) {
			std::vector<std::pair<U, size_t>> temp_output;
			self.parse(input, temp_output, table);
			for (const auto& [value, pos] : temp_output) {
				if (predicate(value)) {
					output.emplace_back(value, pos);
				}
			}
		};
		return Parser<T, U>(filter_parse_func, std::format("({} [? {}])", m_name, name));
	}
	Parser<T, U> operator[](std::function<bool(U)> predicate) const {
		return this->filter(predicate);
	}

	Parser<T, U> final() const {
		auto final_parse_func = [self=*this](const std::vector<T>& input, std::vector<std::pair<U, size_t>>& output,
			ParserTable& table) {
			std::vector<std::pair<U, size_t>> temp_output;
			self.parse(input, temp_output, table);
			for (const auto& [value, pos] : temp_output) {
				if (pos == input.size()) {
					output.emplace_back(value, pos);
				}
			}
		};
		return Parser<T, U>(final_parse_func, std::format("(!{})", m_name));
	}
	Parser<T, U> operator!() const {
		return this->final();
	}

	Parser<T, std::optional<U>> optional() const {
		auto optional_parse_func = [self=*this](const std::vector<T>& input,
			std::vector<std::pair<std::optional<U>, size_t>>& output, ParserTable& table) {
			std::vector<std::pair<U, size_t>> temp_output;
			self.parse(input, temp_output, table);
			for (const auto& [value, pos] : temp_output) {
				output.emplace_back(value, pos);
			}
			if (output.empty()) {
				output.emplace_back(std::nullopt, 0);
			}
		};
		return Parser<T, std::optional<U>>(optional_parse_func, std::format("({}?)", m_name));
	}
	Parser<T, std::optional<U>> operator~() const {
		return this->optional();
	}

	Parser<T, std::optional<U>> always_optional() const {
		auto always_optional_parse_func = [self=*this](const std::vector<T>& input,
			std::vector<std::pair<std::optional<U>, size_t>>& output, ParserTable& table) {
			std::vector<std::pair<U, size_t>> temp_output;
			self.parse(input, temp_output, table);
			for (const auto& [value, pos] : temp_output) {
				output.emplace_back(value, pos);
			}
			output.emplace_back(std::nullopt, 0);
		};
		return Parser<T, std::optional<U>>(always_optional_parse_func, std::format("({}??)", m_name));
	}
	Parser<T, std::optional<U>> operator-() const {
		return this->always_optional();
	}

	template<typename V>
	Parser<T, std::vector<U>> separated_by(const Parser<T, V> separator, bool allow_trailing = false) const {
		auto separated_by_parse_func = [self=*this, separator, allow_trailing
			](const std::vector<T>& input, std::vector<std::pair<std::vector<U>, size_t>>& output, ParserTable& table) {
			std::vector<std::pair<std::vector<U>, size_t>> frontier;
			frontier.emplace_back(std::vector<U>{}, 0);
			while (!frontier.empty()) {
				auto [current_values, current_pos] = frontier.back();
				frontier.pop_back();
				std::vector<T> remaining_input(input.begin() + current_pos, input.end());
				std::vector<std::pair<U, size_t>> temp_output;
				self.parse(remaining_input, temp_output, table);
				if (temp_output.empty()) {
					if (allow_trailing || current_values.size() > 0) {
						output.emplace_back(current_values, current_pos);
					}
					continue;
				}
				for (const auto& [value, pos] : temp_output) {
					auto new_values = current_values;
					new_values.push_back(value);
					std::vector<T> next_input(remaining_input.begin() + pos, remaining_input.end());
					std::vector<std::pair<V, size_t>> sep_output;
					separator.parse(next_input, sep_output, table);
					if (sep_output.empty()) {
						frontier.emplace_back(new_values, current_pos + pos);
					}
					else {
						for (const auto& [sep_value, sep_pos] : sep_output) {
							frontier.emplace_back(new_values, current_pos + pos + sep_pos);
						}
					}
				}
			}
		};
		// allow trailing: operator %, disallow trailing: operator /
		std::string sep_name = allow_trailing
			? std::format("{} % {}", m_name, separator.m_name)
			: std::format("{} / {}", m_name, separator.m_name);
		return Parser<T, std::vector<U>>(separated_by_parse_func, sep_name);
	}
	template<typename V>
	Parser<T, std::vector<U>> operator%(const Parser<T, V> other) const {
		return this->separated_by(other, true);
	}
	template<typename V>
	Parser<T, std::vector<U>> operator/(const Parser<T, V> other) const {
		return this->separated_by(other, false);
	}

	Parser<T, U> rename(std::string name) const {
		return Parser<T, U>(m_parse_func, name, m_name);
	}
};

template<typename T, typename U>
Parser<T, U> make_parser(typename Parser<T, U>::ParseFunction parse_func, std::string name = "?") {
	return Parser<T, U>(parse_func, name);
}

template<typename T, typename U>
Parser<T, U> lookup_parser(std::string name, ParserTable& table) {
	if (const auto it = table.find(name); it != table.end()) {
		return *std::static_pointer_cast<Parser<T, U>>(it->second);
	}
	auto placeholder = std::make_shared<Parser<T, U>>(
		[](const std::vector<T>&, std::vector<std::pair<U, size_t>>&, ParserTable&) {
			// does nothing, always fails
		},
		name);
	table[name] = placeholder;
	return *placeholder;
}

template<typename T, typename U>
Parser<T, U> ref_parser(std::string name) {
	return Parser<T, U>(
		[name](const std::vector<T>& input, std::vector<std::pair<U, size_t>>& output, ParserTable& table) {
			if (const auto it = table.find(name); it != table.end()) {
				auto parser = std::static_pointer_cast<Parser<T, U>>(it->second);
				parser->parse(input, output, table);
			}
		},
		name);
}

template<typename T>
std::string try_infer_name(T value) {
	if constexpr (std::is_same_v<T, char>) {
		return std::string(1, value);
	}
	if constexpr (std::is_same_v<T, std::vector<char>>) {
		return std::string(value.begin(), value.end());
	}
	else if constexpr (std::is_arithmetic_v<T>) {
		return std::to_string(value);
	}
	else if constexpr (std::is_same_v<T, std::string>) {
		return value;
	}
	else if constexpr (std::is_convertible_v<T, std::string>) {
		return static_cast<std::string>(value);
	}
	// checks if ostream << T is valid
	else if constexpr (requires(std::ostream& os, T v) { os << v; }) {
		std::ostringstream oss;
		oss << value;
		return oss.str();
	}
	else {
		return "?";
	}
}

template<typename T>
Parser<T, T> symbol(T sym, std::string name) {
	auto symbol_parse_func = [sym](const std::vector<T>& input, std::vector<std::pair<T, size_t>>& output, ParserTable&) {
		if (!input.empty() && input[0] == sym) {
			output.emplace_back(sym, 1);
		}
	};
	return Parser<T, T>(symbol_parse_func, std::format("(symbol '{}')", name));
}
template<typename T>
Parser<T, T> symbol(T sym) {
	return symbol(sym, try_infer_name(sym));
}
inline Parser<char, char> symbol(char sym, std::string name, bool ignore_case) {
	auto symbol_parse_func = [sym, ignore_case](const std::vector<char>& input,
		std::vector<std::pair<char, size_t>>& output, ParserTable&) {
		if (!input.empty()) {
			if (ignore_case) {
				if (std::tolower(static_cast<unsigned char>(input[0])) == std::tolower(static_cast<unsigned char>(sym))) {
					output.emplace_back(input[0], 1);
				}
			}
			else {
				if (input[0] == sym) {
					output.emplace_back(sym, 1);
				}
			}
		}
	};
	return Parser<char, char>(symbol_parse_func, std::format("(symbol '{}')", name));
}
inline Parser<char, char> symbol(char sym, bool ignore_case) {
	return symbol(sym, try_infer_name(sym), ignore_case);
}
template<typename T>
Parser<T, T> symbols(std::vector<T> syms, std::string name) {
	auto symbols_parse_func = [syms
		](const std::vector<T>& input, std::vector<std::pair<T, size_t>>& output, ParserTable&) {
		if (!input.empty() && std::find(syms.begin(), syms.end(), input[0]) != syms.end()) {
			output.emplace_back(input[0], 1);
		}
	};
	return Parser<T, T>(symbols_parse_func, std::format("(symbols \"{}\")", name));
}
inline Parser<char, char> symbols(std::vector<char> syms, std::string name, bool ignore_case) {
	auto symbols_parse_func = [syms, ignore_case](const std::vector<char>& input,
		std::vector<std::pair<char, size_t>>& output, ParserTable&) {
		if (!input.empty()) {
			if (ignore_case) {
				for (const auto& sym : syms) {
					if (std::tolower(static_cast<unsigned char>(input[0])) == std::tolower(static_cast<unsigned char>(sym))) {
						output.emplace_back(input[0], 1);
						return;
					}
				}
			}
			else {
				if (std::find(syms.begin(), syms.end(), input[0]) != syms.end()) {
					output.emplace_back(input[0], 1);
				}
			}
		}
	};
	return Parser<char, char>(symbols_parse_func, std::format("(symbols \"{}\")", name));
}

template<typename T>
Parser<T, std::vector<T>> token(std::vector<T> tok, std::string name) {
	auto token_parse_func = [tok
		](const std::vector<T>& input, std::vector<std::pair<std::vector<T>, size_t>>& output, ParserTable&) {
		if (input.size() >= tok.size() && std::equal(tok.begin(), tok.end(), input.begin())) {
			output.emplace_back(tok, tok.size());
		}
	};
	return Parser<T, std::vector<T>>(token_parse_func, std::format("(token \"{}\")", name));
}
template<typename T>
Parser<T, std::vector<T>> token(std::vector<T> tok) {
	return token(tok, try_infer_name(tok));
}
inline Parser<char, std::vector<char>> token(std::vector<char> tok, std::string name, bool ignore_case) {
	auto token_parse_func = [tok, ignore_case](const std::vector<char>& input,
		std::vector<std::pair<std::vector<char>, size_t>>& output, ParserTable&) {
		if (input.size() >= tok.size()) {
			if (ignore_case) {
				bool match = true;
				for (size_t i = 0; i < tok.size(); ++i) {
					if (std::tolower(static_cast<unsigned char>(input[i])) != std::tolower(static_cast<unsigned char>(tok[i]))) {
						match = false;
						break;
					}
				}
				if (match) {
					output.emplace_back(std::vector<char>(input.begin(), input.begin() + tok.size()), tok.size());
				}
			}
			else {
				if (std::equal(tok.begin(), tok.end(), input.begin())) {
					output.emplace_back(std::vector<char>(input.begin(), input.begin() + tok.size()), tok.size());
				}
			}
		}
	};
	return Parser<char, std::vector<char>>(token_parse_func, std::format("(token \"{}\")", name));
}
inline Parser<char, std::vector<char>> token(std::string tok, std::string name, bool ignore_case = false) {
	return token(std::vector<char>(tok.begin(), tok.end()), name, ignore_case);
}
inline Parser<char, std::vector<char>> token(std::vector<char> tok, bool ignore_case) {
	return token(tok, try_infer_name(tok), ignore_case);
}
inline Parser<char, std::vector<char>> token(std::string tok, bool ignore_case = false) {
	return token(std::vector<char>(tok.begin(), tok.end()), try_infer_name(tok), ignore_case);
}
template<typename T>
Parser<T, std::vector<T>> tokens(std::vector<std::vector<T>> toks, std::string name, bool first_only = false) {
	auto tokens_parse_func = [toks, name, first_only
		](const std::vector<T>& input, std::vector<std::pair<std::vector<T>, size_t>>& output, ParserTable&) {
		if constexpr (Parser<T, std::vector<T>>::DO_DEBUG) {
			std::cout << "Entering parser: (tokens \"" << name << "\") on input: ";
			PRINT_CONTENT(input);
		}
		for (const auto& tok : toks) {
			if (input.size() >= tok.size() && std::equal(tok.begin(), tok.end(), input.begin())) {
				output.emplace_back(tok, tok.size());
				if (first_only) {
					break;
				}
			}
		}
	};
	return Parser<T, std::vector<T>>(tokens_parse_func, std::format("(tokens \"{}\")", name));
}
inline Parser<char, std::vector<char>> tokens(std::vector<std::vector<char>> toks, std::string name, bool ignore_case,
	bool first_only = false) {
	auto tokens_parse_func = [toks, ignore_case, first_only](const std::vector<char>& input,
		std::vector<std::pair<std::vector<char>, size_t>>& output, ParserTable&) {
		for (const auto& tok : toks) {
			if (input.size() >= tok.size()) {
				if (ignore_case) {
					bool match = true;
					for (size_t i = 0; i < tok.size(); ++i) {
						if (std::tolower(static_cast<unsigned char>(input[i])) !=
							std::tolower(static_cast<unsigned char>(tok[i]))) {
							match = false;
							break;
						}
					}
					if (match) {
						output.emplace_back(std::vector<char>(input.begin(), input.begin() + tok.size()), tok.size());
						if (first_only) {
							break;
						}
					}
				}
				else {
					if (std::equal(tok.begin(), tok.end(), input.begin())) {
						output.emplace_back(std::vector<char>(input.begin(), input.begin() + tok.size()), tok.size());
						if (first_only) {
							break;
						}
					}
				}
			}
		}
	};
	return Parser<char, std::vector<char>>(tokens_parse_func, std::format("(tokens \"{}\")", name));
}
inline Parser<char, std::vector<char>> tokens(std::vector<std::string> toks, std::string name, bool ignore_case = false,
	bool first_only = false) {
	// Sort tokens by length descending to ensure longest match first
	std::ranges::sort(toks,
		[](const std::string& a, const std::string& b) {
			return a.size() > b.size();
		});
	// Convert to vector<vector<char>>
	std::vector<std::vector<char>> char_toks;
	for (const auto& tok : toks) {
		char_toks.emplace_back(tok.begin(), tok.end());
	}
	return tokens(char_toks, name, ignore_case, first_only);
}

inline Parser<char, char> symbol_range(char start, char end, std::string name = "?") {
	auto range_parse_func = [start, end](const std::vector<char>& input, std::vector<std::pair<char, size_t>>& output,
		ParserTable&) {
		if (!input.empty() && input[0] >= start && input[0] <= end) {
			output.emplace_back(input[0], 1);
		}
	};
	return Parser<char, char>(range_parse_func, std::format("(range '{}'-'{}')", start, end));
}

template<typename T>
Parser<T, T> satisfy(std::function<bool(T)> predicate, std::string name = "?") {
	auto satisfy_parse_func = [predicate](const std::vector<T>& input, std::vector<std::pair<T, size_t>>& output,
		ParserTable&) {
		if (!input.empty() && predicate(input[0])) {
			output.emplace_back(input[0], 1);
		}
	};
	return Parser<T, T>(satisfy_parse_func, std::format("(satisfy {})", name));
}
template<typename T, typename U>
Parser<T, U> succeed(U value) {
	auto succeed_parse_func = [value](const std::vector<T>&, std::vector<std::pair<U, size_t>>& output, ParserTable&) {
		output.emplace_back(value, 0);
	};
	return Parser<T, U>(succeed_parse_func, std::format("(succeed {})", try_infer_name(value)));
}
template<typename T, typename U>
Parser<T, U> fail() {
	auto fail_parse_func = [](const std::vector<T>& input, std::vector<std::pair<U, size_t>>& output, ParserTable&) {
		// Always fails, produces no output
	};
	return Parser<T, U>(fail_parse_func, "(fail)");
}

template<typename T, typename U>
Parser<T, U> parse_eof(U value) {
	auto eof_parse_func = [value](const std::vector<T>& input, std::vector<std::pair<U, size_t>>& output, ParserTable&) {
		if (input.empty()) {
			output.emplace_back(value, 0);
		}
	};
	return Parser<T, U>(eof_parse_func, "(eof)");
}

inline std::vector<char> operator""_t(const char* str, size_t len) {
	return {str, str + len};
}
