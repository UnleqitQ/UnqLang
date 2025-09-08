#pragma once

#include <vector>
#include <memory>
#include <unordered_map>
#include <variant>

/**
 *
 * @tparam I input type
 * @tparam S symbol type
 */
template<typename I, typename S>
class ShiftReduceParser {
public:
	struct Reduced {
		S symbol;
		std::variant<I, std::vector<Reduced>> children;
		int consumed_terminal_count;
	};
	typedef std::vector<S> Stack;
	typedef std::vector<I> Input;

	struct Rule {
		S result;
		std::vector<S> pattern;
	};
	typedef std::function<bool(const I&, S&)> InputToSymbolFunc;

private:
	InputToSymbolFunc m_input_to_symbol;
	std::vector<Rule> m_rules;

public:
	explicit ShiftReduceParser(InputToSymbolFunc input_to_symbol) : m_input_to_symbol(std::move(input_to_symbol)) {
	}
	ShiftReduceParser() : m_input_to_symbol([](const I&, S&) { return false; }) {
	}
	void add_rule(const Rule& rule) {
		m_rules.push_back(rule);
	}
	std::vector<Reduced> parse(const Input& input, int& consumed) const;
};

template<typename I, typename S>
std::vector<typename ShiftReduceParser<I, S>::Reduced> ShiftReduceParser<I, S>::parse(const Input& input, int& consumed) const {
	Stack stack;
	std::vector<Reduced> reduced_nodes;
	consumed = 0;
	for (const auto& token : input) {
		S sym;
		if (!m_input_to_symbol(token, sym)) {
			// token is considered terminal, that means the parse is complete
			break;
		}
		++consumed;
		stack.push_back(sym);
		reduced_nodes.push_back(Reduced{sym, token, 1});
		bool reduced;
		do {
			reduced = false;
			for (const auto& rule : m_rules) {
				if (stack.size() >= rule.pattern.size()) {
					bool match = true;
					for (size_t i = 0; i < rule.pattern.size(); ++i) {
						if (stack[stack.size() - rule.pattern.size() + i] != rule.pattern[i]) {
							match = false;
							break;
						}
					}
					if (match) {
						// Perform reduction
						std::vector<Reduced> children;
						for (size_t i = 0; i < rule.pattern.size(); ++i) {
							children.push_back(reduced_nodes.back());
							reduced_nodes.pop_back();
							stack.pop_back();
						}
						std::reverse(children.begin(), children.end());
						stack.push_back(rule.result);
						int consumed_terminal_count = 0;
						for (const auto& child : children) {
							consumed_terminal_count += child.consumed_terminal_count;
						}
						reduced_nodes.push_back(Reduced{rule.result, children, consumed_terminal_count});
						reduced = true;
						break; // Restart scanning rules
					}
				}
			}
		} while (reduced);
	}
	return reduced_nodes;
}
