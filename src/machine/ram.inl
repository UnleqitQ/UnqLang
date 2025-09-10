#pragma once
#ifndef MACHINE_RAM
#error "Include machine/ram.hpp instead of machine/ram.inl"
#endif

#include <iostream>

namespace machine {
	inline data_size_t data_size_from_string(const std::string& str) {
		if (str == "byte") {
			return data_size_t::BYTE;
		}
		else if (str == "word") {
			return data_size_t::WORD;
		}
		else if (str == "dword") {
			return data_size_t::DWORD;
		}
		else {
			throw std::invalid_argument("Invalid data size string: " + str);
		}
	}
	inline std::ostream& operator<<(std::ostream& os, const data_size_t& ds) {
		switch (ds) {
			case data_size_t::BYTE:
				os << "byte";
				break;
			case data_size_t::WORD:
				os << "word";
				break;
			case data_size_t::DWORD:
				os << "dword";
				break;
			default:
				os << "unknown";
				break;
		}
		return os;
	}
}

template<>
struct std::formatter<machine::data_size_t> : std::formatter<std::string> {
	auto format(const machine::data_size_t& ds, auto& ctx) const {
		std::string str;
		switch (ds) {
			case machine::data_size_t::BYTE:
				str = "byte";
				break;
			case machine::data_size_t::WORD:
				str = "word";
				break;
			case machine::data_size_t::DWORD:
				str = "dword";
				break;
			default:
				str = "unknown";
				break;
		}
		return std::formatter<std::string>::format(str, ctx);
	}
};
