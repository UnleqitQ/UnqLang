#pragma once
#include <string>

namespace utils {
	inline std::string trim(const std::string& str) {
		const std::string whitespace = " \t\n\r";
		const size_t start = str.find_first_not_of(whitespace);
		if (start == std::string::npos) {
			return "";
		}
		const size_t end = str.find_last_not_of(whitespace);
		return str.substr(start, end - start + 1);
	}
	inline std::string to_lower(const std::string& str) {
		std::string result = str;
		for (char& c : result) {
			c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
		}
		return result;
	}
	inline std::string to_upper(const std::string& str) {
		std::string result = str;
		for (char& c : result) {
			c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
		}
		return result;
	}
}
