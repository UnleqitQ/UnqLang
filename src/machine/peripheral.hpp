#pragma once
#include <cstdint>
#include <functional>

#include "ram.hpp"

namespace machine {
	struct peripheral {
		typedef std::function<uint32_t(data_size_t value_size)> read_callback_t;
		typedef std::function<void(uint32_t value, data_size_t value_size)> write_callback_t;

		uint16_t port;
		read_callback_t read_callback;
		write_callback_t write_callback;

		peripheral() : port(0), read_callback(nullptr), write_callback(nullptr) {
		}
		explicit peripheral(uint16_t port) : port(port), read_callback(nullptr), write_callback(nullptr) {
		}
		peripheral(uint16_t port, const read_callback_t& read_callback, const write_callback_t& write_callback)
			: port(port), read_callback(read_callback), write_callback(write_callback) {
		}
	};
} // machine
