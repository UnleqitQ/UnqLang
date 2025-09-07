#pragma once

#include "instruction.hpp"
#include "ram.hpp"
#include "register.hpp"

namespace machine {
	enum class execution_state_t : uint8_t {
		RUNNING,
		HALTED,
		ERROR
	};

	class computer {
		ram m_ram;
		register_file m_registers;
		uint32_t m_instruction_pointer = 0;
		program_t m_program;
		execution_state_t m_state = execution_state_t::HALTED;
		bool m_verbose = false;
		std::string m_error_message;

	public:
		computer() {
			uint32_t initial_stack_pointer = ram::SIZE;
			m_registers.esp = initial_stack_pointer;
			m_registers.ebp = initial_stack_pointer;
		}
		computer(const ram& r, const register_file& reg)
			: m_ram(r), m_registers(reg) {
		}
		void load_program(const program_t& program) {
			m_program = program;
			m_instruction_pointer = 0;
			m_state = execution_state_t::RUNNING;
		}
		void step(); // Execute a single instruction
		void run(int max_steps = -1); // Run until the end of the program or max_steps reached

		void set_verbose(bool v) {
			m_verbose = v;
		}
		bool is_verbose() const {
			return m_verbose;
		}
		const std::string& get_error_message() const {
			return m_error_message;
		}

		ram& get_ram() {
			return m_ram;
		}
		const ram& get_ram() const {
			return m_ram;
		}
		register_file& get_registers() {
			return m_registers;
		}
		const register_file& get_registers() const {
			return m_registers;
		}
		uint32_t get_instruction_pointer() const {
			return m_instruction_pointer;
		}
		void set_instruction_pointer(uint32_t ip) {
			m_instruction_pointer = ip;
		}
		const program_t& get_program() const {
			return m_program;
		}
		execution_state_t get_state() const {
			return m_state;
		}
		void set_state(execution_state_t state) {
			m_state = state;
		}

		bool is_halted() const {
			return m_state == execution_state_t::HALTED;
		}
		bool is_running() const {
			return m_state == execution_state_t::RUNNING;
		}
		bool is_error() const {
			return m_state == execution_state_t::ERROR;
		}

	private:
		uint32_t retrieve_memory_address(const memory_operand& mem_op) const;
		uint32_t retrieve_operand_value(const operand_arg& op) const;
		uint32_t retrieve_result_value(const result_arg& res) const;
		void set_result_value(const result_arg& res, uint32_t value);
		void execute_instruction(const instruction_t& instr);
	};
} // machine
