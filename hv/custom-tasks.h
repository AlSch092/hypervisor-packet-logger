#pragma once
#include <ia32.hpp>
#include "spin-lock.h"

namespace hv {

	namespace custom_tasks {
		
		const uint8_t max_tasks = 10;

		enum task_code : uint8_t  {
			none = 0,
			log_packets = 1,
			modify_packets = 2,
		};

		struct custom_task {
			uint32_t pid;
			uint64_t extra_data;
			task_code code;
		};

		bool register_task(uint32_t pid, task_code code, uint64_t extra_data, uint8_t enable);

		uint8_t get_tasks_count();
		custom_task get_task(uint32_t const index);

	} // namespace custom_tasks

} // namespace hv