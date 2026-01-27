#include "custom-tasks.h"

namespace hv {

	namespace custom_tasks
	{
		custom_task tasks[max_tasks];
		uint8_t tasks_count = 0;

		spin_lock lock;

		uint8_t get_tasks_count()
		{
			return tasks_count;
		}

		custom_task get_task(const uint32_t index)
		{
			if (index >= max_tasks)
				return custom_task{ 0,0,none };

			return tasks[index];
		}

		//searches for the first available slot from 0..max_tasks-1 . 
		//we could make it so that tasks are shifted downwards when removed, but id argue it uses more rsources than just iterating the list, as the list is always small
		bool register_task(uint32_t pid, task_code code, uint64_t extra_data, uint8_t enable)
		{
			scoped_spin_lock lock(lock);

			if (enable)
			{
				if (tasks_count >= max_tasks)
					return false; // max tasks reached

				for (int i = 0; i < max_tasks; i++) //needs to be improved to be linked-list style, but realistically this is barely any extra cpu usage
				{
					if (tasks[i].pid == 0 && tasks[i].code == none)
					{
						tasks[i].pid = pid;
						tasks[i].code = code;
						tasks[i].extra_data = extra_data; //generally RIP of VA which we want to take action on when that VA hits violation handler
						tasks_count++;
						return true;
					}
				}

				return false; //no space
			}
			else
			{
				if (tasks_count == 0)
					return false;

				for (int i = 0; i < max_tasks; i++)
				{
					if (tasks[i].pid == pid && tasks[i].code == code)
					{
						tasks[i].pid = 0;
						tasks[i].code = none;
						tasks[i].extra_data = 0;
						tasks_count--;
						return true;
					}
				}

				return false; //not found
			}
		}
	}
}