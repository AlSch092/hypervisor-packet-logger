#pragma once
#include <ia32.hpp>
#include "spin-lock.h"

namespace hv {

	typedef struct _SecBuffer
	{
		unsigned long cbBuffer; // Size of the buffer, in bytes
		unsigned long BufferType; // BufferType 7 = SECBUFFER_HEADER, 1 = SECBUFFER_DATA, 6 = SECBUFFER_TRAILER
		void* pvBuffer;            // Pointer to the buffer
	} SecBuffer, * PSecBuffer;

	typedef struct _SecBufferDesc
	{
		unsigned long ulVersion;
		unsigned long cBuffers;
		PSecBuffer    pBuffers;
	} SecBufferDesc, * PSecBufferDesc;

	namespace custom_tasks {
		
		const uint8_t max_tasks = 10;

		enum task_code : uint8_t  {
			none = 0,
			log_send_packets = 1, //implemented
			log_recv_packets = 2, //not yet implemented
			modify_packets = 3, //needs a shared buffer between UM and HV, not yet implemented
			log_plaintext_tls = 4, //in-progress
			bypass_testsign_check_ntquery = 5, 
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