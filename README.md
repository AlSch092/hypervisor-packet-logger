# hypervisor-packet-logger
Intel VT-x Hypervisor with custom packet logging logic

Uses jonomango's "hv" project, found [here](https://github.com/jonomango/hv)  , in particular MMRs to catch execution of specific addresses  

- Currently supports send() logging for all processes (you must register your desired process to log data from its send() calls)
- Future updates will include recv() logging, plaintext TLS logging (SealMessage/EncryptMessage) for easy logging in cert-pinned applications
- Data modification might also be implemented in the future, along with data sending

Processes can be registered & unregistered from user mode for data logging in the hypervisor by using:  
`hv::register_custom_task(target_pid, task_code::log_send_packets, src_addr, true);` and `hv::register_custom_task(target_pid, task_code::log_send_packets, src_addr, false);`

We then register an MMR:  
`add_monitored_mem_range(target_pid, src_addr, 1, 4);`  

When monitoring an address located in a common DLL such as `ws2_32.dll`, most often the same address can be used to log data from most to all running processes, as their VA's will often map to the same physical addresses.

Example of working program:  

<img width="981" height="322" alt="hv_packetlog" src="https://github.com/user-attachments/assets/46b449e0-4794-4be7-aca6-1715fe23fd1f" />

Program can be easily modified to log plaintext data from games, you just need the correct VA + registers of the data + length.  

Enjoy!
