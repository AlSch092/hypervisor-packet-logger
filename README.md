# helpervisor
Intel VT-x Hypervisor with custom features to assist with pentesting, game hacking & bypassing

Uses jonomango's "hv" project, found [here](https://github.com/jonomango/hv)  , in particular MMRs to catch execution of specific addresses  

## Current Features:
- Supports send() logging for all/any processes, recv() will be addded soon
- Supports plaintext TLS logging (SealMessage/EncryptMessage) for easy outbound data logging of cert-pinned applications (won't work for applications using a custom TLS implementation such as OpenSSL), inbound support (DecryptMessage) will be added soon
- Bypasses usermode calls to `NtQuerySystemInformation` where `SYSTEM_INFORMATION_CLASS` == 103 (CodeIntegrityInformation) -> Tricks usermode processes into believing testsigning mode is OFF

## Planned Features:
- Sending data via send()
- Additional usermode bypass methods -> Try to trick usermode programs into thinking test signing mode is OFF, debug mode is OFF, secure boot is ON, HVCI is ON, no hypervisor is loaded, etc.

## Setting up custom tasks:

Processes can be registered & unregistered from user mode code for custom tasks in the hypervisor by using:  
`hv::register_custom_task(target_pid, task_code::log_send_packets, first_instruction_address_send, true);` (register)  
and...  
`hv::register_custom_task(target_pid, task_code::log_send_packets, first_instruction_address_send, false);`  (unregister)  

We then register an MMR:  
`add_monitored_mem_range(target_pid, src_addr, 1, 4);`  

`src_addr` == RIP (current address being executed), must be the address of the instruction you want to monitor in the MMR. For example, if we are logging `send()` data, `src_addr` needs to be the address of the first instruction in `send()`.

When monitoring an address located in a common DLL such as `ws2_32.dll`, most often the same VA can be used for most (if not all) running processes, as their VA's will map to the same physical addresses (unless an instruction on that page has been patched in one of the processes, triggering copy-on-write).

## Example of working program:  

<img width="981" height="322" alt="hv_packetlog" src="https://github.com/user-attachments/assets/46b449e0-4794-4be7-aca6-1715fe23fd1f" />

Program can be easily modified to log plaintext data from games, you just need the correct VA + registers of the data + length.  

Enjoy!
