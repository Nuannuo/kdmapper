#include "kdmapper.hpp"
#include <Windows.h>
#include <iostream>

#include "utils.hpp"
#include "intel_driver.hpp"
#include "nt.hpp"
#include "portable_executable.hpp"
#include <cstring>
#include <vector>

static bool kdmapper_entry_via_io_create_driver = false;

void kdmapper::SetEntryViaIoCreateDriver(bool enabled) {
	kdmapper_entry_via_io_create_driver = enabled;
}

/*
 * Calls IoCreateDriver(NULL, DriverEntry) from a real kernel system thread.
 *
 * kdmapper's regular CallKernelFunction runs the target inside the patched
 * NtAddAtom syscall, so the driver sees PreviousMode == UserMode and any
 * Zw or Nt call that probes kernel-stack structures fails with 0xC0000005
 * (TitanHide's FindCrossThreadFlagsOffset is one example). A PsCreateSystemThread
 * worker runs with PreviousMode == KernelMode, exactly like a service-loaded
 * driver.
 *
 * Page layout (one non-paged, executable page):
 *   0x000  create-thread stub (calls PsCreateSystemThread on the worker)
 *   0x100  worker stub (calls IoCreateDriver, stores the status)
 *   0x180  HANDLE slot / 0x188 NTSTATUS slot / 0x1A0 OBJECT_ATTRIBUTES
 */
static bool CallEntryViaKernelThread(NTSTATUS* out_status, ULONG64 driver_entry) {
	const ULONG64 io_create_driver =
		intel_driver::GetKernelModuleExport(intel_driver::ntoskrnlAddr, "IoCreateDriver");
	const ULONG64 ps_create_thread =
		intel_driver::GetKernelModuleExport(intel_driver::ntoskrnlAddr, "PsCreateSystemThread");
	if (io_create_driver == 0 || ps_create_thread == 0) {
		kdmLog(L"[-] IoCreateDriver or PsCreateSystemThread was not found" << std::endl);
		return false;
	}

	constexpr ULONG64 kPageSize = 0x1000;
	const ULONG64 page = intel_driver::AllocatePool(nt::POOL_TYPE::NonPagedPool, kPageSize);
	if (page == 0) {
		kdmLog(L"[-] Failed to allocate the entry stub page" << std::endl);
		return false;
	}

	const ULONG64 worker = page + 0x100;
	const ULONG64 handle_slot = page + 0x180;
	const ULONG64 status_slot = page + 0x188;
	const ULONG64 object_attributes = page + 0x1A0;

	BYTE block[0x200] = {};
	size_t o = 0;
	auto byte = [&](BYTE value) { block[o++] = value; };
	auto imm64 = [&](ULONG64 value) {
		for (int i = 0; i < 8; ++i) {
			block[o++] = static_cast<BYTE>(value >> (i * 8));
		}
	};

	/* create-thread stub */
	byte(0x48); byte(0x83); byte(0xEC); byte(0x38);            /* sub rsp, 0x38 */
	byte(0x48); byte(0xB9); imm64(handle_slot);                /* mov rcx, &handle */
	byte(0xBA); byte(0xFF); byte(0xFF); byte(0x1F); byte(0x00);/* mov edx, THREAD_ALL_ACCESS */
	byte(0x49); byte(0xB8); imm64(object_attributes);          /* mov r8, &object attributes */
	byte(0x45); byte(0x31); byte(0xC9);                        /* xor r9d, r9d */
	byte(0x48); byte(0xC7); byte(0x44); byte(0x24); byte(0x20); byte(0); byte(0); byte(0); byte(0); /* [rsp+0x20] = NULL (ClientId) */
	byte(0x48); byte(0xB8); imm64(worker);                     /* mov rax, worker */
	byte(0x48); byte(0x89); byte(0x44); byte(0x24); byte(0x28);/* [rsp+0x28] = worker (StartRoutine) */
	byte(0x48); byte(0xC7); byte(0x44); byte(0x24); byte(0x30); byte(0); byte(0); byte(0); byte(0); /* [rsp+0x30] = NULL (StartContext) */
	byte(0x48); byte(0xB8); imm64(ps_create_thread);           /* mov rax, PsCreateSystemThread */
	byte(0xFF); byte(0xD0);                                    /* call rax */
	byte(0x48); byte(0x83); byte(0xC4); byte(0x38);            /* add rsp, 0x38 */
	byte(0xC3);                                                /* ret */

	if (o > 0x100) {
		kdmLog(L"[-] Internal error: create stub overflows its slot" << std::endl);
		intel_driver::FreePool(page);
		return false;
	}

	/* worker stub, entered with the system thread's kernel stack */
	o = 0x100;
	byte(0x48); byte(0x83); byte(0xEC); byte(0x28);            /* sub rsp, 0x28 */
	byte(0x48); byte(0xB9); imm64(0);                          /* mov rcx, NULL (DriverName) */
	byte(0x48); byte(0xBA); imm64(driver_entry);               /* mov rdx, DriverEntry */
	byte(0x48); byte(0xB8); imm64(io_create_driver);           /* mov rax, IoCreateDriver */
	byte(0xFF); byte(0xD0);                                    /* call rax */
	byte(0x48); byte(0xBB); imm64(status_slot);                /* mov rbx, &status */
	byte(0x89); byte(0x03);                                    /* mov [rbx], eax */
	byte(0x48); byte(0x83); byte(0xC4); byte(0x28);            /* add rsp, 0x28 */
	byte(0xC3);                                                /* ret -> thread exits */

	/* OBJECT_ATTRIBUTES for PsCreateSystemThread: Length=0x30, rest zero */
	block[0x1A0] = 0x30;
	/* status sentinel: the worker overwrites it with the real NTSTATUS */
	*reinterpret_cast<ULONG*>(block + 0x188) = 0xDEADBEEFu;

	if (!intel_driver::WriteMemory(page, block, sizeof(block)) ||
		!intel_driver::MmSetPageProtection(page, static_cast<uint32_t>(kPageSize), PAGE_EXECUTE_READWRITE)) {
		kdmLog(L"[-] Failed to prepare the entry stub page" << std::endl);
		intel_driver::FreePool(page);
		return false;
	}

	/* The create stub only builds the thread; it returns immediately. */
	intel_driver::CallKernelFunction<void>(nullptr, page);

	HANDLE thread = nullptr;
	if (!intel_driver::ReadMemory(handle_slot, &thread, sizeof(thread)) || thread == nullptr) {
		kdmLog(L"[-] PsCreateSystemThread did not return a handle" << std::endl);
		intel_driver::FreePool(page);
		return false;
	}

	WaitForSingleObject(thread, 30000);

	NTSTATUS status = 0xDEADBEEF;
	intel_driver::ReadMemory(status_slot, &status, sizeof(status));

	CloseHandle(thread);
	intel_driver::FreePool(page);

	if (status == 0xDEADBEEF) {
		kdmLog(L"[-] The kernel worker thread did not report a status" << std::endl);
		return false;
	}

	*out_status = status;
	return true;
}

void RelocateImageByDelta(portable_executable::vec_relocs relocs, const ULONG64 delta) {
	for (const auto& current_reloc : relocs) {
		for (auto i = 0u; i < current_reloc.count; ++i) {
			const uint16_t type = current_reloc.item[i] >> 12;
			const uint16_t offset = current_reloc.item[i] & 0xFFF;

			if (type == IMAGE_REL_BASED_DIR64)
				*reinterpret_cast<ULONG64*>(current_reloc.address + offset) += delta;
		}
	}
}

// Fix cookie by @Jerem584
bool FixSecurityCookie(void* local_image, ULONG64 kernel_image_base)
{
	auto headers = portable_executable::GetNtHeaders(local_image);
	if (!headers)
		return false;

	auto load_config_directory = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
	if (!load_config_directory)
	{
		kdmLog(L"[+] Load config directory wasn't found, probably StackCookie not defined, fix cookie skipped" << std::endl);
		return true;
	}

	auto load_config_struct = (PIMAGE_LOAD_CONFIG_DIRECTORY)((uintptr_t)local_image + load_config_directory);
	auto stack_cookie = load_config_struct->SecurityCookie;
	if (!stack_cookie)
	{
		kdmLog(L"[+] StackCookie not defined, fix cookie skipped" << std::endl);
		return true; // as I said, it is not an error and we should allow that behavior
	}

	stack_cookie = stack_cookie - (uintptr_t)kernel_image_base + (uintptr_t)local_image; //since our local image is already relocated the base returned will be kernel address

	if (*(uintptr_t*)(stack_cookie) != 0x2B992DDFA232) {
		kdmLog(L"[-] StackCookie already fixed!? this probably wrong" << std::endl);
		return false;
	}

	kdmLog(L"[+] Fixing stack cookie" << std::endl);

	auto new_cookie = 0x2B992DDFA232 ^ GetCurrentProcessId() ^ GetCurrentThreadId(); // here we don't really care about the value of stack cookie, it will still works and produce nice result
	if (new_cookie == 0x2B992DDFA232)
		new_cookie = 0x2B992DDFA233;

	*(uintptr_t*)(stack_cookie) = new_cookie; // the _security_cookie_complement will be init by the driver itself if they use crt
	return true;
}

bool ResolveImports(portable_executable::vec_imports imports) {
	for (const auto& current_import : imports) {
		ULONG64 Module = kdmUtils::GetKernelModuleAddress(current_import.module_name);
		if (!Module) {
#if !defined(DISABLE_OUTPUT)
			std::cout << "[-] Dependency " << current_import.module_name << " wasn't found" << std::endl;
#endif
			return false;
		}

		for (auto& current_function_data : current_import.function_datas) {
			ULONG64 function_address = intel_driver::GetKernelModuleExport(Module, current_function_data.name);

			if (!function_address) {
				//Lets try with ntoskrnl
				if (Module != intel_driver::ntoskrnlAddr) {
					function_address = intel_driver::GetKernelModuleExport(intel_driver::ntoskrnlAddr, current_function_data.name);
					if (!function_address) {
#if !defined(DISABLE_OUTPUT)
						std::cout << "[-] Failed to resolve import " << current_function_data.name << " (" << current_import.module_name << ")" << std::endl;
#endif
						return false;
					}
				}
			}

			*current_function_data.address = function_address;
		}
	}

	return true;
}

ULONG64 kdmapper::MapDriver(BYTE* data, ULONG64 param1, ULONG64 param2, bool free, bool destroyHeader, AllocationMode mode, bool PassAllocationAddressAsFirstParam, mapCallback callback, NTSTATUS* exitCode) {

	const PIMAGE_NT_HEADERS64 nt_headers = portable_executable::GetNtHeaders(data);

	if (!nt_headers) {
		kdmLog(L"[-] Invalid format of PE image" << std::endl);
		return 0;
	}

	if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		kdmLog(L"[-] Image is not 64 bit" << std::endl);
		return 0;
	}

	ULONG32 image_size = nt_headers->OptionalHeader.SizeOfImage;

	void* local_image_base = VirtualAlloc(nullptr, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!local_image_base)
		return 0;

	DWORD TotalVirtualHeaderSize = (IMAGE_FIRST_SECTION(nt_headers))->VirtualAddress;
	image_size = image_size - (destroyHeader ? TotalVirtualHeaderSize : 0);

	ULONG64 kernel_image_base = 0;
	if (mode == AllocationMode::AllocateIndependentPages)
	{
		kernel_image_base = intel_driver::MmAllocateIndependentPagesEx(image_size);
	}
	else { // AllocatePool by default
		kernel_image_base = intel_driver::AllocatePool(nt::POOL_TYPE::NonPagedPool, image_size);
	}

	if (!kernel_image_base) {
		kdmLog(L"[-] Failed to allocate remote image in kernel" << std::endl);

		VirtualFree(local_image_base, 0, MEM_RELEASE);
		return 0;
	}

	do {
		kdmLog(L"[+] Image base has been allocated at 0x" << reinterpret_cast<void*>(kernel_image_base) << std::endl);

		// Copy image headers

		memcpy(local_image_base, data, nt_headers->OptionalHeader.SizeOfHeaders);

		// Copy image sections

		const PIMAGE_SECTION_HEADER current_image_section = IMAGE_FIRST_SECTION(nt_headers);

		for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
			if ((current_image_section[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0)
				continue;
			auto local_section = reinterpret_cast<void*>(reinterpret_cast<ULONG64>(local_image_base) + current_image_section[i].VirtualAddress);
			memcpy(local_section, reinterpret_cast<void*>(reinterpret_cast<ULONG64>(data) + current_image_section[i].PointerToRawData), current_image_section[i].SizeOfRawData);
		}

		ULONG64 realBase = kernel_image_base;
		if (destroyHeader) {
			kernel_image_base -= TotalVirtualHeaderSize;
			kdmLog(L"[+] Skipped 0x" << std::hex << TotalVirtualHeaderSize << L" bytes of PE Header" << std::endl);
		}

		// Resolve relocs and imports

		RelocateImageByDelta(portable_executable::GetRelocs(local_image_base), kernel_image_base - nt_headers->OptionalHeader.ImageBase);

		if (!FixSecurityCookie(local_image_base, kernel_image_base ))
		{
			kdmLog(L"[-] Failed to fix cookie" << std::endl);
			return 0;
		}

		if (!ResolveImports(portable_executable::GetImports(local_image_base))) {
			kdmLog(L"[-] Failed to resolve imports" << std::endl);
			kernel_image_base = realBase;
			break;
		}

		// Write fixed image to kernel

		if (!intel_driver::WriteMemory(realBase, (PVOID)((uintptr_t)local_image_base + (destroyHeader ? TotalVirtualHeaderSize : 0)), image_size)) {
			kdmLog(L"[-] Failed to write local image to remote image" << std::endl);
			kernel_image_base = realBase;
			break;
		}

		if (mode == AllocationMode::AllocateIndependentPages)
		{
			auto ProtectionToString = [](ULONG prot) -> const char* {
				switch (prot)
				{
				case PAGE_NOACCESS: return "NOACCESS";
				case PAGE_READONLY: return "READONLY";
				case PAGE_READWRITE: return "READWRITE";
				case PAGE_EXECUTE: return "EXECUTE";
				case PAGE_EXECUTE_READ: return "EXECUTE_READ";
				case PAGE_EXECUTE_READWRITE: return "EXECUTE_READWRITE";
				default: return "UNKNOWN";
				}
				};

			for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
				auto sec = &IMAGE_FIRST_SECTION(nt_headers)[i];
				uintptr_t secAddr = kernel_image_base + sec->VirtualAddress;
				uint32_t secSize = sec->Misc.VirtualSize;

				if (secSize <= 0) {
					kdmLog(L"[*] Skipping empty section: " << (char*)sec->Name << std::endl);
					continue;
				}

				ULONG prot = PAGE_READONLY;

				if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
					prot = (sec->Characteristics & IMAGE_SCN_MEM_WRITE) ?
						PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
				}
				else if (sec->Characteristics & IMAGE_SCN_MEM_WRITE) {
					prot = PAGE_READWRITE;
				}
				else if (sec->Characteristics & IMAGE_SCN_MEM_READ) {
					prot = PAGE_READONLY;
				}

				kdmLog(L"[+] Setting protection for section: "
					<< (char*)sec->Name
					<< L" Base: 0x" << std::hex << secAddr
					<< L" Size: 0x" << secSize
					<< L" Prot: " << ProtectionToString(prot)
					<< std::dec << std::endl);

				if (!intel_driver::MmSetPageProtection(secAddr, secSize, prot)) {
					kdmLog(L"[-] Failed to set protection for section: " << (char*)sec->Name << std::endl);
				}
			}
		}

		// Call driver entry point

		const ULONG64 address_of_entry_point = kernel_image_base + nt_headers->OptionalHeader.AddressOfEntryPoint;

		kdmLog(L"[<] Calling DriverEntry 0x" << reinterpret_cast<void*>(address_of_entry_point) << std::endl);

		if (callback) {
			if (!callback(&param1, &param2, realBase, image_size)) {
				kdmLog(L"[-] Callback returns false, failed!" << std::endl);
				kernel_image_base = realBase;
				break;
			}
		}

		NTSTATUS status = 0;
		if (kdmapper_entry_via_io_create_driver) {
			kdmLog(L"[<] Invoking DriverEntry through IoCreateDriver in a kernel system thread" << std::endl);
			if (!CallEntryViaKernelThread(&status, address_of_entry_point)) {
				kdmLog(L"[-] Failed to invoke the entry point in a kernel thread" << std::endl);
				kernel_image_base = realBase;
				break;
			}
		}
		else if (!intel_driver::CallKernelFunction(&status, address_of_entry_point, (PassAllocationAddressAsFirstParam ? realBase : param1), param2)) {
			kdmLog(L"[-] Failed to call driver entry" << std::endl);
			kernel_image_base = realBase;
			break;
		}

		if (exitCode)
			*exitCode = status;

		kdmLog(L"[+] DriverEntry returned 0x" << std::hex << status << std::endl);

		// Free memory
		if (free) {
			kdmLog(L"[+] Freeing memory" << std::endl);
			bool free_status = false;

			if (mode == AllocationMode::AllocateIndependentPages)
			{
				free_status = intel_driver::MmFreeIndependentPages(realBase, image_size);
			}
			else {
				free_status = intel_driver::FreePool(realBase);
			}

			if (free_status) {
				kdmLog(L"[+] Memory has been released" << std::endl);
			}
			else {
				kdmLog(L"[-] WARNING: Failed to free memory!" << std::endl);
			}
		}



		VirtualFree(local_image_base, 0, MEM_RELEASE);
		return realBase;

	} while (false);


	VirtualFree(local_image_base, 0, MEM_RELEASE);

	kdmLog(L"[+] Freeing memory" << std::endl);
	bool free_status = false;

	if (mode == AllocationMode::AllocateIndependentPages)
	{
		free_status = intel_driver::MmFreeIndependentPages(kernel_image_base, image_size);
	}
	else {
		free_status = intel_driver::FreePool(kernel_image_base);
	}

	if (free_status) {
		kdmLog(L"[+] Memory has been released" << std::endl);
	}
	else {
		kdmLog(L"[-] WARNING: Failed to free memory!" << std::endl);
	}

	return 0;
}


