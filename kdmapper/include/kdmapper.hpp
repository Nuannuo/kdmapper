#pragma once

#include <Windows.h>
#include <winternl.h>   // NTSTATUS
#include <ntstatus.h>   // STATUS_* 常量

namespace kdmapper
{
	enum class AllocationMode
	{
		AllocatePool,
		AllocateIndependentPages
	};

	typedef bool (*mapCallback)(ULONG64* param1, ULONG64* param2, ULONG64 allocationPtr, ULONG64 allocationSize);

	//Note: if you set PassAllocationAddressAsFirstParam as true, param1 will be ignored
	ULONG64 MapDriver(BYTE* data, ULONG64 param1 = 0, ULONG64 param2 = 0, bool free = false, bool destroyHeader = true, AllocationMode mode = AllocationMode::AllocatePool, bool PassAllocationAddressAsFirstParam = false, mapCallback callback = nullptr, NTSTATUS* exitCode = nullptr);

	/*
	 * Default: call DriverEntry(NULL, NULL) directly.
	 * Enabled: call IoCreateDriver(NULL, DriverEntry) instead, so the I/O
	 * manager hands the driver a real DRIVER_OBJECT and a real registry path.
	 * Required by drivers that dereference DriverObject (for example TitanHide,
	 * which calls IoCreateDevice on it).
	 */
	void SetEntryViaIoCreateDriver(bool enabled);
}