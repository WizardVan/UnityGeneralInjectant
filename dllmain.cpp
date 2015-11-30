// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "monotype.h"
#include "dllmain.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		CreateThread(NULL, 0, StartAddress, NULL, 0, NULL);
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

DWORD WINAPI StartAddress(LPVOID lpParam)
{
	Sleep(4000);
	HMODULE hMono;
	hMono = GetModuleHandle(TEXT("mono.dll"));
	if (hMono != NULL)
	{
		mono_domain_assembly_open = (mono_domain_assembly_open_t)GetProcAddress(hMono, "mono_domain_assembly_open");
		mono_jit_exec = (mono_jit_exec_t)GetProcAddress(hMono, "mono_jit_exec");
		mono_domain_get = (mono_domain_get_t)GetProcAddress(hMono, "mono_domain_get");
		mono_class_from_name = (mono_class_from_name_t)GetProcAddress(hMono, "mono_class_from_name");
		mono_class_init = (mono_class_init_t)GetProcAddress(hMono, "mono_class_init");
		mono_class_get_method_from_name = (mono_class_get_method_from_name_t)GetProcAddress(hMono, "mono_class_get_method_from_name");
		mono_runtime_invoke = (mono_runtime_invoke_t)GetProcAddress(hMono, "mono_runtime_invoke");
		mono_object_new = (mono_object_new_t)GetProcAddress(hMono, "mono_object_new");
		mono_runtime_object_init = (mono_runtime_object_init_t)GetProcAddress(hMono, "mono_runtime_object_init");
		mono_security_set_mode = (mono_security_set_mode_t)GetProcAddress(hMono, "mono_security_set_mode");
		mono_security_set_core_clr_platform_callback = (mono_security_set_core_clr_platform_callback_t)GetProcAddress(hMono, "mono_security_set_core_clr_platform_callback");
	}
	return true;

}