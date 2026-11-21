#ifndef WIN64_MIN_H
#define WIN64_MIN_H

typedef unsigned char      uint8_t;
typedef signed char        int8_t;
typedef unsigned short     uint16_t;
typedef short              int16_t;
typedef unsigned int       uint32_t;
typedef int                int32_t;
typedef unsigned long long uint64_t;
typedef long long          int64_t;
typedef unsigned long long size_t;

typedef uint32_t DWORD;
typedef int32_t  BOOL;
typedef int32_t  HRESULT;
typedef uint64_t HANDLE;
typedef uint64_t HMODULE;
typedef uint64_t HWND;

#define NULL ((void *)0)
#define TRUE 1
#define FALSE 0
#define DLL_PROCESS_ATTACH 1
#define INFINITE 0xFFFFFFFFu

typedef struct { char opaque[40]; } CRITICAL_SECTION;
typedef DWORD (*LPTHREAD_START_ROUTINE)(void *param);

__declspec(dllimport) HANDLE   GetProcessHeap(void);
__declspec(dllimport) void    *HeapAlloc(HANDLE hHeap, DWORD flags, size_t bytes);
__declspec(dllimport) BOOL     HeapFree(HANDLE hHeap, DWORD flags, void *mem);
__declspec(dllimport) void    *VirtualAlloc(void *addr, size_t size, DWORD type, DWORD prot);
__declspec(dllimport) BOOL     VirtualFree(void *addr, size_t size, DWORD type);
__declspec(dllimport) BOOL     QueryPerformanceFrequency(int64_t *freq);
__declspec(dllimport) BOOL     QueryPerformanceCounter(int64_t *cnt);
__declspec(dllimport) DWORD    TlsAlloc(void);
__declspec(dllimport) BOOL     TlsSetValue(DWORD idx, void *val);
__declspec(dllimport) void    *TlsGetValue(DWORD idx);
__declspec(dllimport) BOOL     TlsFree(DWORD idx);
__declspec(dllimport) void     InitializeCriticalSection(CRITICAL_SECTION *cs);
__declspec(dllimport) void     EnterCriticalSection(CRITICAL_SECTION *cs);
__declspec(dllimport) void     LeaveCriticalSection(CRITICAL_SECTION *cs);
__declspec(dllimport) void     DeleteCriticalSection(CRITICAL_SECTION *cs);
__declspec(dllimport) HANDLE   CreateThread(void *sa, size_t stk, LPTHREAD_START_ROUTINE fn, void *param, DWORD flags, DWORD *tid);
__declspec(dllimport) DWORD    WaitForSingleObject(HANDLE h, DWORD ms);
__declspec(dllimport) BOOL     CloseHandle(HANDLE h);
__declspec(dllimport) HMODULE  GetModuleHandleA(const char *name);
__declspec(dllimport) void    *GetProcAddress(HMODULE mod, const char *name);
__declspec(dllimport) void     ExitProcess(DWORD code);

__declspec(dllimport) int      printf(const char *fmt, ...);
__declspec(dllimport) void     qsort(void *base, size_t n, size_t sz, int (*cmp)(const void *, const void *));
__declspec(dllimport) void    *memset(void *p, int c, size_t n);

#endif
