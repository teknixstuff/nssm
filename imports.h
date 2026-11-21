#ifndef IMPORTS_H
#define IMPORTS_H

/* Some functions don't have decorated versions. */
#ifdef UNICODE
#define QUERYFULLPROCESSIMAGENAME_EXPORT "QueryFullProcessImageNameW"
#else
#define QUERYFULLPROCESSIMAGENAME_EXPORT "QueryFullProcessImageNameA"
#endif

#ifndef PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
#define PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE 0x00020016
#endif

typedef struct _STARTUPINFOEXA {
  STARTUPINFOA StartupInfo;
  LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
} STARTUPINFOEXA, * LPSTARTUPINFOEXA;

typedef struct _STARTUPINFOEXW {
  STARTUPINFOW StartupInfo;
  LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
} STARTUPINFOEXW, * LPSTARTUPINFOEXW;

#ifdef UNICODE
typedef STARTUPINFOEXW STARTUPINFOEX;
typedef LPSTARTUPINFOEXW LPSTARTUPINFOEX;
#else
typedef STARTUPINFOEXA STARTUPINFOEX;
typedef LPSTARTUPINFOEXA LPSTARTUPINFOEX;
#endif

typedef BOOL (WINAPI *AttachConsole_ptr)(DWORD);
typedef BOOL (WINAPI *SleepConditionVariableCS_ptr)(PCONDITION_VARIABLE, PCRITICAL_SECTION, DWORD);
typedef BOOL (WINAPI *QueryFullProcessImageName_ptr)(HANDLE, unsigned long, LPTSTR, unsigned long *);
typedef void (WINAPI *WakeConditionVariable_ptr)(PCONDITION_VARIABLE);
typedef BOOL (WINAPI *CreateWellKnownSid_ptr)(WELL_KNOWN_SID_TYPE, SID *, SID *, unsigned long *);
typedef BOOL (WINAPI *IsWellKnownSid_ptr)(SID *, WELL_KNOWN_SID_TYPE);
typedef BOOL(WINAPI* InitializeProcThreadAttributeList_ptr)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
typedef BOOL(WINAPI* UpdateProcThreadAttribute_ptr)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PSIZE_T);
typedef VOID(WINAPI* DeleteProcThreadAttributeList_ptr)(LPPROC_THREAD_ATTRIBUTE_LIST);
typedef BOOL(WINAPI* CancelIoEx_ptr)(HANDLE, LPOVERLAPPED);
typedef HRESULT(WINAPI* CreatePseudoConsole_ptr)(COORD, HANDLE, HANDLE, DWORD, HPCON*);
typedef HRESULT(WINAPI* ResizePseudoConsole_ptr)(HPCON, COORD);
typedef VOID(WINAPI* ClosePseudoConsole_ptr)(HPCON);

typedef struct {
  HMODULE kernel32;
  HMODULE advapi32;
  AttachConsole_ptr AttachConsole;
  SleepConditionVariableCS_ptr SleepConditionVariableCS;
  QueryFullProcessImageName_ptr QueryFullProcessImageName;
  WakeConditionVariable_ptr WakeConditionVariable;
  CreateWellKnownSid_ptr CreateWellKnownSid;
  IsWellKnownSid_ptr IsWellKnownSid;
  InitializeProcThreadAttributeList_ptr InitializeProcThreadAttributeList;
  UpdateProcThreadAttribute_ptr UpdateProcThreadAttribute;
  DeleteProcThreadAttributeList_ptr DeleteProcThreadAttributeList;
  CancelIoEx_ptr CancelIoEx;
  CreatePseudoConsole_ptr CreatePseudoConsole;
  ResizePseudoConsole_ptr ResizePseudoConsole;
  ClosePseudoConsole_ptr ClosePseudoConsole;
} imports_t;

HMODULE get_dll(const TCHAR *, unsigned long *);
FARPROC get_import(HMODULE, const char *, unsigned long *);
int get_imports();
void free_imports();

#endif
