#include "nssm.h"

extern unsigned long tls_index;
extern bool is_admin;
extern imports_t imports;

static TCHAR unquoted_imagepath[PATH_LENGTH];
static TCHAR imagepath[PATH_LENGTH];
static TCHAR imageargv0[PATH_LENGTH];

void nssm_exit(int status) {
  free_imports();
  unsetup_utf8();
  exit(status);
}

/* Are two strings case-insensitively equivalent? */
int str_equiv(const TCHAR *a, const TCHAR *b) {
  size_t len = _tcslen(a);
  if (_tcslen(b) != len) return 0;
  if (_tcsnicmp(a, b, len)) return 0;
  return 1;
}

/* Convert a string to a number. */
int str_number(const TCHAR *string, unsigned long *number, TCHAR **bogus) {
  if (! string) return 1;

  *number = _tcstoul(string, bogus, 0);
  if (**bogus) return 2;

  return 0;
}

/* User requested us to print our version. */
static bool is_version(const TCHAR *s) {
  if (! s || ! *s) return false;
  /* /version */
  if (*s == '/') s++;
  else if (*s == '-') {
    /* -v, -V, -version, --version */
    s++;
    if (*s == '-') s++;
    else if (str_equiv(s, _T("v"))) return true;
  }
  if (str_equiv(s, _T("version"))) return true;
  return false;
}

int str_number(const TCHAR *string, unsigned long *number) {
  TCHAR *bogus;
  return str_number(string, number, &bogus);
}

/* Does a char need to be escaped? */
static bool needs_escape(const TCHAR c) {
  if (c == _T('"')) return true;
  if (c == _T('&')) return true;
  if (c == _T('%')) return true;
  if (c == _T('^')) return true;
  if (c == _T('<')) return true;
  if (c == _T('>')) return true;
  if (c == _T('|')) return true;
  return false;
}

/* Does a char need to be quoted? */
static bool needs_quote(const TCHAR c) {
  if (c == _T(' ')) return true;
  if (c == _T('\t')) return true;
  if (c == _T('\n')) return true;
  if (c == _T('\v')) return true;
  if (c == _T('"')) return true;
  if (c == _T('*')) return true;
  return needs_escape(c);
}

/* https://blogs.msdn.microsoft.com/twistylittlepassagesallalike/2011/04/23/everyone-quotes-command-line-arguments-the-wrong-way/ */
/* http://www.robvanderwoude.com/escapechars.php */
int quote(const TCHAR *unquoted, TCHAR *buffer, size_t buflen) {
  size_t i, j, n;
  size_t len = _tcslen(unquoted);
  if (len > buflen - 1) return 1;

  bool escape = false;
  bool quotes = false;

  for (i = 0; i < len; i++) {
    if (needs_escape(unquoted[i])) {
      escape = quotes = true;
      break;
    }
    if (needs_quote(unquoted[i])) quotes = true;
  }
  if (! quotes) {
    memmove(buffer, unquoted, (len + 1) * sizeof(TCHAR));
    return 0;
  }

  /* "" */
  size_t quoted_len = 2;
  if (escape) quoted_len += 2;
  for (i = 0; ; i++) {
    n = 0;

    while (i != len && unquoted[i] == _T('\\')) {
      i++;
      n++;
    }

    if (i == len) {
      quoted_len += n * 2;
      break;
    }
    else if (unquoted[i] == _T('"')) quoted_len += n * 2 + 2;
    else quoted_len += n + 1;
    if (needs_escape(unquoted[i])) quoted_len += n;
  }
  if (quoted_len > buflen - 1) return 1;

  TCHAR *s = buffer;
  if (escape) *s++ = _T('^');
  *s++ = _T('"');

  for (i = 0; ; i++) {
    n = 0;

    while (i != len && unquoted[i] == _T('\\')) {
      i++;
      n++;
    }

    if (i == len) {
      for (j = 0; j < n * 2; j++) {
        if (escape) *s++ = _T('^');
        *s++ = _T('\\');
      }
      break;
    }
    else if (unquoted[i] == _T('"')) {
      for (j = 0; j < n * 2 + 1; j++) {
        if (escape) *s++ = _T('^');
        *s++ = _T('\\');
      }
      if (escape && needs_escape(unquoted[i])) *s++ = _T('^');
      *s++ = unquoted[i];
    }
    else {
      for (j = 0; j < n; j++) {
        if (escape) *s++ = _T('^');
        *s++ = _T('\\');
      }
      if (escape && needs_escape(unquoted[i])) *s++ = _T('^');
      *s++ = unquoted[i];
    }
  }
  if (escape) *s++ = _T('^');
  *s++ = _T('"');
  *s++ = _T('\0');

  return 0;
}

/* Remove basename of a path. */
void strip_basename(TCHAR *buffer) {
  size_t len = _tcslen(buffer);
  size_t i;
  for (i = len; i && buffer[i] != _T('\\') && buffer[i] != _T('/'); i--);
  /* X:\ is OK. */
  if (i && buffer[i - 1] == _T(':')) i++;
  buffer[i] = _T('\0');
}

/* How to use me correctly */
int usage(int ret) {
  if ((! GetConsoleWindow() || ! GetStdHandle(STD_OUTPUT_HANDLE)) && GetProcessWindowStation()) popup_message(0, MB_OK, NSSM_MESSAGE_USAGE, NSSM_VERSION, NSSM_CONFIGURATION, NSSM_DATE);
  else print_message(stderr, NSSM_MESSAGE_USAGE, NSSM_VERSION, NSSM_CONFIGURATION, NSSM_DATE);
  return(ret);
}

void check_admin() {
  is_admin = false;

  /* Lifted from MSDN examples */
  PSID AdministratorsGroup;
  SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
  if (! AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup)) return;
  CheckTokenMembership(0, AdministratorsGroup, /*XXX*/(PBOOL) &is_admin);
  FreeSid(AdministratorsGroup);
}

static int elevate(int argc, TCHAR **argv, unsigned long message) {
  print_message(stderr, message);

  SHELLEXECUTEINFO sei;
  ZeroMemory(&sei, sizeof(sei));
  sei.cbSize = sizeof(sei);
  sei.lpVerb = _T("runas");
  sei.lpFile = (TCHAR *) nssm_imagepath();

  TCHAR *args = (TCHAR *) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, EXE_LENGTH * sizeof(TCHAR));
  if (! args) {
    print_message(stderr, NSSM_MESSAGE_OUT_OF_MEMORY, _T("GetCommandLine()"), _T("elevate()"));
    return 111;
  }

  /* Get command line, which includes the path to NSSM, and skip that part. */
  _sntprintf_s(args, EXE_LENGTH, _TRUNCATE, _T("%s"), GetCommandLine());
  size_t s = _tcslen(argv[0]) + 1;
  if (args[0] == _T('"')) s += 2;
  while (isspace(args[s])) s++;

  sei.lpParameters = args + s;
  sei.nShow = SW_SHOW;

  unsigned long exitcode = 0;
  if (! ShellExecuteEx(&sei)) exitcode = 100;

  HeapFree(GetProcessHeap(), 0, (void *) args);
  return exitcode;
}

int num_cpus() {
  DWORD_PTR i, affinity, system_affinity;
  if (! GetProcessAffinityMask(GetCurrentProcess(), &affinity, &system_affinity)) return 64;
  for (i = 0; system_affinity & (1LL << i); i++) if (i == 64) break;
  return (int) i;
}

const TCHAR *nssm_unquoted_imagepath() {
  return unquoted_imagepath;
}

const TCHAR *nssm_imagepath() {
  return imagepath;
}

const TCHAR *nssm_exe() {
  return imageargv0;
}

typedef struct {
  HANDLE pipe;
  HANDLE stdin_h;
  HANDLE stdout_h;
  DWORD orig_in_mode;
  DWORD orig_out_mode;
  bool have_in_mode;
  bool have_out_mode;
} attach_ctx_t;

static void restore_attach_console(attach_ctx_t* ctx) {
  if (!ctx) return;
  if (ctx->have_out_mode && ctx->stdout_h != INVALID_HANDLE_VALUE) {
    DWORD written = 0;
    WriteFile(ctx->stdout_h, "\x1b[0m", 4, &written, NULL);
    SetConsoleMode(ctx->stdout_h, ctx->orig_out_mode);
  }
  if (ctx->have_in_mode && ctx->stdin_h != INVALID_HANDLE_VALUE) {
    SetConsoleMode(ctx->stdin_h, ctx->orig_in_mode);
  }
}

static bool write_all_overlapped(HANDLE h, const char* buf, DWORD len, HANDLE ev) {
  DWORD sent = 0;
  while (sent < len) {
    OVERLAPPED ov;
    ZeroMemory(&ov, sizeof(ov));
    ov.hEvent = ev;
    ResetEvent(ev);

    DWORD written = 0;
    if (!WriteFile(h, buf + sent, len - sent, &written, &ov)) {
      if (GetLastError() != ERROR_IO_PENDING) return false;
      if (!GetOverlappedResult(h, &ov, &written, TRUE)) return false;
    }
    if (written == 0) return false;
    sent += written;
  }
  return true;
}

static bool write_all_sync(HANDLE h, const char* buf, DWORD len) {
  DWORD sent = 0;
  while (sent < len) {
    DWORD written = 0;
    if (!WriteFile(h, buf + sent, len - sent, &written, NULL) || written == 0) {
      return false;
    }
    sent += written;
  }
  return true;
}

int attach_conpty_service(const TCHAR* service_name) {
  TCHAR pipe_name[MAX_PATH];
  _sntprintf_s(pipe_name, _countof(pipe_name), _TRUNCATE, _T("\\\\.\\pipe\\nssm-conpty-%s"), service_name);

  HANDLE pipe = CreateFile(
    pipe_name,
    GENERIC_READ | GENERIC_WRITE,
    0,
    NULL,
    OPEN_EXISTING,
    FILE_FLAG_OVERLAPPED,
    NULL);
  if (pipe == INVALID_HANDLE_VALUE) {
    _ftprintf(stderr, _T("%s: %s\n"), pipe_name, error_string(GetLastError()));
    return 1;
  }

  HANDLE read_ev = CreateEvent(NULL, TRUE, FALSE, NULL);
  HANDLE write_ev = CreateEvent(NULL, TRUE, FALSE, NULL);
  if (!read_ev || !write_ev) {
    if (read_ev) CloseHandle(read_ev);
    if (write_ev) CloseHandle(write_ev);
    CloseHandle(pipe);
    return 1;
  }

  attach_ctx_t ctx;
  ZeroMemory(&ctx, sizeof(ctx));
  ctx.pipe = pipe;
  ctx.stdin_h = GetStdHandle(STD_INPUT_HANDLE);
  ctx.stdout_h = GetStdHandle(STD_OUTPUT_HANDLE);

  if (ctx.stdin_h != INVALID_HANDLE_VALUE && GetConsoleMode(ctx.stdin_h, &ctx.orig_in_mode)) {
    ctx.have_in_mode = true;
    DWORD mode = ctx.orig_in_mode;
    mode &= ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT | ENABLE_QUICK_EDIT_MODE);
    mode |= ENABLE_EXTENDED_FLAGS | ENABLE_VIRTUAL_TERMINAL_INPUT;
    SetConsoleMode(ctx.stdin_h, mode);
  }

  if (ctx.stdout_h != INVALID_HANDLE_VALUE && GetConsoleMode(ctx.stdout_h, &ctx.orig_out_mode)) {
    ctx.have_out_mode = true;
    SetConsoleMode(ctx.stdout_h, ctx.orig_out_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
  }

  char out_buf[4096];
  OVERLAPPED rov;
  ZeroMemory(&rov, sizeof(rov));
  rov.hEvent = read_ev;
  bool read_pending = false;

  HANDLE waits[2];
  DWORD wait_count = 0;
  waits[wait_count++] = read_ev;
  if (ctx.stdin_h != INVALID_HANDLE_VALUE) waits[wait_count++] = ctx.stdin_h;

  bool done = false;
  while (!done) {
    if (!read_pending) {
      ResetEvent(read_ev);
      ZeroMemory(&rov, sizeof(rov));
      rov.hEvent = read_ev;

      DWORD n = 0;
      if (ReadFile(pipe, out_buf, sizeof(out_buf), &n, &rov)) {
        if (n == 0 || !write_all_sync(ctx.stdout_h, out_buf, n)) break;
        continue;
      }
      if (GetLastError() != ERROR_IO_PENDING) break;
      read_pending = true;
    }

    DWORD wr = WaitForMultipleObjects(wait_count, waits, FALSE, INFINITE);
    if (wr == WAIT_FAILED) break;

    DWORD idx = wr - WAIT_OBJECT_0;
    if (idx >= wait_count) continue;

    if (waits[idx] == read_ev) {
      DWORD n = 0;
      if (!GetOverlappedResult(pipe, &rov, &n, FALSE) || n == 0) break;
      read_pending = false;
      if (!write_all_sync(ctx.stdout_h, out_buf, n)) break;
    } else if (waits[idx] == ctx.stdin_h) {
      DWORD nev = 0;
      while (!done && GetNumberOfConsoleInputEvents(ctx.stdin_h, &nev) && nev > 0) {
        INPUT_RECORD peek;
        DWORD peeked = 0;
        if (!PeekConsoleInputW(ctx.stdin_h, &peek, 1, &peeked) || peeked == 0) {
          break;
        }

        if (peek.EventType != KEY_EVENT || !peek.Event.KeyEvent.bKeyDown) {
          INPUT_RECORD discard;
          DWORD dropped = 0;
          ReadConsoleInputW(ctx.stdin_h, &discard, 1, &dropped);
          continue;
        }

        char ch = 0;
        DWORD n = 0;
        if (!ReadFile(ctx.stdin_h, &ch, 1, &n, NULL) || n == 0) {
          done = true;
          break;
        }

        if (ch == 0x1D) { /* Ctrl+] */
          done = true;
          break;
        }

        if (!write_all_overlapped(pipe, &ch, 1, write_ev)) {
          done = true;
          break;
        }
      }
    }
  }

  if (read_pending) {
    CancelIo(pipe);
    DWORD dummy = 0;
    GetOverlappedResult(pipe, &rov, &dummy, TRUE);
  }

  CloseHandle(read_ev);
  CloseHandle(write_ev);
  CloseHandle(pipe);
  restore_attach_console(&ctx);
  return 0;
}

int _tmain(int argc, TCHAR **argv) {
  if (check_console()) setup_utf8();

  /* Remember if we are admin */
  check_admin();

  /* Set up function pointers. */
  if (get_imports()) nssm_exit(111);

  /* Remember our path for later. */
  _sntprintf_s(imageargv0, _countof(imageargv0), _TRUNCATE, _T("%s"), argv[0]);
  PathQuoteSpaces(imageargv0);
  GetModuleFileName(0, unquoted_imagepath, _countof(unquoted_imagepath));
  GetModuleFileName(0, imagepath, _countof(imagepath));
  PathQuoteSpaces(imagepath);

  /* Elevate */
  if (argc > 1) {
    /*
      Valid commands are:
      start, stop, pause, continue, install, edit, get, set, reset, unset, remove
      status, statuscode, rotate, list, processes, version
    */
    if (is_version(argv[1])) {
      _tprintf(_T("%s %s %s %s\n"), NSSM, NSSM_VERSION, NSSM_CONFIGURATION, NSSM_DATE);
      nssm_exit(0);
    }
    if (str_equiv(argv[1], _T("start"))) nssm_exit(control_service(NSSM_SERVICE_CONTROL_START, argc - 2, argv + 2));
    if (str_equiv(argv[1], _T("stop"))) nssm_exit(control_service(SERVICE_CONTROL_STOP, argc - 2, argv + 2));
    if (str_equiv(argv[1], _T("restart"))) {
      int ret = control_service(SERVICE_CONTROL_STOP, argc - 2, argv + 2);
      if (ret) nssm_exit(ret);
      nssm_exit(control_service(NSSM_SERVICE_CONTROL_START, argc - 2, argv + 2));
    }
    if (str_equiv(argv[1], _T("pause"))) nssm_exit(control_service(SERVICE_CONTROL_PAUSE, argc - 2, argv + 2));
    if (str_equiv(argv[1], _T("continue"))) nssm_exit(control_service(SERVICE_CONTROL_CONTINUE, argc - 2, argv + 2));
    if (str_equiv(argv[1], _T("status"))) nssm_exit(control_service(SERVICE_CONTROL_INTERROGATE, argc - 2, argv + 2));
    if (str_equiv(argv[1], _T("statuscode"))) nssm_exit(control_service(SERVICE_CONTROL_INTERROGATE, argc - 2, argv + 2, true));
    if (str_equiv(argv[1], _T("rotate"))) nssm_exit(control_service(NSSM_SERVICE_CONTROL_ROTATE, argc - 2, argv + 2));
    if (str_equiv(argv[1], _T("install"))) {
      if (! is_admin) nssm_exit(elevate(argc, argv, NSSM_MESSAGE_NOT_ADMINISTRATOR_CANNOT_INSTALL));
      create_messages();
      nssm_exit(pre_install_service(argc - 2, argv + 2));
    }
    if (str_equiv(argv[1], _T("edit")) || str_equiv(argv[1], _T("get")) || str_equiv(argv[1], _T("set")) || str_equiv(argv[1], _T("reset")) || str_equiv(argv[1], _T("unset")) || str_equiv(argv[1], _T("dump"))) {
      int ret = pre_edit_service(argc - 1, argv + 1);
      if (ret == 3 && ! is_admin && argc == 3) nssm_exit(elevate(argc, argv, NSSM_MESSAGE_NOT_ADMINISTRATOR_CANNOT_EDIT));
      /* There might be a password here. */
      for (int i = 0; i < argc; i++) SecureZeroMemory(argv[i], _tcslen(argv[i]) * sizeof(TCHAR));
      nssm_exit(ret);
    }
    if (str_equiv(argv[1], _T("list"))) nssm_exit(list_nssm_services(argc - 2, argv + 2));
    if (str_equiv(argv[1], _T("processes"))) nssm_exit(service_process_tree(argc - 2, argv + 2));
    if (str_equiv(argv[1], _T("remove"))) {
      if (! is_admin) nssm_exit(elevate(argc, argv, NSSM_MESSAGE_NOT_ADMINISTRATOR_CANNOT_REMOVE));
      nssm_exit(pre_remove_service(argc - 2, argv + 2));
    }
    if (str_equiv(argv[1], _T("attach"))) {
      if (argc < 3) nssm_exit(usage(1));
      nssm_exit(attach_conpty_service(argv[2]));
    }
  }

  /* Thread local storage for error message buffer */
  tls_index = TlsAlloc();

  /* Register messages */
  if (is_admin) create_messages();

  /*
    Optimisation for Windows 2000:
    When we're run from the command line the StartServiceCtrlDispatcher() call
    will time out after a few seconds on Windows 2000.  On newer versions the
    call returns instantly.  Check for stdin first and only try to call the
    function if there's no input stream found.  Although it's possible that
    we're running with input redirected it's much more likely that we're
    actually running as a service.
    This will save time when running with no arguments from a command prompt.
  */
  if (! GetStdHandle(STD_INPUT_HANDLE)) {
    /* Start service magic */
    SERVICE_TABLE_ENTRY table[] = { { NSSM, service_main }, { 0, 0 } };
    if (! StartServiceCtrlDispatcher(table)) {
      unsigned long error = GetLastError();
      /* User probably ran nssm with no argument */
      if (error == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) nssm_exit(usage(1));
      log_event(EVENTLOG_ERROR_TYPE, NSSM_EVENT_DISPATCHER_FAILED, error_string(error), 0);
      nssm_exit(100);
    }
  }
  else nssm_exit(usage(1));

  /* And nothing more to do */
  nssm_exit(0);
}
