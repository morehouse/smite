/// Preloaded crash handler for JVM-based targets (Eclair).
///
/// Overrides exit() and abort() to report crashes before the JVM's atexit
/// handlers close TCP sockets. Without this, there is a race condition:
/// exit() runs atexit handlers that close the TCP socket (which the scenario
/// detects), but the process hasn't become a zombie yet, so is_running()
/// returns true and the crash is missed.
///
/// JVM exit paths and what they call:
///   Runtime.halt(n)     -> exit(n)
///   System.exit(n)      -> exit(n)
///   SIGTERM             -> exit(143)
///   JVM crash (SIGSEGV) -> abort()
///   Fatal JVM error     -> _exit(1)
///
/// Crashes are reported for ALL exit codes (including code 0). Any exit
/// triggered by a peer message is a bug, since an offline LN node cannot
/// enforce contracts on chain. Exits that occur during node startup are not
/// reported since Eclair runs various external binaries during startup that
/// are expected to exit.
///
/// Note that our fuzz scenarios send SIGTERM to shut down LN nodes when done
/// running in local mode. The JVM calls exit(143) in this case, which triggers
/// a crash report. The fuzz scenarios never check for these crash reports, so
/// no false positives are ever reported.
///
/// Compile-time options:
///   -DENABLE_NYX  Report crashes via Nyx hypercalls instead of crash file.
///   -DNO_PT_NYX   Use port I/O hypercalls (must match nyx-agent.c build).
///
/// Compile (local mode):
///   gcc -shared -fPIC jvm-crash-handler.c -o jvm-crash-handler.so
///
/// Compile (Nyx mode):
///   gcc -shared -fPIC -DENABLE_NYX -DNO_PT_NYX \
///       jvm-crash-handler.c -o nyx-jvm-crash-handler.so

#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifdef ENABLE_NYX
#include "nyx.h"
#endif

// Must match STARTUP_COMPLETE_MARKER in smite/src/runners.rs.
#define STARTUP_COMPLETE_MARKER "/tmp/smite-startup-complete"

static int startup_complete(void) {
  return access(STARTUP_COMPLETE_MARKER, F_OK) == 0;
}

static void report_crash(const char *reason, int code) {
  char buf[256];
  int len = snprintf(buf, sizeof(buf), "%s (code %d)\n", reason, code);
  if (len <= 0)
    return;

#ifdef ENABLE_NYX
  kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uintptr_t)buf);
  __builtin_unreachable();
#else
  int fd = open("/tmp/smite-crash.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd >= 0) {
    write(fd, buf, len);
    close(fd);
  }
#endif
}

// Override exit(). The JVM routes all normal termination through exit().
void exit(int status) {
  if (startup_complete())
    report_crash("exit", status);
  syscall(SYS_exit_group, status);
  __builtin_unreachable();
}

// Override abort(). The JVM calls abort() for crash dumps (SIGSEGV, etc.).
void abort(void) {
  if (startup_complete())
    report_crash("abort", 134);
  syscall(SYS_exit_group, 134);
  __builtin_unreachable();
}
