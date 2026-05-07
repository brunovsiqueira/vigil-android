/**
 * proc_reader.c
 *
 * Native /proc/self/maps reading using direct syscalls.
 *
 * Why direct syscalls?
 * --------------------
 * Frida and similar instrumentation frameworks work by hooking libc functions
 * such as open(), read(), fopen(), fgets(), access(), etc. When these hooked
 * functions are called, the framework can intercept the call, modify arguments,
 * or alter return values — for example, hiding specific entries from
 * /proc/self/maps to conceal injected libraries.
 *
 * By invoking the kernel directly via syscall(), we bypass the libc layer
 * entirely, making it significantly harder for userspace hooks to tamper with
 * our file I/O. This is a defense-in-depth measure and not foolproof against
 * kernel-level instrumentation, but it defeats the most common hooking
 * techniques used by Frida, Xposed, and similar tools.
 */

#include <jni.h>
#include <android/log.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <sys/syscall.h>
#include <errno.h>

#define TAG "VigilNative"

#define LOG_D(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOG_W(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOG_E(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* Buffer size for reading /proc/self/maps (64 KB). */
#define MAPS_BUF_SIZE (64 * 1024)

/* Maximum total size we are willing to accumulate (512 KB).
 * /proc/self/maps on a typical app is well under this limit. */
#define MAPS_MAX_SIZE (512 * 1024)

/* --------------------------------------------------------------------------
 * Direct syscall wrappers
 *
 * These bypass libc's open/read/close so that Frida hooks on those functions
 * have no effect on our file operations.
 * -------------------------------------------------------------------------- */

/**
 * Open a file using the openat(2) syscall directly.
 * Uses AT_FDCWD so that relative paths are resolved against cwd (though we
 * only use absolute paths in practice).
 */
static int vigil_openat(const char *path, int flags) {
    return (int)syscall(__NR_openat, AT_FDCWD, path, flags);
}

/**
 * Read from a file descriptor using the read(2) syscall directly.
 */
static ssize_t vigil_read(int fd, void *buf, size_t count) {
    return syscall(__NR_read, fd, buf, count);
}

/**
 * Close a file descriptor using the close(2) syscall directly.
 */
static int vigil_close(int fd) {
    return (int)syscall(__NR_close, fd);
}

/* --------------------------------------------------------------------------
 * Helper: case-insensitive substring search
 *
 * We cannot rely on strcasestr() being available on all NDK / platform
 * versions, so we provide our own implementation.
 * -------------------------------------------------------------------------- */

/**
 * Convert a single character to lowercase (ASCII-only).
 */
static char to_lower(char c) {
    if (c >= 'A' && c <= 'Z') {
        return (char)(c + ('a' - 'A'));
    }
    return c;
}

/**
 * Case-insensitive substring search (ASCII-only).
 *
 * Returns a pointer to the first occurrence of `needle` in `haystack`,
 * ignoring case, or NULL if not found.
 */
static const char *vigil_strcasestr(const char *haystack, const char *needle) {
    if (needle == NULL || needle[0] == '\0') {
        return haystack;
    }

    size_t needle_len = strlen(needle);
    size_t haystack_len = strlen(haystack);

    if (needle_len > haystack_len) {
        return NULL;
    }

    size_t limit = haystack_len - needle_len;
    for (size_t i = 0; i <= limit; i++) {
        size_t j;
        for (j = 0; j < needle_len; j++) {
            if (to_lower(haystack[i + j]) != to_lower(needle[j])) {
                break;
            }
        }
        if (j == needle_len) {
            return &haystack[i];
        }
    }

    return NULL;
}

/* --------------------------------------------------------------------------
 * JNI: readProcMaps
 *
 * Reads the entire contents of /proc/self/maps via direct syscalls and
 * returns it as a Java String.
 * -------------------------------------------------------------------------- */

JNIEXPORT jstring JNICALL
Java_io_github_brunovsiqueira_vigil_detectors_NativeBridge_readProcMaps(
    JNIEnv *env, jclass clazz) {

    (void)clazz;

    int fd = vigil_openat("/proc/self/maps", O_RDONLY);
    if (fd < 0) {
        LOG_E("readProcMaps: failed to open /proc/self/maps (errno=%d)", errno);
        return NULL;
    }

    /*
     * Allocate a buffer to accumulate the full maps content.
     * We read in MAPS_BUF_SIZE chunks and grow as needed up to MAPS_MAX_SIZE.
     */
    char buf[MAPS_BUF_SIZE];
    char *result = NULL;
    size_t total = 0;
    size_t capacity = 0;

    for (;;) {
        ssize_t n = vigil_read(fd, buf, sizeof(buf));
        if (n < 0) {
            LOG_E("readProcMaps: read error (errno=%d)", errno);
            if (result != NULL) {
                free(result);
            }
            vigil_close(fd);
            return NULL;
        }
        if (n == 0) {
            break; /* EOF */
        }

        /* Ensure we have room in the accumulation buffer. */
        if (total + (size_t)n + 1 > capacity) {
            size_t new_cap = (capacity == 0) ? MAPS_BUF_SIZE : capacity * 2;
            if (new_cap > MAPS_MAX_SIZE) {
                new_cap = MAPS_MAX_SIZE;
            }
            if (total + (size_t)n + 1 > new_cap) {
                LOG_W("readProcMaps: /proc/self/maps exceeds max size, truncating");
                break;
            }
            char *new_buf = (char *)realloc(result, new_cap);
            if (new_buf == NULL) {
                LOG_E("readProcMaps: allocation failure");
                free(result);
                vigil_close(fd);
                return NULL;
            }
            result = new_buf;
            capacity = new_cap;
        }

        memcpy(result + total, buf, (size_t)n);
        total += (size_t)n;
    }

    vigil_close(fd);

    if (result == NULL || total == 0) {
        free(result);
        return (*env)->NewStringUTF(env, "");
    }

    /* Null-terminate the accumulated content. */
    result[total] = '\0';

    jstring jresult = (*env)->NewStringUTF(env, result);
    free(result);

    return jresult;
}

/* --------------------------------------------------------------------------
 * JNI: scanMapsForPattern
 *
 * Opens /proc/self/maps via direct syscall, reads it line by line (manually,
 * without fgets), and performs a case-insensitive search for the given
 * pattern. Returns JNI_TRUE if found, JNI_FALSE otherwise.
 * -------------------------------------------------------------------------- */

JNIEXPORT jboolean JNICALL
Java_io_github_brunovsiqueira_vigil_detectors_NativeBridge_scanMapsForPattern(
    JNIEnv *env, jclass clazz, jstring pattern) {

    (void)clazz;

    if (pattern == NULL) {
        return JNI_FALSE;
    }

    const char *native_pattern = (*env)->GetStringUTFChars(env, pattern, NULL);
    if (native_pattern == NULL) {
        return JNI_FALSE;
    }

    int fd = vigil_openat("/proc/self/maps", O_RDONLY);
    if (fd < 0) {
        LOG_E("scanMapsForPattern: failed to open /proc/self/maps (errno=%d)", errno);
        (*env)->ReleaseStringUTFChars(env, pattern, native_pattern);
        return JNI_FALSE;
    }

    /*
     * Manual line-by-line reading without fgets/stdio.
     *
     * We maintain a small read buffer and a line buffer. Data is read in
     * chunks from the fd; we then scan for newline characters to extract
     * individual lines, which are checked against the pattern.
     */
    char read_buf[4096];
    char line_buf[1024];
    size_t line_len = 0;
    jboolean found = JNI_FALSE;

    for (;;) {
        ssize_t n = vigil_read(fd, read_buf, sizeof(read_buf));
        if (n < 0) {
            LOG_E("scanMapsForPattern: read error (errno=%d)", errno);
            break;
        }
        if (n == 0) {
            /* EOF — check any remaining data in line_buf. */
            if (line_len > 0) {
                line_buf[line_len] = '\0';
                if (vigil_strcasestr(line_buf, native_pattern) != NULL) {
                    found = JNI_TRUE;
                }
            }
            break;
        }

        for (ssize_t i = 0; i < n; i++) {
            if (read_buf[i] == '\n') {
                /* End of line — null-terminate and check. */
                line_buf[line_len] = '\0';

                if (vigil_strcasestr(line_buf, native_pattern) != NULL) {
                    found = JNI_TRUE;
                    goto done;
                }

                line_len = 0;
            } else {
                if (line_len < sizeof(line_buf) - 1) {
                    line_buf[line_len++] = read_buf[i];
                }
                /* If line_len reaches the limit we silently truncate;
                 * maps lines are typically ~80-200 chars. */
            }
        }
    }

done:
    vigil_close(fd);
    (*env)->ReleaseStringUTFChars(env, pattern, native_pattern);

    return found;
}

/* --------------------------------------------------------------------------
 * JNI: fileExistsNative
 *
 * Checks whether a file exists using the faccessat(2) syscall directly,
 * bypassing libc's access() which can be hooked to hide files.
 * -------------------------------------------------------------------------- */

JNIEXPORT jboolean JNICALL
Java_io_github_brunovsiqueira_vigil_detectors_NativeBridge_fileExistsNative(
    JNIEnv *env, jclass clazz, jstring path) {

    (void)clazz;

    if (path == NULL) {
        return JNI_FALSE;
    }

    const char *native_path = (*env)->GetStringUTFChars(env, path, NULL);
    if (native_path == NULL) {
        return JNI_FALSE;
    }

    int result = (int)syscall(__NR_faccessat, AT_FDCWD, native_path, F_OK, 0);

    (*env)->ReleaseStringUTFChars(env, path, native_path);

    return (result == 0) ? JNI_TRUE : JNI_FALSE;
}

/* --------------------------------------------------------------------------
 * JNI: readProcFile
 *
 * Generic /proc file reader via direct syscalls.
 * Used for /proc/self/mountinfo, /proc/net/unix, /proc/self/status, etc.
 * -------------------------------------------------------------------------- */

JNIEXPORT jstring JNICALL
Java_io_github_brunovsiqueira_vigil_detectors_NativeBridge_readProcFile(
    JNIEnv *env, jclass clazz, jstring path) {

    (void)clazz;

    if (path == NULL) return NULL;

    const char *native_path = (*env)->GetStringUTFChars(env, path, NULL);
    if (native_path == NULL) return NULL;

    int fd = vigil_openat(native_path, O_RDONLY);
    if (fd < 0) {
        (*env)->ReleaseStringUTFChars(env, path, native_path);
        return NULL;
    }

    char *result = NULL;
    size_t total = 0;
    size_t capacity = 0;
    char buf[4096];

    for (;;) {
        ssize_t n = vigil_read(fd, buf, sizeof(buf));
        if (n <= 0) break;

        if (total + (size_t)n + 1 > capacity) {
            size_t new_cap = (capacity == 0) ? 8192 : capacity * 2;
            if (new_cap > MAPS_MAX_SIZE) break;
            char *new_buf = (char *)realloc(result, new_cap);
            if (new_buf == NULL) { free(result); vigil_close(fd); (*env)->ReleaseStringUTFChars(env, path, native_path); return NULL; }
            result = new_buf;
            capacity = new_cap;
        }
        memcpy(result + total, buf, (size_t)n);
        total += (size_t)n;
    }

    vigil_close(fd);
    (*env)->ReleaseStringUTFChars(env, path, native_path);

    if (result == NULL || total == 0) {
        free(result);
        return (*env)->NewStringUTF(env, "");
    }

    result[total] = '\0';
    jstring jresult = (*env)->NewStringUTF(env, result);
    free(result);
    return jresult;
}

/* --------------------------------------------------------------------------
 * JNI: detectOverlayFs
 *
 * Reads /proc/self/mountinfo via direct syscall and scans for overlayfs
 * mounts. KernelSU uses overlayfs with identifiers like "KSU" or
 * "overlay" to mount modules into app namespaces.
 *
 * Returns: comma-separated suspicious mount lines, or NULL if clean.
 * -------------------------------------------------------------------------- */

JNIEXPORT jstring JNICALL
Java_io_github_brunovsiqueira_vigil_detectors_NativeBridge_detectOverlayFs(
    JNIEnv *env, jclass clazz) {

    (void)clazz;

    int fd = vigil_openat("/proc/self/mountinfo", O_RDONLY);
    if (fd < 0) return NULL;

    char *content = NULL;
    size_t total = 0;
    size_t capacity = 0;
    char buf[4096];

    for (;;) {
        ssize_t n = vigil_read(fd, buf, sizeof(buf));
        if (n <= 0) break;
        if (total + (size_t)n + 1 > capacity) {
            size_t new_cap = (capacity == 0) ? 16384 : capacity * 2;
            if (new_cap > MAPS_MAX_SIZE) break;
            char *new_buf = (char *)realloc(content, new_cap);
            if (new_buf == NULL) { free(content); vigil_close(fd); return NULL; }
            content = new_buf;
            capacity = new_cap;
        }
        memcpy(content + total, buf, (size_t)n);
        total += (size_t)n;
    }
    vigil_close(fd);

    if (content == NULL || total == 0) {
        free(content);
        return NULL;
    }
    content[total] = '\0';

    /* Scan for overlayfs indicators:
     * - "overlay" filesystem type in mountinfo
     * - "KSU" in mount options (KernelSU meta-overlayfs)
     * - "lowerdir=" containing /data/adb (Magisk/KSU module mounts)
     */
    char findings[4096];
    size_t findings_len = 0;
    int found_count = 0;

    char *line = content;
    while (line != NULL && *line != '\0') {
        char *next = strchr(line, '\n');
        if (next != NULL) *next = '\0';

        int suspicious = 0;
        if (vigil_strcasestr(line, "overlay") != NULL) suspicious = 1;
        if (strstr(line, "KSU") != NULL) suspicious = 1;
        if (strstr(line, "lowerdir=") != NULL && strstr(line, "/data/adb") != NULL) suspicious = 1;

        if (suspicious && found_count < 5) {
            size_t line_len = strlen(line);
            if (findings_len + line_len + 2 < sizeof(findings)) {
                if (findings_len > 0) findings[findings_len++] = '\n';
                memcpy(findings + findings_len, line, line_len);
                findings_len += line_len;
                found_count++;
            }
        }

        if (next != NULL) { *next = '\n'; line = next + 1; }
        else break;
    }

    free(content);

    if (found_count == 0) return NULL;

    findings[findings_len] = '\0';
    return (*env)->NewStringUTF(env, findings);
}

/* --------------------------------------------------------------------------
 * JNI: detectMagiskUnixSockets
 *
 * Reads /proc/net/unix via direct syscall and scans for Magisk daemon
 * Unix domain sockets. Magisk creates UDS with 32-character random hex
 * names for IPC. This is what RootBeerFresh detects.
 *
 * Returns: comma-separated suspicious socket names, or NULL if clean.
 * -------------------------------------------------------------------------- */

JNIEXPORT jstring JNICALL
Java_io_github_brunovsiqueira_vigil_detectors_NativeBridge_detectMagiskUnixSockets(
    JNIEnv *env, jclass clazz) {

    (void)clazz;

    int fd = vigil_openat("/proc/net/unix", O_RDONLY);
    if (fd < 0) return NULL;

    char *content = NULL;
    size_t total = 0;
    size_t capacity = 0;
    char buf[4096];

    for (;;) {
        ssize_t n = vigil_read(fd, buf, sizeof(buf));
        if (n <= 0) break;
        if (total + (size_t)n + 1 > capacity) {
            size_t new_cap = (capacity == 0) ? 16384 : capacity * 2;
            if (new_cap > MAPS_MAX_SIZE) break;
            char *new_buf = (char *)realloc(content, new_cap);
            if (new_buf == NULL) { free(content); vigil_close(fd); return NULL; }
            content = new_buf;
            capacity = new_cap;
        }
        memcpy(content + total, buf, (size_t)n);
        total += (size_t)n;
    }
    vigil_close(fd);

    if (content == NULL || total == 0) {
        free(content);
        return NULL;
    }
    content[total] = '\0';

    /* Magisk daemon creates abstract Unix sockets with 32-char random hex names.
     * Format in /proc/net/unix: ... @<32 hex chars>
     * Normal Android sockets use descriptive names like @jdwp-control, @zygote, etc.
     * A 32+ char hex-only abstract socket name is highly suspicious.
     */
    char findings[2048];
    size_t findings_len = 0;
    int found_count = 0;

    char *line = content;
    while (line != NULL && *line != '\0') {
        char *next = strchr(line, '\n');
        if (next != NULL) *next = '\0';

        /* Find the socket path (last field, starts with @) */
        char *at = strrchr(line, '@');
        if (at != NULL) {
            char *name = at + 1;
            size_t name_len = strlen(name);
            /* Check if it's a 32+ char hex-only string */
            if (name_len >= 32) {
                int all_hex = 1;
                for (size_t i = 0; i < name_len; i++) {
                    char c = name[i];
                    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                        all_hex = 0;
                        break;
                    }
                }
                if (all_hex && found_count < 5) {
                    if (findings_len + name_len + 2 < sizeof(findings)) {
                        if (findings_len > 0) findings[findings_len++] = ',';
                        memcpy(findings + findings_len, name, name_len);
                        findings_len += name_len;
                        found_count++;
                    }
                }
            }
        }

        if (next != NULL) { *next = '\n'; line = next + 1; }
        else break;
    }

    free(content);

    if (found_count == 0) return NULL;

    findings[findings_len] = '\0';
    return (*env)->NewStringUTF(env, findings);
}

/* --------------------------------------------------------------------------
 * JNI: checkMountNamespaceDiff
 *
 * Compares mount namespace IDs between the current process and init (PID 1).
 * On a stock device, all processes share the same mount namespace.
 * Root hiding tools (Shamiko, KernelSU) use mount namespace isolation
 * to unmount modules from the app's view — this changes the namespace ID.
 *
 * Reads /proc/self/ns/mnt and /proc/1/ns/mnt via readlink() syscall.
 * Returns JNI_TRUE if namespaces differ (suspicious), JNI_FALSE if same.
 * -------------------------------------------------------------------------- */

JNIEXPORT jboolean JNICALL
Java_io_github_brunovsiqueira_vigil_detectors_NativeBridge_checkMountNamespaceDiff(
    JNIEnv *env, jclass clazz) {

    (void)env;
    (void)clazz;

    char self_ns[128];
    char init_ns[128];

    ssize_t self_len = syscall(__NR_readlinkat, AT_FDCWD, "/proc/self/ns/mnt", self_ns, sizeof(self_ns) - 1);
    if (self_len <= 0) return JNI_FALSE;
    self_ns[self_len] = '\0';

    ssize_t init_len = syscall(__NR_readlinkat, AT_FDCWD, "/proc/1/ns/mnt", init_ns, sizeof(init_ns) - 1);
    if (init_len <= 0) return JNI_FALSE; /* Can't read init ns — likely permission denied, inconclusive */
    init_ns[init_len] = '\0';

    /* If namespace IDs differ, mount isolation is active */
    return (strcmp(self_ns, init_ns) != 0) ? JNI_TRUE : JNI_FALSE;
}

/* --------------------------------------------------------------------------
 * JNI: probeSupercall
 *
 * Probes for APatch's custom syscall #45 (__NR_supercall).
 * APatch registers this syscall for root operations. On a normal kernel,
 * syscall 45 is __NR_brk. We call it with an invalid SuperKey — if we get
 * -EPERM (permission denied), APatch is present. If we get the normal brk
 * behavior or -ENOSYS, it's not installed.
 *
 * Returns: 1 = APatch detected, 0 = not detected, -1 = error/inconclusive
 *
 * Reference: https://github.com/bmax121/APatch
 * SuperCall format: [32-bit version][16-bit magic 0x1158][16-bit cmd]
 * -------------------------------------------------------------------------- */

JNIEXPORT jint JNICALL
Java_io_github_brunovsiqueira_vigil_detectors_NativeBridge_probeSupercall(
    JNIEnv *env, jclass clazz) {

    (void)env;
    (void)clazz;

    /*
     * APatch SuperCall uses syscall #45 with a specific protocol:
     * arg1 = SuperKey (string pointer)
     * arg2 = encoded command: [version(32) | magic(16)=0x1158 | cmd(16)]
     *
     * We send HELLO command (0x1000) with a deliberately invalid key.
     * If APatch is present, it validates the key and returns -EPERM.
     * If APatch is NOT present, syscall 45 is __NR_brk on ARM64
     * and will behave normally (return current brk address or similar).
     *
     * Safety: This is a read-only probe. The invalid key ensures no
     * state change even if APatch is present.
     */
    const char *fake_key = "vigil_probe_not_a_real_key";
    /* Command: version=0, magic=0x1158, cmd=0x1000 (HELLO) */
    long cmd = (0L << 32) | (0x1158L << 16) | 0x1000L;

    errno = 0;
    long result = syscall(45, fake_key, cmd);

    if (result == -1 && errno == EPERM) {
        /* -EPERM means APatch recognized the syscall format
         * but rejected the key — APatch IS installed */
        LOG_D("probeSupercall: APatch detected (got EPERM)");
        return 1;
    }

    /* Any other result means syscall 45 is normal __NR_brk or similar */
    return 0;
}
