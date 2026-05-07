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

    /*
     * Use faccessat(2) via direct syscall instead of access(2) from libc.
     * F_OK (0) checks for file existence only.
     * The fourth argument (flags) is 0 — no AT_SYMLINK_NOFOLLOW etc.
     */
    int result = (int)syscall(__NR_faccessat, AT_FDCWD, native_path, F_OK, 0);

    (*env)->ReleaseStringUTFChars(env, path, native_path);

    return (result == 0) ? JNI_TRUE : JNI_FALSE;
}
