/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/xattr.h>
#include <threads.h>
#include <unistd.h>

#include "alloc-util.h"
#include "capsule-util.h"
#include "cgroup-util.h"
#include "constants.h"
#include "dirent-util.h"
#include "errno-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "log.h"
#include "login-util.h"
#include "macro.h"
#include "missing_fs.h"
#include "missing_magic.h"
#include "mkdir.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "set.h"
#include "special.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "unit-name.h"
#include "user-util.h"
#include "xattr-util.h"

int cg_get_path(int cgroupfs_fd, const char *path, const char *suffix, char **ret) {
        char *t;
        int r;

        /* Returns relative path under /sys/fs/cgroup/ if cgroupfs_fd is valid, absolute path otherwise. */

        assert(path);
        assert(ret);

        if (cgroupfs_fd >= 0)
                t = path_join(skip_leading_slash(path), suffix);
        else
                t = path_join("/sys/fs/cgroup", path, suffix);
        if (!t)
                return -ENOMEM;

        *ret = path_simplify(t);
        return 0;
}

int cg_cgroupid_open(int cgroupfs_fd, uint64_t id) {
        _cleanup_close_ int fsfd = -EBADF;

        if (cgroupfs_fd < 0) {
                fsfd = open("/sys/fs/cgroup", O_CLOEXEC|O_DIRECTORY);
                if (fsfd < 0)
                        return -errno;

                cgroupfs_fd = fsfd;
        }

        cg_file_handle fh = CG_FILE_HANDLE_INIT;
        CG_FILE_HANDLE_CGROUPID(fh) = id;

        return RET_NERRNO(open_by_handle_at(cgroupfs_fd, &fh.file_handle, O_DIRECTORY|O_CLOEXEC));
}

int cg_path_from_cgroupid(int cgroupfs_fd, uint64_t id, char **ret) {
        _cleanup_close_ int cgfd = -EBADF;
        int r;

        cgfd = cg_cgroupid_open(cgroupfs_fd, id);
        if (cgfd < 0)
                return cgfd;

        _cleanup_free_ char *path = NULL;
        r = fd_get_path(cgfd, &path);
        if (r < 0)
                return r;

        if (!path_startswith(path, "/sys/fs/cgroup/"))
                return -EXDEV; /* recognizable error */

        if (ret)
                *ret = TAKE_PTR(path);
        return 0;
}

int cg_get_cgroupid_at(int dfd, const char *path, uint64_t *ret) {
        cg_file_handle fh = CG_FILE_HANDLE_INIT;
        int mnt_id;

        assert(dfd >= 0 || (dfd == AT_FDCWD && path_is_absolute(path)));
        assert(ret);

        /* This is cgroupfs so we know the size of the handle, thus no need to loop around like
         * name_to_handle_at_loop() does in mountpoint-util.c */
        if (name_to_handle_at(dfd, strempty(path), &fh.file_handle, &mnt_id, isempty(path) ? AT_EMPTY_PATH : 0) < 0) {
                assert(errno != EOVERFLOW);
                return -errno;
        }

        *ret = CG_FILE_HANDLE_CGROUPID(fh);
        return 0;
}

int cg_get_owner(int cgroupfs_fd, const char *path, uid_t *ret_uid) {
        _cleanup_free_ char *f = NULL;
        struct stat stats;
        int r;

        assert(ret_uid);

        r = cg_get_path(cgroupfs_fd, path, /* suffix = */ NULL, &f);
        if (r < 0)
                return r;

        if (fstatat(cgroupfs_fd, f, &stats, /* flags = */ 0) < 0)
                return -errno;

        r = stat_verify_directory(&stats);
        if (r < 0)
                return r;

        *ret_uid = stats.st_uid;
        return 0;
}

int cg_enumerate_processes(int cgroupfs_fd, const char *path, FILE **ret) {
        _cleanup_free_ char *fs = NULL;
        int r;

        assert(path);
        assert(item);
        assert(ret);

        r = cg_get_path(cgroupfs_fd, path, "cgroup.procs", &fs);
        if (r < 0)
                return r;

        return xfopenat(cgroupfs_fd, path, "re", /* open_flags = */ 0, ret);
}

int cg_read_pid(FILE *f, pid_t *ret, CGroupFlags flags) {
        unsigned long ul;

        /* Note that the cgroup.procs might contain duplicates! See cgroups.txt for details. */

        assert(f);
        assert(ret);

        for (;;) {
                errno = 0;
                if (fscanf(f, "%lu", &ul) != 1) {

                        if (feof(f)) {
                                *ret = 0;
                                return 0;
                        }

                        return errno_or_else(EIO);
                }

                if (ul > PID_T_MAX)
                        return -EIO;

                /* In some circumstances (e.g. WSL), cgroups might contain unmappable PIDs from other
                 * contexts. These show up as zeros, and depending on the caller, can either be plain
                 * skipped over, or returned as-is. */
                if (ul == 0 && !FLAGS_SET(flags, CGROUP_DONT_SKIP_UNMAPPED))
                        continue;

                *ret = (pid_t) ul;
                return 1;
        }
}

int cg_read_pidref(FILE *f, PidRef *ret, CGroupFlags flags) {
        int r;

        assert(f);
        assert(ret);

        for (;;) {
                pid_t pid;

                r = cg_read_pid(f, &pid, flags);
                if (r < 0)
                        return log_debug_errno(r, "Failed to read pid from cgroup item: %m");
                if (r == 0) {
                        *ret = PIDREF_NULL;
                        return 0;
                }
                if (pid == 0)
                        return -EREMOTE;

                r = pidref_set_pid(ret, pid);
                if (r >= 0)
                        return 1;
                if (r != -ESRCH)
                        return r;

                /* ESRCH → gone by now? just skip over it, read the next */
        }
}

bool cg_kill_supported(void) {
        static thread_local int supported = -1;

        if (supported >= 0)
                return supported;

        if (access("/sys/fs/cgroup/init.scope/cgroup.kill", F_OK) >= 0)
                return (supported = true);
        if (errno != ENOENT)
                log_debug_errno(errno, "Failed to check whether cgroup.kill is available, assuming not: %m");
        return (supported = false);
}

int cg_read_event(
                int cgroupfs_fd,
                const char *path,
                const char *event,
                char **ret) {

        _cleanup_free_ char *events = NULL, *content = NULL;
        int r;

        r = cg_get_path(cgroupfs_fd, path, "cgroup.events", &events);
        if (r < 0)
                return r;

        r = read_full_virtual_file_at(cgroupfs_fd, events, &content, NULL);
        if (r < 0)
                return r;

        for (const char *p = content;;) {
                _cleanup_free_ char *line = NULL, *key = NULL;
                const char *q;

                r = extract_first_word(&p, &line, "\n", 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ENOENT;

                q = line;
                r = extract_first_word(&q, &key, " ", 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EINVAL;

                if (streq(key, event))
                        return strdup_to(ret, q);
        }
}

int cg_enumerate_subgroups(int cgroupfs_fd, const char *path, DIR **ret) {
        _cleanup_free_ char *fs = NULL;
        DIR *d;
        int r;

        assert(path);
        assert(ret);

        /* This is not recursive! */

        r = cg_get_path(cgroupfs_fd, path, NULL, &fs);
        if (r < 0)
                return r;

        d = xopendirat(cgroupfs_fd, fs, /* flags = */ 0);
        if (!d)
                return -errno;

        *ret = d;
        return 0;
}

int cg_read_subgroup(DIR *d, char **ret) {
        assert(d);
        assert(ret);

        FOREACH_DIRENT_ALL(de, d, return -errno) {
                if (de->d_type != DT_DIR)
                        continue;

                if (dot_or_dot_dot(de->d_name))
                        continue;

                return strdup_to_full(ret, de->d_name);
        }

        *ret = NULL;
        return 0;
}

int cg_kill(
                int cgroupfs_fd,
                const char *path,
                int sig,
                CGroupFlags flags,
                Set *s,
                cg_kill_log_func_t log_kill,
                void *userdata) {

        _cleanup_set_free_ Set *allocated_set = NULL;
        int r, ret = 0;

        assert(path);
        assert(sig >= 0);

         /* Don't send SIGCONT twice. Also, SIGKILL always works even when process is suspended, hence
          * don't send SIGCONT on SIGKILL. */
        if (IN_SET(sig, SIGCONT, SIGKILL))
                flags &= ~CGROUP_SIGCONT;

        /* This goes through the tasks list and kills them all. This is repeated until no further processes
         * are added to the tasks list, to properly handle forking processes.
         *
         * When sending SIGKILL, prefer cg_kill_kernel_sigkill(), which is fully atomic. */

        if (!s) {
                s = allocated_set = set_new(NULL);
                if (!s)
                        return -ENOMEM;
        }

        bool done;
        do {
                _cleanup_fclose_ FILE *f = NULL;
                int ret_log_kill;

                done = true;

                r = cg_enumerate_processes(cgroupfs_fd, path, &f);
                if (r == -ENOENT)
                        break;
                if (r < 0)
                        return RET_GATHER(ret, log_debug_errno(r, "Failed to enumerate processes in cgroup '%s': %m", path));

                for (;;) {
                        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;

                        r = cg_read_pidref(f, &pidref, flags);
                        if (r < 0)
                                return RET_GATHER(ret, log_debug_errno(r, "Failed to read pidref from cgroup '%s': %m", path));
                        if (r == 0)
                                break;

                        if ((flags & CGROUP_IGNORE_SELF) && pidref_is_self(&pidref))
                                continue;

                        if (set_contains(s, PID_TO_PTR(pidref.pid)))
                                continue;

                        /* Ignore kernel threads to mimic the behavior of cgroup.kill. */
                        if (pidref_is_kernel_thread(&pidref) > 0) {
                                log_debug("Ignoring kernel thread with pid " PID_FMT " in cgroup '%s'", pidref.pid, path);
                                continue;
                        }

                        if (log_kill)
                                ret_log_kill = log_kill(&pidref, sig, userdata);

                        /* If we haven't killed this process yet, kill it */
                        r = pidref_kill(&pidref, sig);
                        if (r < 0 && r != -ESRCH)
                                RET_GATHER(ret, log_debug_errno(r, "Failed to kill process with pid " PID_FMT " from cgroup '%s': %m", pidref.pid, path));
                        if (r >= 0) {
                                if (flags & CGROUP_SIGCONT)
                                        (void) pidref_kill(&pidref, SIGCONT);

                                if (ret == 0) {
                                        if (log_kill)
                                                ret = ret_log_kill;
                                        else
                                                ret = 1;
                                }
                        }

                        done = false;

                        r = set_put(s, PID_TO_PTR(pidref.pid));
                        if (r < 0)
                                return RET_GATHER(ret, r);
                }

                /* To avoid racing against processes which fork quicker than we can kill them, we repeat this
                 * until no new pids need to be killed. */

        } while (!done);

        return ret;
}

int cg_kill_recursive(
                int cgroupfs_fd,
                const char *path,
                int sig,
                CGroupFlags flags,
                Set *s,
                cg_kill_log_func_t log_kill,
                void *userdata) {

        _cleanup_set_free_ Set *allocated_set = NULL;
        _cleanup_closedir_ DIR *d = NULL;
        int r, ret;

        assert(path);
        assert(sig >= 0);

        if (!s) {
                s = allocated_set = set_new(NULL);
                if (!s)
                        return -ENOMEM;
        }

        ret = cg_kill(cgroupfs_fd, path, sig, flags, s, log_kill, userdata);

        r = cg_enumerate_subgroups(cgroupfs_fd, path, &d);
        if (r < 0) {
                if (r != -ENOENT)
                        RET_GATHER(ret, log_debug_errno(r, "Failed to enumerate cgroup '%s' subgroups: %m", path));

                return ret;
        }

        for (;;) {
                _cleanup_free_ char *fn = NULL, *p = NULL;

                r = cg_read_subgroup(d, &fn);
                if (r < 0)
                        return RET_GATHER(ret,
                                          log_debug_errno(r, "Failed to read subgroup from cgroup '%s': %m", path));
                if (r == 0)
                        return ret;

                p = path_join(path, fn);
                if (!p)
                        return -ENOMEM;

                r = cg_kill_recursive(cgroupfs_fd, p, sig, flags, s, log_kill, userdata);
                if (r < 0)
                        log_debug_errno(r, "Failed to recursively kill processes in cgroup '%s': %m", p);
                if (r != 0 && ret >= 0)
                        ret = r;
        }
}

int cg_kill_kernel_sigkill(int cgroupfs_fd, const char *path) {
        _cleanup_free_ char *killfile = NULL;
        int r;

        /* Kills the cgroup at `path` directly by writing to its cgroup.kill file.  This sends SIGKILL to all
         * processes in the cgroup and has the advantage of being completely atomic, unlike cg_kill_items(). */

        assert(path);

        if (!cg_kill_supported())
                return -EOPNOTSUPP;

        r = cg_get_path(cgroupfs_fd, path, "cgroup.kill", &killfile);
        if (r < 0)
                return r;

        r = write_string_file_at(cgroupfs_fd, killfile, "1", WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return log_debug_errno(r, "Failed to write to cgroup.kill for cgroup '%s': %m", path);

        return 0;
}

int cg_set_xattr(
                int cgroupfs_fd,
                const char *path,
                const char *name,
                const void *value,
                size_t size) {

        _cleanup_free_ char *fs = NULL;
        int r;

        assert(path);
        assert(name);
        assert(value || size == 0);

        r = cg_get_path(cgroupfs_fd, path, /* suffix = */ NULL, &fs);
        if (r < 0)
                return r;

        return RET_NERRNO(xsetxattr_full(cgroupfs_fd, fs, /* at_flags = */ 0, value, size, /* xattr_flags = */ 0));
}

int cg_get_xattr(int cgroupfs_fd, const char *path, const char *name, char **ret, size_t *ret_size) {
        _cleanup_free_ char *fs = NULL;
        int r;

        assert(path);
        assert(name);

        r = cg_get_path(cgroupfs_fd, path, /* suffix = */ NULL, &fs);
        if (r < 0)
                return r;

        return getxattr_at_malloc(cgroupfs_fd, fs, /* at_flags = */ 0, ret, ret_size);
}

int cg_get_xattr_bool(int cgroupfs_fd, const char *path, const char *name) {
        _cleanup_free_ char *fs = NULL;
        int r;

        assert(path);
        assert(name);

        r = cg_get_path(cgroupfs_fd, path, /* suffix = */ NULL, &fs);
        if (r < 0)
                return r;

        return getxattr_at_bool(cgroupfs_fd, fs, name, /* at_flags= */ 0);
}

int cg_remove_xattr(int cgroupfs_fd, const char *path, const char *name) {
        _cleanup_free_ char *fs = NULL;
        int r;

        assert(path);
        assert(name);

        r = cg_get_path(cgroupfs_fd, path, /* suffix = */ NULL, &fs);
        if (r < 0)
                return r;

        return RET_NERRNO(xremovexattr(cgroupfs_fd, fs, name));
}

int cg_pid_get_path(pid_t pid, char **ret_path) {
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(pid >= 0);
        assert(ret_path);

        r = fopen_unlocked(procfs_file_alloca(pid, "cgroup"), "re", &f);
        if (r == -ENOENT) {
                r = proc_mounted();
                if (r > 0)
                        return -ESRCH; /* /proc/ is definitely around, hence it's the process that doesn't exist */
                if (r == 0)
                        return -ENOSYS;

                return -ENOENT; /* Cannot determine, propagate ENOENT as-is */
        }
        if (r < 0)
                return r;

        for (;;) {
                _cleanup_free_ char *line = NULL;
                char *e;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -ENODATA;

                e = startswith(line, "0:");
                if (!e)
                        continue;

                e = strchr(e, ':');
                if (!e)
                        continue;

                _cleanup_free_ char *path = strdup(e + 1);
                if (!path)
                        return -ENOMEM;

                /* Refuse cgroup paths from outside our cgroup namespace */
                if (startswith(path, "/../"))
                        return -EUNATCH;

                /* Truncate suffix indicating the process is a zombie */
                e = endswith(path, " (deleted)");
                if (e)
                        *e = 0;

                *ret_path = TAKE_PTR(path);
                return 0;
        }
}

int cg_pidref_get_path(const PidRef *pidref, char **ret_path) {
        _cleanup_free_ char *path = NULL;
        int r;

        assert(ret_path);

        if (!pidref_is_set(pidref))
                return -ESRCH;
        if (pidref_is_remote(pidref))
                return -EREMOTE;

        // XXX: Ideally we'd use pidfd_get_cgroupid() + cg_path_from_cgroupid() here, to extract this
        // bit of information from pidfd directly. However, the latter requires privilege and it's
        // not entirely clear how to handle cgroups from outer namespace.

        r = cg_pid_get_path(pidref->pid, &path);
        if (r < 0)
                return r;

        /* Before we return the path, make sure the procfs entry for this pid still matches the pidref */
        r = pidref_verify(pidref);
        if (r < 0)
                return r;

        *ret_path = TAKE_PTR(path);
        return 0;
}

int cg_is_empty_recursive(int cgroupfs_fd, const char *path) {
        _cleanup_free_ char *t = NULL;
        int r;

        assert(path);

        /* The root cgroup is always populated */
        if (empty_or_root(path))
                return false;

        // TODO: port to keyed attr
        r = cg_read_event(cgroupfs_fd, path, "populated", &t);
        if (r == -ENOENT)
                return true;
        if (r < 0)
                return r;

        return streq(t, "0");
}

int cg_mangle_path(const char *path, char **ret) {
        int r;

        assert(path);
        assert(ret);

        /* First, check if it already is a filesystem path */
        if (path_startswith(path, "/sys/fs/cgroup"))
                return path_simplify_alloc(path, ret);

        if (!path_is_absolute(path) || !path_is_normalized(path))
                return -EINVAL;

        return cg_get_path(/* cgroupfs_fd = */ -EBADF, path, /* suffix = */ NULL, ret);
}

int cg_get_root_path(char **ret) {
        char *p, *e;
        int r;

        assert(ret);

        r = cg_pid_get_path(1, &p);
        if (r < 0)
                return r;

        e = endswith(p, "/" SPECIAL_INIT_SCOPE);
        if (e)
                *e = 0;

        *ret = p;
        return 0;
}

int cg_shift_path(const char *cgroup, const char *root, const char **ret_shifted) {
        _cleanup_free_ char *rt = NULL;
        const char *p;
        int r;

        assert(cgroup);
        assert(ret_shifted);

        if (!root) {
                /* If the root was specified let's use that, otherwise let's determine it from PID 1 */

                r = cg_get_root_path(&rt);
                if (r < 0)
                        return r;

                root = rt;
        }

        p = path_startswith(cgroup, root);
        if (!p || p <= cgroup) {
                *ret_shifted = cgroup;
                return 0;
        }

        *ret_shifted = p - 1;
        return 1; /* did something */
}

int cg_pid_get_path_shifted(pid_t pid, const char *root, char **ret_cgroup) {
        _cleanup_free_ char *raw = NULL;
        const char *c;
        int r;

        assert(pid >= 0);
        assert(ret_cgroup);

        r = cg_pid_get_path(pid, &raw);
        if (r < 0)
                return r;

        r = cg_shift_path(raw, root, &c);
        if (r < 0)
                return r;
        if (r == 0) {
                *ret_cgroup = TAKE_PTR(raw);
                return 0;
        }

        return strdup_to(ret_cgroup, c);
}

int cg_path_decode_unit(const char *cgroup, char **ret_unit) {
        assert(cgroup);
        assert(ret_unit);

        size_t n = strcspn(cgroup, "/");
        if (n < 3)
                return -ENXIO;

        char *c = strndupa_safe(cgroup, n);
        c = cg_unescape(c);

        if (!unit_name_is_valid(c, UNIT_NAME_PLAIN|UNIT_NAME_INSTANCE))
                return -ENXIO;

        return strdup_to(ret_unit, c);
}

static bool valid_slice_name(const char *p, size_t n) {
        assert(p || n == 0);

        if (!p)
                return false;

        if (n < STRLEN("x.slice"))
                return false;

        if (!endswith_n(p, n, ".slice"))
                return false;

        char buf[n+1], *c;

        memcpy(buf, p, n);
        buf[n] = 0;

        c = cg_unescape(buf);

        return unit_name_is_valid(c, UNIT_NAME_PLAIN);
}

static const char* skip_slices(const char *p) {
        assert(p);

        /* Skips over all slice assignments */

        for (;;) {
                size_t n;

                p = skip_leading_slash(p);
                n = strcspn(p, "/");

                if (!valid_slice_name(p, n))
                        return p;

                p += n;
        }
}

int cg_path_get_unit(const char *path, char **ret) {
        _cleanup_free_ char *unit = NULL;
        int r;

        assert(path);
        assert(ret);

        path = skip_slices(path);

        r = cg_path_decode_unit(path, &unit);
        if (r < 0)
                return r;

        /* We skipped over the slices, don't accept any now */
        if (endswith(unit, ".slice"))
                return -ENXIO;

        *ret = TAKE_PTR(unit);
        return 0;
}

int cg_path_get_unit_path(const char *path, char **ret) {
        _cleanup_free_ char *path_copy = NULL;
        char *unit_name;

        assert(path);
        assert(ret);

        path_copy = strdup(path);
        if (!path_copy)
                return -ENOMEM;

        unit_name = (char*) skip_slices(path_copy);
        unit_name[strcspn(unit_name, "/")] = 0;

        if (!unit_name_is_valid(cg_unescape(unit_name), UNIT_NAME_PLAIN|UNIT_NAME_INSTANCE))
                return -ENXIO;

        *ret = TAKE_PTR(path_copy);

        return 0;
}

int cg_pid_get_unit(pid_t pid, char **ret_unit) {
        _cleanup_free_ char *cgroup = NULL;
        int r;

        assert(ret_unit);

        r = cg_pid_get_path_shifted(pid, /* root = */ NULL, &cgroup);
        if (r < 0)
                return r;

        return cg_path_get_unit(cgroup, ret_unit);
}

int cg_pidref_get_unit(const PidRef *pidref, char **ret) {
        _cleanup_free_ char *unit = NULL;
        int r;

        assert(ret);

        if (!pidref_is_set(pidref))
                return -ESRCH;
        if (pidref_is_remote(pidref))
                return -EREMOTE;

        r = cg_pid_get_unit(pidref->pid, &unit);
        if (r < 0)
                return r;

        r = pidref_verify(pidref);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(unit);
        return 0;
}

/**
 * Skip session-*.scope, but require it to be there.
 */
static const char* skip_session(const char *p) {
        size_t n;

        if (isempty(p))
                return NULL;

        p = skip_leading_slash(p);

        n = strcspn(p, "/");
        if (n < STRLEN("session-x.scope"))
                return NULL;

        if (!startswith(p, "session-") || !endswith_n(p, n, ".scope"))
                return NULL;

        char buf[n - STRLEN("session-") - STRLEN(".scope") + 1];

        memcpy(buf, p + 8, n - 8 - 6);
        buf[n - 8 - 6] = 0;

        /* Note that session scopes never need unescaping, since they cannot conflict with the kernel's
         * own names, hence we don't need to call cg_unescape() here. */

        if (!session_id_valid(buf))
                return NULL;

        p += n;
        return skip_leading_slash(p);
}

/**
 * Skip user@*.service or capsule@*.service, but require either of them to be there.
 */
static const char* skip_user_manager(const char *p) {
        size_t n;

        if (isempty(p))
                return NULL;

        p = skip_leading_slash(p);

        n = strcspn(p, "/");
        if (n < CONST_MIN(STRLEN("user@x.service"), STRLEN("capsule@x.service")))
                return NULL;

        /* Any possible errors from functions called below are converted to NULL return, so our callers won't
         * resolve user/capsule name. */
        _cleanup_free_ char *unit_name = strndup(p, n);
        if (!unit_name)
                return NULL;

        _cleanup_free_ char *i = NULL;
        UnitNameFlags type = unit_name_to_instance(unit_name, &i);
        if (type != UNIT_NAME_INSTANCE)
                return NULL;

        /* Note that user manager services never need unescaping, since they cannot conflict with the
         * kernel's own names, hence we don't need to call cg_unescape() here. Prudently check validity of
         * instance names, they should be always valid as we validate them upon unit start. */
        if ((startswith(unit_name, "user@") && parse_uid(i, NULL) >= 0) ||
            (startswith(unit_name, "capsule@") && capsule_name_is_valid(i) >= 0))
                return skip_leading_slash(p + n);

        return NULL;
}

static const char* skip_user_prefix(const char *path) {
        const char *t;

        assert(path);

        /* Skip slices, if there are any */
        path = skip_slices(path);

        /* Skip the user manager, if it's in the path now... */
        t = skip_user_manager(path);
        if (t)
                return t;

        /* Alternatively skip the user session if it is in the path... */
        return skip_session(path);
}

int cg_path_get_user_unit(const char *path, char **ret) {
        const char *t;

        assert(path);
        assert(ret);

        t = skip_user_prefix(path);
        if (!t)
                return -ENXIO;

        /* And from here on it looks pretty much the same as for a system unit, hence let's use the same
         * parser. */
        return cg_path_get_unit(t, ret);
}

int cg_pid_get_user_unit(pid_t pid, char **ret_unit) {
        _cleanup_free_ char *cgroup = NULL;
        int r;

        assert(ret_unit);

        r = cg_pid_get_path_shifted(pid, /* root = */ NULL, &cgroup);
        if (r < 0)
                return r;

        return cg_path_get_user_unit(cgroup, ret_unit);
}

int cg_path_get_machine_name(const char *path, char **ret_machine) {
        _cleanup_free_ char *u = NULL;
        const char *sl;
        int r;

        r = cg_path_get_unit(path, &u);
        if (r < 0)
                return r;

        sl = strjoina("/run/systemd/machines/unit:", u);
        return readlink_malloc(sl, ret_machine);
}

int cg_pid_get_machine_name(pid_t pid, char **ret_machine) {
        _cleanup_free_ char *cgroup = NULL;
        int r;

        assert(ret_machine);

        r = cg_pid_get_path_shifted(pid, /* root = */ NULL, &cgroup);
        if (r < 0)
                return r;

        return cg_path_get_machine_name(cgroup, ret_machine);
}

int cg_path_get_session(const char *path, char **ret_session) {
        _cleanup_free_ char *unit = NULL;
        char *start, *end;
        int r;

        assert(path);

        r = cg_path_get_unit(path, &unit);
        if (r < 0)
                return r;

        start = startswith(unit, "session-");
        if (!start)
                return -ENXIO;
        end = endswith(start, ".scope");
        if (!end)
                return -ENXIO;
        *end = 0;

        if (!session_id_valid(start))
                return -ENXIO;

        return strdup_to_full(ret_session, start);
}

int cg_pid_get_session(pid_t pid, char **ret_session) {
        _cleanup_free_ char *cgroup = NULL;
        int r;

        r = cg_pid_get_path_shifted(pid, /* root = */ NULL, &cgroup);
        if (r < 0)
                return r;

        return cg_path_get_session(cgroup, ret_session);
}

int cg_pidref_get_session(const PidRef *pidref, char **ret) {
        int r;

        if (!pidref_is_set(pidref))
                return -ESRCH;
        if (pidref_is_remote(pidref))
                return -EREMOTE;

        _cleanup_free_ char *session = NULL;
        r = cg_pid_get_session(pidref->pid, &session);
        if (r < 0)
                return r;

        r = pidref_verify(pidref);
        if (r < 0)
                return r;

        if (ret)
                *ret = TAKE_PTR(session);
        return 0;
}

int cg_path_get_owner_uid(const char *path, uid_t *ret_uid) {
        _cleanup_free_ char *slice = NULL;
        char *start, *end;
        int r;

        assert(path);

        r = cg_path_get_slice(path, &slice);
        if (r < 0)
                return r;

        start = startswith(slice, "user-");
        if (!start)
                return -ENXIO;
        end = endswith(start, ".slice");
        if (!end)
                return -ENXIO;
        *end = 0;

        if (parse_uid(start, ret_uid) < 0)
                return -ENXIO;

        return 0;
}

int cg_pid_get_owner_uid(pid_t pid, uid_t *ret_uid) {
        _cleanup_free_ char *cgroup = NULL;
        int r;

        r = cg_pid_get_path_shifted(pid, /* root = */ NULL, &cgroup);
        if (r < 0)
                return r;

        return cg_path_get_owner_uid(cgroup, ret_uid);
}

int cg_pidref_get_owner_uid(const PidRef *pidref, uid_t *ret) {
        int r;

        if (!pidref_is_set(pidref))
                return -ESRCH;
        if (pidref_is_remote(pidref))
                return -EREMOTE;

        uid_t uid;
        r = cg_pid_get_owner_uid(pidref->pid, &uid);
        if (r < 0)
                return r;

        r = pidref_verify(pidref);
        if (r < 0)
                return r;

        if (ret)
                *ret = uid;

        return 0;
}

int cg_path_get_slice(const char *p, char **ret_slice) {
        const char *e = NULL;

        assert(p);
        assert(ret_slice);

        /* Finds the right-most slice unit from the beginning, but stops before we come to
         * the first non-slice unit. */

        for (;;) {
                const char *s;
                int n;

                n = path_find_first_component(&p, /* accept_dot_dot = */ false, &s);
                if (n < 0)
                        return n;
                if (!valid_slice_name(s, n))
                        break;

                e = s;
        }

        if (e)
                return cg_path_decode_unit(e, ret_slice);

        return strdup_to(ret_slice, SPECIAL_ROOT_SLICE);
}

int cg_pid_get_slice(pid_t pid, char **ret_slice) {
        _cleanup_free_ char *cgroup = NULL;
        int r;

        assert(ret_slice);

        r = cg_pid_get_path_shifted(pid, /* root = */ NULL, &cgroup);
        if (r < 0)
                return r;

        return cg_path_get_slice(cgroup, ret_slice);
}

int cg_path_get_user_slice(const char *p, char **ret_slice) {
        const char *t;

        assert(p);
        assert(ret_slice);

        t = skip_user_prefix(p);
        if (!t)
                return -ENXIO;

        /* And now it looks pretty much the same as for a system slice, so let's just use the same parser
         * from here on. */
        return cg_path_get_slice(t, ret_slice);
}

int cg_pid_get_user_slice(pid_t pid, char **ret_slice) {
        _cleanup_free_ char *cgroup = NULL;
        int r;

        assert(ret_slice);

        r = cg_pid_get_path_shifted(pid, /* root = */ NULL, &cgroup);
        if (r < 0)
                return r;

        return cg_path_get_user_slice(cgroup, ret_slice);
}

bool cg_needs_escape(const char *p) {
        assert(p);

        /* Checks if the specified path is a valid cgroup name by our rules, or if it must be escaped. Note
         * that we consider escaped cgroup names invalid here, as they need to be escaped a second time if
         * they shall be used. Also note that various names cannot be made valid by escaping even if we
         * return true here (because too long, or contain the forbidden character "/"). */

        if (!filename_is_valid(p))
                return true;

        if (IN_SET(p[0], '_', '.'))
                return true;

        if (startswith(p, "cgroup."))
                return true;

        for (CGroupController c = 0; c < _CGROUP_CONTROLLER_MAX; c++) {
                const char *q;

                q = startswith(p, cgroup_controller_to_string(c));
                if (!q)
                        continue;

                if (q[0] == '.')
                        return true;
        }

        return false;
}

int cg_escape(const char *p, char **ret) {
        _cleanup_free_ char *n = NULL;

        /* This implements very minimal escaping for names to be used as file names in the cgroup tree: any
         * name which might conflict with a kernel name or is prefixed with '_' is prefixed with a '_'. That
         * way, when reading cgroup names it is sufficient to remove a single prefixing underscore if there
         * is one. */

        /* The return value of this function (unlike cg_unescape()) needs free()! */

        assert(p);
        assert(ret);

        if (cg_needs_escape(p)) {
                n = strjoin("_", p);
                if (!n)
                        return -ENOMEM;

                if (!filename_is_valid(n)) /* paranoia: became invalid due to the prefixing? */
                        return -EINVAL;
        } else {
                n = strdup(p);
                if (!n)
                        return -ENOMEM;
        }

        *ret = TAKE_PTR(n);
        return 0;
}

char* cg_unescape(const char *p) {
        assert(p);

        /* The return value of this function (unlike cg_escape()) doesn't need free()! */

        if (p[0] == '_')
                return (char*) p+1;

        return (char*) p;
}

#define CONTROLLER_VALID                        \
        DIGITS LETTERS                          \
        "_"

bool cg_controller_is_valid(const char *p) {

        if (isempty(p))
                return false;

        if (*p == '_')
                return false;

        if (!in_charset(p, CONTROLLER_VALID))
                return false;

        if (strlen(p) > NAME_MAX)
                return false;

        return true;
}

int cg_slice_to_path(const char *unit, char **ret) {
        _cleanup_free_ char *p = NULL, *s = NULL, *e = NULL;
        const char *dash;
        int r;

        assert(unit);
        assert(ret);

        if (streq(unit, SPECIAL_ROOT_SLICE))
                return strdup_to(ret, "");

        if (!unit_name_is_valid(unit, UNIT_NAME_PLAIN))
                return -EINVAL;

        if (!endswith(unit, ".slice"))
                return -EINVAL;

        r = unit_name_to_prefix(unit, &p);
        if (r < 0)
                return r;

        dash = strchr(p, '-');

        /* Don't allow initial dashes */
        if (dash == p)
                return -EINVAL;

        while (dash) {
                _cleanup_free_ char *escaped = NULL;
                char n[dash - p + sizeof(".slice")];

#if HAS_FEATURE_MEMORY_SANITIZER
                /* msan doesn't instrument stpncpy, so it thinks
                 * n is later used uninitialized:
                 * https://github.com/google/sanitizers/issues/926
                 */
                zero(n);
#endif

                /* Don't allow trailing or double dashes */
                if (IN_SET(dash[1], 0, '-'))
                        return -EINVAL;

                strcpy(stpncpy(n, p, dash - p), ".slice");
                if (!unit_name_is_valid(n, UNIT_NAME_PLAIN))
                        return -EINVAL;

                r = cg_escape(n, &escaped);
                if (r < 0)
                        return r;

                if (!strextend(&s, escaped, "/"))
                        return -ENOMEM;

                dash = strchr(dash+1, '-');
        }

        r = cg_escape(unit, &e);
        if (r < 0)
                return r;

        if (!strextend(&s, e))
                return -ENOMEM;

        *ret = TAKE_PTR(s);
        return 0;
}

int cg_is_threaded(int cgroupfs_fd, const char *path) {
        _cleanup_free_ char *fs = NULL, *contents = NULL;
        _cleanup_strv_free_ char **v = NULL;
        int r;

        r = cg_get_path(cgroupfs_fd, path, "cgroup.type", &fs);
        if (r < 0)
                return r;

        r = read_full_virtual_file_at(fs, &contents, NULL);
        if (r == -ENOENT)
                return false; /* Assume no. */
        if (r < 0)
                return r;

        v = strv_split(contents, NULL);
        if (!v)
                return -ENOMEM;

        /* If the cgroup is in the threaded mode, it contains "threaded".
         * If one of the parents or siblings is in the threaded mode, it may contain "invalid". */
        return strv_contains(v, "threaded") || strv_contains(v, "invalid");
}

int cg_set_attribute(int cgroupfs_fd, const char *path, const char *attribute, const char *value) {
        _cleanup_free_ char *p = NULL;
        int r;

        assert(attribute);
        assert(value);

        r = cg_get_path(cgroupfs_fd, path, attribute, &p);
        if (r < 0)
                return r;

        return write_string_file_at(cgroupfs_fd, p, value, WRITE_STRING_FILE_DISABLE_BUFFER);
}

int cg_get_attribute(int cgroupfs_fd, const char *path, const char *attribute, char **ret) {
        _cleanup_free_ char *p = NULL;
        int r;

        assert(attribute);
        assert(ret);

        r = cg_get_path(cgroupfs_fd, path, attribute, &p);
        if (r < 0)
                return r;

        return read_one_line_file_at(cgroupfs_fd, p, ret);
}

int cg_get_attribute_uint64(int cgroupfs_fd, const char *path, const char *attribute, uint64_t *ret) {
        _cleanup_free_ char *value = NULL;
        uint64_t v;
        int r;

        assert(attribute);
        assert(ret);

        r = cg_get_attribute(cgroupfs_fd, path, attribute, &value);
        if (r == -ENOENT)
                return -ENODATA;
        if (r < 0)
                return r;

        if (streq(value, "max")) {
                *ret = CGROUP_LIMIT_MAX;
                return 0;
        }

        r = safe_atou64(value, &v);
        if (r < 0)
                return r;

        *ret = v;
        return 0;
}

int cg_get_attribute_bool(int cgroupfs_fd, const char *path, const char *attribute) {
        _cleanup_free_ char *value = NULL;
        int r;

        assert(attribute);

        r = cg_get_attribute(cgroupfs_fd, path, attribute, &value);
        if (r == -ENOENT)
                return -ENODATA;
        if (r < 0)
                return r;

        return parse_boolean(value);
}

int cg_get_keyed_attribute_full(
                int cgroupfs_fd,
                const char *path,
                const char *attribute,
                char * const *keys,
                char **ret_values,
                CGroupKeyMode flags) {

        _cleanup_free_ char *attr_path = NULL, *contents = NULL;
        int r;

        /* Reads one or more fields of a cgroup v2 keyed attribute file. The 'keys' parameter should be an strv with
         * all keys to retrieve. The 'ret_values' parameter should be passed as string size with the same number of
         * entries as 'keys'. On success each entry will be set to the value of the matching key.
         *
         * If the attribute file doesn't exist at all returns ENOENT, if any key is not found returns ENXIO. If mode
         * is set to GG_KEY_MODE_GRACEFUL we ignore missing keys and return those that were parsed successfully. */

        r = cg_get_path(cgroupfs_fd, path, attribute, &attr_path);
        if (r < 0)
                return r;

        r = read_full_file_at(cgroupfs_fd, attr_path, &contents, NULL);
        if (r < 0)
                return r;

        size_t n, n_done = 0;

        n = strv_length(keys);
        if (n == 0) /* No keys to retrieve? That's easy, we are done then */
                return 0;

        /* Let's build this up in a temporary array for now in order not to clobber the return parameter on failure */
        char **v = newa(char*, n);

        // TODO: test and commit msg: the behavior has been adjusted to permit duplicate keys
        for (size_t i = 0; i < n; i++) {
                const char *p = find_line_startswith(contents, keys[i]);
                if (!p) {
                        if (FLAGS_SET(flags, CG_KEY_MODE_GRACEFUL)) {
                                v[i] = NULL;
                                continue;
                        }

                        r = -ENXIO;
                        goto fail;
                }

                p = skip_leading_chars(p, /* bad = */ NULL);
                v[i] = strndup(p, strcspn(p, NEWLINE));
                if (!v[i]) {
                        r = -ENOMEM;
                        goto fail;
                }
        }

        memcpy(ret_values, v, sizeof(char*) * n);
        return 0;

fail:
        free_many_charp(v, n);
        return r;
}

int cg_mask_to_string(CGroupMask mask, char **ret) {
        _cleanup_free_ char *s = NULL;

        assert(ret);

        BIT_FOREACH(c, mask)
                if (!strextend_with_separator(&s, " ", cgroup_controller_to_string(c)))
                        return -ENOMEM;

        *ret = TAKE_PTR(s);
        return 0;
}

int cg_mask_from_string(const char *value, CGroupMask *ret) {
        CGroupMask m = 0;

        assert(value);
        assert(ret);

        for (;;) {
                _cleanup_free_ char *n = NULL;
                CGroupController v;
                int r;

                r = extract_first_word(&value, &n, NULL, 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                v = cgroup_controller_from_string(n);
                if (v < 0)
                        continue;

                SET_BIT(m, v);
        }

        *ret = m;
        return 0;
}

int cg_mask_supported_subtree(int cgroupfs_fd, const char *root, CGroupMask *ret) {
        _cleanup_free_ char *path = NULL, *controllers = NULL;
        int r;

        /* Determines the mask of supported cgroup controllers. Only includes controllers we can make sense of and that
         * are actually accessible. Only covers real controllers, i.e. not the CGROUP_CONTROLLER_BPF_xyz
         * pseudo-controllers. */

        assert(root);

        r = cg_get_path(cgroupfs_fd, root, "cgroup.controllers", &path);
        if (r < 0)
                return r;

        r = read_one_line_file(path, &controllers);
        if (r < 0)
                return r;

        return cg_mask_from_string(controllers, ret);
}

int cg_mask_supported(CGroupMask *ret) {
        _cleanup_free_ char *root = NULL;
        int r;

        r = cg_get_root_path(&root);
        if (r < 0)
                return r;

        return cg_mask_supported_subtree(/* cgroupfs_fd = */ -EBADF, root, ret);
}

int cg_is_delegated(const char *path) {
        int r;

        assert(path);

        r = cg_get_xattr_bool(path, "trusted.delegate");
        if (!ERRNO_IS_NEG_XATTR_ABSENT(r))
                return r;

        /* If the trusted xattr isn't set (preferred), then check the untrusted one. Under the assumption
         * that whoever is trusted enough to own the cgroup, is also trusted enough to decide if it is
         * delegated or not this should be safe (see also comments in cgroup_delegate_xattr_apply()) . */
        r = cg_get_xattr_bool(path, "user.delegate");
        return ERRNO_IS_NEG_XATTR_ABSENT(r) ? false : r;
}

int cg_is_delegated_fd(int fd) {
        int r;

        assert(fd >= 0);

        r = getxattr_at_bool(fd, /* path= */ NULL, "trusted.delegate", /* at_flags= */ 0);
        if (!ERRNO_IS_NEG_XATTR_ABSENT(r))
                return r;

        r = getxattr_at_bool(fd, /* path= */ NULL, "user.delegate", /* at_flags= */ 0);
        return ERRNO_IS_NEG_XATTR_ABSENT(r) ? false : r;
}

int cg_has_coredump_receive(int cgroupfs_fd, const char *path) {
        int r;

        assert(path);

        r = cg_get_xattr_bool(cgroupfs_fd, path, "user.coredump_receive");
        if (ERRNO_IS_NEG_XATTR_ABSENT(r))
                return false;

        return r;
}

bool cg_ns_supported(void) {
        static thread_local int supported = -1;

        if (supported >= 0)
                return supported;

        if (access("/proc/self/ns/cgroup", F_OK) >= 0)
                return (supported = true);
        if (errno != ENOENT)
                log_debug_errno(errno, "Failed to check whether /proc/self/ns/cgroup is available, assuming not: %m");
        return (supported = false);
}

bool cg_kill_supported(void) {
        static thread_local int supported = -1;

        if (supported >= 0)
                return supported;

        if (access("/sys/fs/cgroup/init.scope/cgroup.kill", F_OK) >= 0)
                return (supported = true);
        if (errno != ENOENT)
                log_debug_errno(errno, "Failed to check whether cgroup.kill is available, assuming not: %m");
        return (supported = false);
}

bool is_cgroup_fs(const struct statfs *s) {
        return is_fs_type(s, CGROUP2_SUPER_MAGIC) ||
               is_fs_type(s, CGROUP_SUPER_MAGIC);
}

bool fd_is_cgroup_fs(int fd) {
        struct statfs s;

        if (fstatfs(fd, &s) < 0)
                return -errno;

        return is_cgroup_fs(&s);
}

const uint64_t cgroup_io_limit_defaults[_CGROUP_IO_LIMIT_TYPE_MAX] = {
        [CGROUP_IO_RBPS_MAX]    = CGROUP_LIMIT_MAX,
        [CGROUP_IO_WBPS_MAX]    = CGROUP_LIMIT_MAX,
        [CGROUP_IO_RIOPS_MAX]   = CGROUP_LIMIT_MAX,
        [CGROUP_IO_WIOPS_MAX]   = CGROUP_LIMIT_MAX,
};

static const char* const cgroup_io_limit_type_table[_CGROUP_IO_LIMIT_TYPE_MAX] = {
        [CGROUP_IO_RBPS_MAX]    = "IOReadBandwidthMax",
        [CGROUP_IO_WBPS_MAX]    = "IOWriteBandwidthMax",
        [CGROUP_IO_RIOPS_MAX]   = "IOReadIOPSMax",
        [CGROUP_IO_WIOPS_MAX]   = "IOWriteIOPSMax",
};

DEFINE_STRING_TABLE_LOOKUP(cgroup_io_limit_type, CGroupIOLimitType);

static const char *const cgroup_controller_table[_CGROUP_CONTROLLER_MAX] = {
        [CGROUP_CONTROLLER_CPU] = "cpu",
        [CGROUP_CONTROLLER_CPUSET] = "cpuset",
        [CGROUP_CONTROLLER_IO] = "io",
        [CGROUP_CONTROLLER_MEMORY] = "memory",
        [CGROUP_CONTROLLER_DEVICES] = "devices",
        [CGROUP_CONTROLLER_PIDS] = "pids",
        [CGROUP_CONTROLLER_BPF_FIREWALL] = "bpf-firewall",
        [CGROUP_CONTROLLER_BPF_DEVICES] = "bpf-devices",
        [CGROUP_CONTROLLER_BPF_FOREIGN] = "bpf-foreign",
        [CGROUP_CONTROLLER_BPF_SOCKET_BIND] = "bpf-socket-bind",
        [CGROUP_CONTROLLER_BPF_RESTRICT_NETWORK_INTERFACES] = "bpf-restrict-network-interfaces",
};

DEFINE_STRING_TABLE_LOOKUP(cgroup_controller, CGroupController);

static const char* const managed_oom_mode_table[_MANAGED_OOM_MODE_MAX] = {
        [MANAGED_OOM_AUTO] = "auto",
        [MANAGED_OOM_KILL] = "kill",
};

DEFINE_STRING_TABLE_LOOKUP(managed_oom_mode, ManagedOOMMode);

static const char* const managed_oom_preference_table[_MANAGED_OOM_PREFERENCE_MAX] = {
        [MANAGED_OOM_PREFERENCE_NONE] = "none",
        [MANAGED_OOM_PREFERENCE_AVOID] = "avoid",
        [MANAGED_OOM_PREFERENCE_OMIT] = "omit",
};

DEFINE_STRING_TABLE_LOOKUP(managed_oom_preference, ManagedOOMPreference);
