/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "bitfield.h"
#include "cgroup-setup.h"
#include "cgroup-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "log.h"
#include "missing_magic.h"
#include "mkdir.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "recurse-dir.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "user-util.h"

int cg_weight_parse(const char *s, uint64_t *ret) {
        uint64_t u;
        int r;

        assert(s);
        assert(ret);

        if (isempty(s)) {
                *ret = CGROUP_WEIGHT_INVALID;
                return 0;
        }

        r = safe_atou64(s, &u);
        if (r < 0)
                return r;

        if (u < CGROUP_WEIGHT_MIN || u > CGROUP_WEIGHT_MAX)
                return -ERANGE;

        *ret = u;
        return 0;
}

int cg_cpu_weight_parse(const char *s, uint64_t *ret) {
        assert(s);
        assert(ret);

        if (streq(s, "idle"))
                return *ret = CGROUP_WEIGHT_IDLE;

        return cg_weight_parse(s, ret);
}

static int trim_cb(
                RecurseDirEvent event,
                const char *path,
                int dir_fd,
                int inode_fd,
                const struct dirent *de,
                const struct statx *sx,
                void *userdata) {

        /* Failures to delete inner cgroup we ignore (but debug log in case error code is unexpected) */
        if (event == RECURSE_DIR_LEAVE &&
            de->d_type == DT_DIR &&
            unlinkat(dir_fd, de->d_name, AT_REMOVEDIR) < 0 &&
            !IN_SET(errno, ENOENT, ENOTEMPTY, EBUSY))
                log_debug_errno(errno, "Failed to trim inner cgroup '%s', ignoring: %m", path);

        return RECURSE_DIR_CONTINUE;
}

int cg_trim(int cgroupfs_fd, const char *path, bool delete_root) {
        _cleanup_free_ char *p = NULL;
        int r;

        r = cg_get_path(cgroupfs_fd, path, /* suffix = */ NULL, &p);
        if (r < 0)
                return r;

        r = recurse_dir_at(
                        cgroupfs_fd,
                        p,
                        /* statx_mask = */ 0,
                        /* n_depth_max = */ UINT_MAX,
                        RECURSE_DIR_ENSURE_TYPE,
                        trim_cb,
                        /* userdata = */ NULL);
        if (r == -ENOENT) /* non-existing is the ultimate trimming, hence no error */
                r = 0;
        else if (r < 0)
                log_debug_errno(r, "Failed to trim subcgroups of '%s': %m", path);

        /* If we shall delete the top-level cgroup, then propagate the failure to do so (except if it is
         * already gone anyway). Also, let's debug log about this failure, except if the error code is an
         * expected one. */
        if (delete_root && !empty_or_root(path) &&
            rmdirat(cgroupfs_fd, path) < 0 && errno != ENOENT) {
                if (!IN_SET(errno, ENOTEMPTY, EBUSY))
                        log_debug_errno(errno, "Failed to trim cgroup '%s': %m", path);
                RET_GATHER(r, -errno);
        }

        return r;
}

int cg_create(int cgroupfs_fd, const char *path) {
        _cleanup_free_ char *p = NULL;
        int r;

        /* Returns 0 if the group already existed, 1 on success, negative otherwise. */

        r = cg_get_path(cgroupfs_fd, path, /* suffix = */ NULL, &p);
        if (r < 0)
                return r;

        r = mkdirat_parents(cgroupfs_fd, p, 0755);
        if (r < 0)
                return r;

        r = RET_NERRNO(mkdirat(cgroupfs_fd, p, 0755));
        if (r == -EEXIST)
                return 0;
        if (r < 0)
                return r;

        return 1;
}

int cg_attach(int cgroupfs_fd, const char *path, pid_t pid) {
        _cleanup_free_ char *p = NULL;
        int r;

        assert(pid >= 0);

        if (pid == 0)
                pid = getpid_cached();

        r = cg_get_path(cgroupfs_fd, path, "cgroup.procs", &p);
        if (r < 0)
                return r;

        r = write_string_filef(p, WRITE_STRING_FILE_DISABLE_BUFFER, PID_FMT, pid);
        if (r == -EOPNOTSUPP && cg_is_threaded(path) > 0)
                /* When the threaded mode is used, we cannot read/write the file. Let's return recognizable error. */
                return -EUCLEAN;
        if (r < 0)
                return r;

        return 0;
}

int cg_fd_attach(int fd, pid_t pid) {
        char c[DECIMAL_STR_MAX(pid_t) + 2];

        assert(fd >= 0);
        assert(pid >= 0);

        if (pid == 0)
                pid = getpid_cached();

        xsprintf(c, PID_FMT "\n", pid);

        r = write_string_file_at(fd, "cgroup.procs", c, WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r == -EOPNOTSUPP && cg_is_threaded(path) > 0)
                /* When the threaded mode is used, we cannot read/write the file. Let's return recognizable error. */
                return -EUCLEAN;
        if (r < 0)
                return r;

        return 0;
}

int cg_create_and_attach(int cgroupfs_fd, const char *path, pid_t pid) {
        int r, ret;

        /* This does not remove the cgroup on failure */

        assert(pid >= 0);
        assert(path);

        ret = cg_create(cgroupfs_fd, path);
        if (ret < 0)
                return ret;

        r = cg_attach(cgroupfs_fd, path, pid);
        if (r < 0)
                return r;

        return ret;
}

int cg_set_access(
                int cgroupfs_fd,
                const char *path,
                uid_t uid,
                gid_t gid) {

        static const struct {
                const char *name;
                bool fatal;
        } attributes[] = {
                { "cgroup.procs",           true  },
                { "cgroup.subtree_control", true  },
                { "cgroup.threads",         false },
                { "memory.oom.group",       false },
                { "memory.reclaim",         false },
        };

        _cleanup_free_ char *p = NULL;
        int r;

        assert(path);

        if (uid == UID_INVALID && gid == GID_INVALID)
                return 0;

        /* Configure access to the cgroup itself */
        r = cg_get_path(cgroupfs_fd, path, /* suffix = */ NULL, &p);
        if (r < 0)
                return r;

        r = chmod_and_chown_at(cgroupfs_fd, p, 0755, uid, gid);
        if (r < 0)
                return r;

        /* Configure access to the cgroup's attributes */
        FOREACH_ELEMENT(i, attributes) {
                _cleanup_free_ char *a = path_join(p, i->name);
                if (!a)
                        return -ENOMEM;

                r = chmod_and_chown_at(cgroupfs_fd, a, 0644, uid, gid);
                if (r < 0) {
                        if (i->fatal)
                                return r;

                        log_debug_errno(r, "Failed to set access of attr '%s' on cgroup '%s', ignoring: %m", i->name, p);
                }
        }

        return 0;
}

struct access_callback_data {
        uid_t uid;
        gid_t gid;
        int error;
};

static int access_callback(
                RecurseDirEvent event,
                const char *path,
                int dir_fd,
                int inode_fd,
                const struct dirent *de,
                const struct statx *sx,
                void *userdata) {

        if (!IN_SET(event, RECURSE_DIR_ENTER, RECURSE_DIR_ENTRY))
                return RECURSE_DIR_CONTINUE;

        struct access_callback_data *d = ASSERT_PTR(userdata);

        assert(path);
        assert(inode_fd >= 0);

        if (fchownat(inode_fd, "", d->uid, d->gid, AT_EMPTY_PATH) < 0)
                RET_GATHER(d->error, log_debug_errno(errno, "Failed to change ownership of '%s', ignoring: %m", path));

        return RECURSE_DIR_CONTINUE;
}

int cg_set_access_recursive(
                int cgroupfs_fd,
                const char *path,
                uid_t uid,
                gid_t gid) {

        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ char *p = NULL;
        int r;

        assert(path);

        /* A recursive version of cg_set_access(). But note that this one changes ownership of *all* files,
         * not just the allowlist that cg_set_access() uses. Use cg_set_access() on the cgroup you want to
         * delegate, and cg_set_access_recursive() for any subcgroups you might want to create below it. */

        if (!uid_is_valid(uid) && !gid_is_valid(gid))
                return 0;

        r = cg_get_path(cgroupfs_fd, path, /* suffix = */ NULL, &p);
        if (r < 0)
                return r;

        struct access_callback_data d = {
                .uid = uid,
                .gid = gid,
        };

        r = recurse_dir(cgroupfs_fd, p,
                        /* statx_mask= */ 0,
                        /* n_depth_max= */ UINT_MAX,
                        RECURSE_DIR_SAME_MOUNT|RECURSE_DIR_INODE_FD|RECURSE_DIR_TOPLEVEL,
                        access_callback,
                        &d);
        if (r < 0)
                return r;

        assert(d.error <= 0);
        return d.error;
}

int cg_migrate(int cgroupfs_fd, const char *source, const char *target, CGroupFlags flags) {
        _cleanup_set_free_ Set *s = NULL;
        bool done;
        int r, ret = 0;

        assert(source);
        assert(target);

        do {
                _cleanup_fclose_ FILE *f = NULL;

                done = true;

                r = cg_enumerate_processes(cgroupfs_fd, source, &f);
                if (r < 0)
                        return RET_GATHER(ret, r);

                pid_t pid;
                while ((r = cg_read_pid(f, &pid, flags)) > 0) {
                        /* Throw an error if unmappable PIDs are in output, we can't migrate those. */
                        if (pid == 0)
                                return -EREMOTE;

                        /* This might do weird stuff if we aren't a single-threaded program. However, we
                         * luckily know we are. */
                        if (FLAGS_SET(flags, CGROUP_IGNORE_SELF) && pid == getpid_cached())
                                continue;

                        if (set_contains(s, PID_TO_PTR(pid)))
                                continue;

                        if (pid_is_kernel_thread(pid) > 0)
                                continue;

                        r = cg_attach(cgroupfs_fd, target, pid);
                        if (r < 0) {
                                if (r != -ESRCH)
                                        RET_GATHER(ret, r);
                        } else if (ret == 0)
                                ret = 1;

                        done = false;

                        r = set_ensure_put(&s, /* hash_ops = */ NULL, PID_TO_PTR(pid));
                        if (r < 0)
                                return r;
                }
                if (r < 0)
                        return RET_GATHER(ret, r);
        } while (!done);

        return ret;
}

int cg_enable(
                int cgroupfs_fd,
                const char *path,
                CGroupMask supported,
                CGroupMask mask,
                CGroupMask *ret_result_mask) {

        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *p = NULL;
        int r;

        assert(p);

        if (supported == 0) {
                if (ret_result_mask)
                        *ret_result_mask = 0;
                return 0;
        }

        r = cg_get_path(cgroupfs_fd, path, "cgroup.subtree_control", &p);
        if (r < 0)
                return r;

        r = xfopenat(cgroupfs_fd, p, "we", /* open_flags = */ 0, &f);
        if (r < 0)
                return log_debug_errno(r, "Failed to open cgroup.subtree_control of '%s': %m", path);

        CGroupMask enabled = 0;

        BIT_FOREACH(controller, supported) {
                bool enable = BIT_SET(mask, controller);
                const char *n = ASSERT_PTR(cgroup_controller_to_string(controller)),
                           *s = strjoina(plus_minus(enable), n);

                r = write_string_stream(f, s, WRITE_STRING_FILE_DISABLE_BUFFER);
                if (r < 0) {
                        log_debug_errno(r, "Failed to %s controller %s for cgroup '%s': %m",
                                        enable ? "enable" : "disable", n, path);
                        clearerr(f);

                        /* If we can't turn off a controller, leave it on in the reported resulting mask.
                         * This happens for example when we attempt to turn off a controller up in the tree
                         * that is used down in the tree.
                         *
                         * You might wonder why we check for EBUSY only here, and not follow the same logic
                         * for other errors such as EINVAL or EOPNOTSUPP or anything else. That's because
                         * EBUSY indicates that the controllers is currently enabled and cannot be disabled
                         * because something down the hierarchy is still using it. Any other error most likely
                         * means something like "I never heard of this controller" or similar.
                         * In the former case it's hence safe to assume the controller is still on after
                         * the failed operation, while in the latter case it's safer to assume the controller
                         * is unknown and hence certainly not enabled. */
                        if (!enable && r == -EBUSY)
                                SET_BIT(enabled, controller);

                } else if (enable) /* Otherwise, if we managed to turn on a controller, set the bit reflecting that. */
                        SET_BIT(enabled, controller);
        }

        /* Let's return the precise set of controllers now enabled for the cgroup. */
        if (ret_result_mask)
                *ret_result_mask = enabled;

        return 0;
}

int cg_has_legacy(void) {
        struct statfs fs;

        /* Checks if any legacy controller/hierarchy is mounted. */

        if (statfs("/sys/fs/cgroup/", &fs) < 0) {
                if (errno == ENOENT) /* sysfs not mounted? */
                        return false;

                return log_error_errno(errno, "Failed to statfs /sys/fs/cgroup/: %m");
        }

        if (is_fs_type(&fs, CGROUP2_SUPER_MAGIC) ||
            is_fs_type(&fs, SYSFS_MAGIC)) /* not mounted yet */
                return false;

        if (is_fs_type(&fs, TMPFS_MAGIC)) {
                log_info("Found tmpfs on /sys/fs/cgroup/, assuming legacy hierarchy.");
                return true;
        }

        return log_error_errno(SYNTHETIC_ERRNO(ENOMEDIUM),
                               "Unknown filesystem type %llx mounted on /sys/fs/cgroup/.",
                               (unsigned long long) fs.f_type);
}
