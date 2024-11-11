/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <dirent.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/statfs.h>
#include <sys/types.h>

#include "constants.h"
#include "pidref.h"
#include "set.h"

/* An enum of well known cgroup v2 controllers */
typedef enum CGroupController {
        /* Native cgroup controllers */
        CGROUP_CONTROLLER_CPU,
        CGROUP_CONTROLLER_CPUSET,
        CGROUP_CONTROLLER_IO,
        CGROUP_CONTROLLER_MEMORY,
        CGROUP_CONTROLLER_PIDS,

        _CGROUP_CONTROLLER_REAL_MAX,

        /* BPF-based pseudo-controllers */
        CGROUP_CONTROLLER_BPF_FIREWALL = _CGROUP_CONTROLLER_REAL_MAX,
        CGROUP_CONTROLLER_BPF_DEVICES,
        CGROUP_CONTROLLER_BPF_FOREIGN,
        CGROUP_CONTROLLER_BPF_SOCKET_BIND,
        CGROUP_CONTROLLER_BPF_RESTRICT_NETWORK_INTERFACES,
        /* The BPF hook implementing RestrictFileSystems= is not defined here.
         * It's applied as late as possible in exec_invoke() so we don't block
         * our own unit setup code. */

        _CGROUP_CONTROLLER_MAX,
        _CGROUP_CONTROLLER_INVALID = -EINVAL,
} CGroupController;

#define CGROUP_CONTROLLER_TO_MASK(c) (1U << (c))

/* A bit mask of well known cgroup controllers */
typedef enum CGroupMask {
        CGROUP_MASK_CPU = CGROUP_CONTROLLER_TO_MASK(CGROUP_CONTROLLER_CPU),
        CGROUP_MASK_CPUSET = CGROUP_CONTROLLER_TO_MASK(CGROUP_CONTROLLER_CPUSET),
        CGROUP_MASK_IO = CGROUP_CONTROLLER_TO_MASK(CGROUP_CONTROLLER_IO),
        CGROUP_MASK_MEMORY = CGROUP_CONTROLLER_TO_MASK(CGROUP_CONTROLLER_MEMORY),
        CGROUP_MASK_PIDS = CGROUP_CONTROLLER_TO_MASK(CGROUP_CONTROLLER_PIDS),

        /* All real cgroup v2 controllers, which are also controllers we want to delegate in case of Delegate=yes. */
        _CGROUP_MASK_REAL = CGROUP_CONTROLLER_TO_MASK(_CGROUP_CONTROLLER_REAL_MAX) - 1,

        CGROUP_MASK_BPF_FIREWALL = CGROUP_CONTROLLER_TO_MASK(CGROUP_CONTROLLER_BPF_FIREWALL),
        CGROUP_MASK_BPF_DEVICES = CGROUP_CONTROLLER_TO_MASK(CGROUP_CONTROLLER_BPF_DEVICES),
        CGROUP_MASK_BPF_FOREIGN = CGROUP_CONTROLLER_TO_MASK(CGROUP_CONTROLLER_BPF_FOREIGN),
        CGROUP_MASK_BPF_SOCKET_BIND = CGROUP_CONTROLLER_TO_MASK(CGROUP_CONTROLLER_BPF_SOCKET_BIND),
        CGROUP_MASK_BPF_RESTRICT_NETWORK_INTERFACES = CGROUP_CONTROLLER_TO_MASK(CGROUP_CONTROLLER_BPF_RESTRICT_NETWORK_INTERFACES),

        /* All cgroup v2 BPF pseudo-controllers */
        _CGROUP_MASK_BPF = CGROUP_MASK_BPF_FIREWALL|CGROUP_MASK_BPF_DEVICES|CGROUP_MASK_BPF_FOREIGN|CGROUP_MASK_BPF_SOCKET_BIND|CGROUP_MASK_BPF_RESTRICT_NETWORK_INTERFACES,

        _CGROUP_MASK_ALL = CGROUP_CONTROLLER_TO_MASK(_CGROUP_CONTROLLER_MAX) - 1,
} CGroupMask;

/* Special values for all weight knobs */
#define CGROUP_WEIGHT_INVALID UINT64_MAX
#define CGROUP_WEIGHT_IDLE UINT64_C(0)
#define CGROUP_WEIGHT_MIN UINT64_C(1)
#define CGROUP_WEIGHT_MAX UINT64_C(10000)
#define CGROUP_WEIGHT_DEFAULT UINT64_C(100)

#define CGROUP_LIMIT_MIN UINT64_C(0)
#define CGROUP_LIMIT_MAX UINT64_MAX

static inline bool CGROUP_WEIGHT_IS_OK(uint64_t x) {
        return
            x == CGROUP_WEIGHT_INVALID ||
            (x >= CGROUP_WEIGHT_MIN && x <= CGROUP_WEIGHT_MAX);
}

typedef enum CGroupIOLimitType {
        CGROUP_IO_RBPS_MAX,
        CGROUP_IO_WBPS_MAX,
        CGROUP_IO_RIOPS_MAX,
        CGROUP_IO_WIOPS_MAX,

        _CGROUP_IO_LIMIT_TYPE_MAX,
        _CGROUP_IO_LIMIT_TYPE_INVALID = -EINVAL,
} CGroupIOLimitType;

extern const uint64_t cgroup_io_limit_defaults[_CGROUP_IO_LIMIT_TYPE_MAX];

const char* cgroup_io_limit_type_to_string(CGroupIOLimitType t) _const_;
CGroupIOLimitType cgroup_io_limit_type_from_string(const char *s) _pure_;

/* Special values for the io.weight attribute */
#define CGROUP_IO_WEIGHT_INVALID UINT64_MAX
#define CGROUP_IO_WEIGHT_MIN UINT64_C(10)
#define CGROUP_IO_WEIGHT_MAX UINT64_C(1000)
#define CGROUP_IO_WEIGHT_DEFAULT UINT64_C(500)

static inline bool CGROUP_BLKIO_WEIGHT_IS_OK(uint64_t x) {
        return
            x == CGROUP_BLKIO_WEIGHT_INVALID ||
            (x >= CGROUP_BLKIO_WEIGHT_MIN && x <= CGROUP_BLKIO_WEIGHT_MAX);
}

int cg_path_open(const char *controller, const char *path);
int cg_cgroupid_open(int fsfd, uint64_t id);

typedef enum CGroupFlags {
        CGROUP_SIGCONT            = 1 << 0,
        CGROUP_IGNORE_SELF        = 1 << 1,
        CGROUP_DONT_SKIP_UNMAPPED = 1 << 2,
        CGROUP_NO_PIDFD           = 1 << 3,
} CGroupFlags;

int cg_enumerate_processes(const char *controller, const char *path, FILE **ret);
int cg_read_pid(FILE *f, pid_t *ret, CGroupFlags flags);
int cg_read_pidref(FILE *f, PidRef *ret, CGroupFlags flags);
int cg_read_event(const char *controller, const char *path, const char *event, char **ret);

int cg_enumerate_subgroups(const char *controller, const char *path, DIR **ret);
int cg_read_subgroup(DIR *d, char **ret);

typedef int (*cg_kill_log_func_t)(const PidRef *pid, int sig, void *userdata);

int cg_kill(const char *path, int sig, CGroupFlags flags, Set *s, cg_kill_log_func_t kill_log, void *userdata);
int cg_kill_kernel_sigkill(const char *path);
int cg_kill_recursive(const char *path, int sig, CGroupFlags flags, Set *s, cg_kill_log_func_t kill_log, void *userdata);

int cg_split_spec(const char *spec, char **ret_controller, char **ret_path);
int cg_mangle_path(const char *path, char **ret);

int cg_get_path(const char *controller, const char *path, const char *suffix, char **ret);
int cg_get_path_and_check(const char *controller, const char *path, const char *suffix, char **ret);

int cg_pid_get_path(const char *controller, pid_t pid, char **ret);
int cg_pidref_get_path(const char *controller, const PidRef *pidref, char **ret);

int cg_is_threaded(const char *path);

int cg_is_delegated(const char *path);
int cg_is_delegated_fd(int fd);

int cg_has_coredump_receive(const char *path);

typedef enum {
        CG_KEY_MODE_GRACEFUL = 1 << 0,
} CGroupKeyMode;

int cg_set_attribute(const char *controller, const char *path, const char *attribute, const char *value);
int cg_get_attribute(const char *controller, const char *path, const char *attribute, char **ret);
int cg_get_keyed_attribute_full(const char *controller, const char *path, const char *attribute, char **keys, char **values, CGroupKeyMode mode);

static inline int cg_get_keyed_attribute(
                const char *controller,
                const char *path,
                const char *attribute,
                char **keys,
                char **ret_values) {
        return cg_get_keyed_attribute_full(controller, path, attribute, keys, ret_values, 0);
}

static inline int cg_get_keyed_attribute_graceful(
                const char *controller,
                const char *path,
                const char *attribute,
                char **keys,
                char **ret_values) {
        return cg_get_keyed_attribute_full(controller, path, attribute, keys, ret_values, CG_KEY_MODE_GRACEFUL);
}

int cg_get_attribute_as_uint64(const char *controller, const char *path, const char *attribute, uint64_t *ret);

/* Does a parse_boolean() on the attribute contents and sets ret accordingly */
int cg_get_attribute_as_bool(const char *controller, const char *path, const char *attribute, bool *ret);

int cg_get_owner(const char *path, uid_t *ret_uid);

int cg_set_xattr(const char *path, const char *name, const void *value, size_t size, int flags);
int cg_get_xattr(const char *path, const char *name, void *value, size_t size);
int cg_get_xattr_malloc(const char *path, const char *name, char **ret);
/* Returns negative on error, and 0 or 1 on success for the bool value */
int cg_get_xattr_bool(const char *path, const char *name);
int cg_remove_xattr(const char *path, const char *name);

int cg_is_empty(const char *controller, const char *path);
int cg_is_empty_recursive(const char *controller, const char *path);

int cg_get_root_path(char **path);

int cg_path_get_cgroupid(const char *path, uint64_t *ret);
int cg_fd_get_cgroupid(int fd, uint64_t *ret);
int cg_path_get_session(const char *path, char **ret_session);
int cg_path_get_owner_uid(const char *path, uid_t *ret_uid);
int cg_path_get_unit(const char *path, char **ret_unit);
int cg_path_get_unit_path(const char *path, char **ret_unit);
int cg_path_get_user_unit(const char *path, char **ret_unit);
int cg_path_get_machine_name(const char *path, char **ret_machine);
int cg_path_get_slice(const char *path, char **ret_slice);
int cg_path_get_user_slice(const char *path, char **ret_slice);

int cg_shift_path(const char *cgroup, const char *cached_root, const char **ret_shifted);
int cg_pid_get_path_shifted(pid_t pid, const char *cached_root, char **ret_cgroup);

int cg_pid_get_session(pid_t pid, char **ret_session);
int cg_pid_get_owner_uid(pid_t pid, uid_t *ret_uid);
int cg_pid_get_unit(pid_t pid, char **ret_unit);
int cg_pidref_get_unit(const PidRef *pidref, char **ret);
int cg_pid_get_user_unit(pid_t pid, char **ret_unit);
int cg_pid_get_machine_name(pid_t pid, char **ret_machine);
int cg_pid_get_slice(pid_t pid, char **ret_slice);
int cg_pid_get_user_slice(pid_t pid, char **ret_slice);

int cg_path_decode_unit(const char *cgroup, char **ret_unit);

bool cg_needs_escape(const char *p);
int cg_escape(const char *p, char **ret);
char* cg_unescape(const char *p) _pure_;

bool cg_controller_is_valid(const char *p);

int cg_slice_to_path(const char *unit, char **ret);

int cg_mask_supported(CGroupMask *ret);
int cg_mask_supported_subtree(const char *root, CGroupMask *ret);
int cg_mask_from_string(const char *s, CGroupMask *ret);
int cg_mask_to_string(CGroupMask mask, char **ret);

int cg_kernel_controllers(Set **controllers);

bool cg_ns_supported(void);
bool cg_freezer_supported(void);
bool cg_kill_supported(void);

int cg_all_unified(void);
int cg_hybrid_unified(void);
int cg_unified_controller(const char *controller);
int cg_unified_cached(bool flush);
static inline int cg_unified(void) {
        return cg_unified_cached(true);
}

const char* cgroup_controller_to_string(CGroupController c) _const_;
CGroupController cgroup_controller_from_string(const char *s) _pure_;

bool is_cgroup_fs(const struct statfs *s);
bool fd_is_cgroup_fs(int fd);

typedef enum ManagedOOMMode {
        MANAGED_OOM_AUTO,
        MANAGED_OOM_KILL,
        _MANAGED_OOM_MODE_MAX,
        _MANAGED_OOM_MODE_INVALID = -EINVAL,
} ManagedOOMMode;

const char* managed_oom_mode_to_string(ManagedOOMMode m) _const_;
ManagedOOMMode managed_oom_mode_from_string(const char *s) _pure_;

typedef enum ManagedOOMPreference {
        MANAGED_OOM_PREFERENCE_NONE = 0,
        MANAGED_OOM_PREFERENCE_AVOID = 1,
        MANAGED_OOM_PREFERENCE_OMIT = 2,
        _MANAGED_OOM_PREFERENCE_MAX,
        _MANAGED_OOM_PREFERENCE_INVALID = -EINVAL,
} ManagedOOMPreference;

const char* managed_oom_preference_to_string(ManagedOOMPreference a) _const_;
ManagedOOMPreference managed_oom_preference_from_string(const char *s) _pure_;

/* The structure to pass to name_to_handle_at() on cgroupfs2 */
typedef union {
        struct file_handle file_handle;
        uint8_t space[offsetof(struct file_handle, f_handle) + sizeof(uint64_t)];
} cg_file_handle;

#define CG_FILE_HANDLE_INIT                                     \
        (cg_file_handle) {                                      \
                .file_handle.handle_bytes = sizeof(uint64_t),   \
                .file_handle.handle_type = FILEID_KERNFS,       \
        }

#define CG_FILE_HANDLE_CGROUPID(fh) (*(uint64_t*) (fh).file_handle.f_handle)
