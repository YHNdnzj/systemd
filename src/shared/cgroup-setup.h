/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "cgroup-util.h"

int cg_weight_parse(const char *s, uint64_t *ret);
int cg_cpu_weight_parse(const char *s, uint64_t *ret);

int cg_trim(int cgroupfs_fd, const char *path, bool delete_root);

int cg_create(int cgroupfs_fd, const char *path);
int cg_attach(int cgroupfs_fd, const char *path, pid_t pid);
int cg_fd_attach(int fd, pid_t pid);
int cg_create_and_attach(int cgroupfs_fd, const char *path, pid_t pid);

int cg_set_access(int cgroupfs_fd, const char *path, uid_t uid, gid_t gid);
int cg_set_access_recursive(int cgroupfs_fd, const char *path, uid_t uid, gid_t gid);

int cg_enable(
                int cgroupfs_fd,
                const char *path,
                CGroupMask supported,
                CGroupMask mask,
                CGroupMask *ret_result_mask);

int cg_migrate(int cgroupfs_fd, const char *source, const char *target, CGroupFlags flags);

int cg_has_legacy(void);
