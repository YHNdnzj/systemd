/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "cgroup-util.h"

bool cg_has_legacy(void);

int cg_weight_parse(const char *s, uint64_t *ret);
int cg_cpu_weight_parse(const char *s, uint64_t *ret);

int cg_trim(const char *controller, const char *path, bool delete_root);

int cg_create(const char *controller, const char *path);
int cg_attach(const char *controller, const char *path, pid_t pid);
int cg_fd_attach(int fd, pid_t pid);
int cg_attach_fallback(const char *controller, const char *path, pid_t pid);
int cg_create_and_attach(const char *controller, const char *path, pid_t pid);

int cg_set_access(const char *controller, const char *path, uid_t uid, gid_t gid);
int cg_set_access_recursive(const char *controller, const char *path, uid_t uid, gid_t gid);

int cg_migrate(const char *cfrom, const char *pfrom, const char *cto, const char *pto, CGroupFlags flags);

typedef const char* (*cg_migrate_callback_t)(CGroupMask mask, void *userdata);
