/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/types.h>

#include "parse-util.h"
#include "systemctl-sysv-compat.h"
#include "systemctl.h"

int parse_shutdown_time_spec(const char *t, usec_t *ret) {
        int r;

        assert(t);
        assert(ret);

        if (streq(t, "now"))
                *ret = 0;
        else if (!strchr(t, ':')) {
                uint64_t u;

                if (safe_atou64(t, &u) < 0)
                        return -EINVAL;

                *ret = now(CLOCK_REALTIME) + USEC_PER_MINUTE * u;
        } else {
                char *e = NULL;
                long hour, minute;

                errno = 0;
                hour = strtol(t, &e, 10);
                if (errno > 0 || *e != ':' || hour < 0 || hour > 23)
                        return -EINVAL;

                minute = strtol(e+1, &e, 10);
                if (errno > 0 || *e != 0 || minute < 0 || minute > 59)
                        return -EINVAL;

                usec_t n = now(CLOCK_REALTIME);
                struct tm tm = {};

                r = localtime_or_gmtime_usec(n, /* utc= */ false, &tm);
                if (r < 0)
                        return r;

                tm.tm_hour = (int) hour;
                tm.tm_min = (int) minute;
                tm.tm_sec = 0;

                usec_t s;
                r = mktime_or_timegm_usec(&tm, /* utc= */ false, &s);
                if (r < 0)
                        return r;

                while (s <= n)
                        s += USEC_PER_DAY;

                *ret = s;
        }

        return 0;
}
