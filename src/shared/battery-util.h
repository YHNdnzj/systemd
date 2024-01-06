/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-device.h"

/* Let's make this the lower bound, since we have battery-check and it would reject <= 5% anyway.
 * IOW, battery_is_discharging_and_low() should be stricter so that there's no ambiguity. */
#define BATTERY_LOW_CAPACITY_LEVEL_MIN 5U

int on_ac_power(void);

int battery_is_discharging_and_low_full(unsigned percent);
static int battery_is_discharging_and_low(void) {
        return battery_is_discharging_and_low_full(BATTERY_LOW_CAPACITY_LEVEL_MIN);
}

int battery_enumerator_new(sd_device_enumerator **ret);
int battery_read_capacity_percentage(sd_device *dev);
