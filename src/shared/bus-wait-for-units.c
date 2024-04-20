/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-error.h"
#include "bus-map-properties.h"
#include "bus-wait-for-units.h"
#include "hashmap.h"
#include "string-util.h"
#include "strv.h"
#include "unit-def.h"

typedef struct WaitForItem {
        BusWaitForUnits *parent;

        BusWaitForUnitMetadata meta;

        BusWaitForUnitsFlags flags;

        sd_bus_slot *slot_get_all;
        sd_bus_slot *slot_properties_changed;

        bus_wait_for_units_unit_callback_t unit_callback;
        void *userdata;
} WaitForItem;

typedef struct BusWaitForUnits {
        sd_bus *bus;
        sd_bus_slot *slot_disconnected;

        Hashmap *items;

        BusWaitForUnitsState state;
        bool has_failed:1;
} BusWaitForUnits;

static WaitForItem* wait_for_item_free(WaitForItem *item) {
        int r;

        if (!item)
                return NULL;

        if (item->parent) {
                if (FLAGS_SET(item->flags, BUS_WAIT_REFFED) && item->meta.bus_path && item->parent->bus) {
                        r = sd_bus_call_method_async(
                                        item->parent->bus,
                                        NULL,
                                        "org.freedesktop.systemd1",
                                        item->bus_path,
                                        "org.freedesktop.systemd1.Unit",
                                        "Unref",
                                        NULL,
                                        NULL,
                                        NULL);
                        if (r < 0)
                                log_debug_errno(r, "Failed to drop reference to unit %s, ignoring: %m", item->bus_path);
                }

                assert_se(hashmap_remove_value(item->parent->items, item->bus_path, item));
        }

        sd_bus_slot_unref(item->slot_properties_changed);
        sd_bus_slot_unref(item->slot_get_all);

        free(item->meta.bus_path);
        free(item->meta.active_state);
        free(item->meta.sub_state);
        free(item->meta.clean_result);

        return mfree(item);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(WaitForItem*, wait_for_item_free);

static void wait_for_item_changed(WaitForItem *item, const BusWaitForUnitMetadata *changed, bool end) {
        assert(item);

        if (item->unit_callback)
                item->unit_callback(changed, end, item->userdata);

        if (end)
                wait_for_item_free(item);
}

BusWaitForUnits* bus_wait_for_units_free(BusWaitForUnits *d) {
        if (!d)
                return NULL;

        WaitForItem *item;
        while ((item = hashmap_first(d->items)))
                wait_for_item_changed(item, /* changed = */ NULL, /* end = */ true);

        d->items = hashmap_free(d->items);

        sd_bus_slot_unref(d->slot_disconnected);
        sd_bus_unref(d->bus);

        return mfree(d);
}

static int match_disconnected(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        BusWaitForUnits *d = ASSERT_PTR(userdata);

        assert(m);
        assert(sd_bus_message_get_bus(m) == d->bus);

        log_warning("D-Bus connection terminated while waiting for unit.");
        d->bus = sd_bus_close_unref(d->bus);

        return 0;
}

int bus_wait_for_units_new(sd_bus *bus, BusWaitForUnits **ret) {
        _cleanup_(bus_wait_for_units_freep) BusWaitForUnits *d = NULL;
        int r;

        assert(bus);
        assert(ret);

        d = new(BusWaitForUnits, 1);
        if (!d)
                return -ENOMEM;

        *d = (BusWaitForUnits) {
                .state = BUS_WAIT_SUCCESS,
                .bus = sd_bus_ref(bus),
        };

        r = sd_bus_match_signal_async(
                        bus,
                        &d->slot_disconnected,
                        "org.freedesktop.DBus.Local",
                        NULL,
                        "org.freedesktop.DBus.Local",
                        "Disconnected",
                        match_disconnected, NULL, d);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(d);
        return 0;
}

static bool bus_wait_for_units_is_complete(BusWaitForUnits *d) {
        assert(d);

        if (!d->bus) /* Disconnected? */
                return true;

        return hashmap_isempty(d->items);
}

static void bus_wait_for_units_check_complete(BusWaitForUnits *d) {
        assert(d);

        if (!bus_wait_for_units_is_complete(d))
                return;

        d->state = d->has_failed ? BUS_WAIT_FAILURE : BUS_WAIT_SUCCESS;
}

static bool wait_for_item_check_complete(WaitForItem *item) {
        assert(item);

        if (FLAGS_SET(item->flags, BUS_WAIT_FOR_MAINTENANCE_END)) {

                if (item->meta.clean_result && !streq(item->meta.clean_result, "success"))
                        item->parent->has_failed = true;

                if (!item->active_state || streq(item->active_state, "maintenance"))
                        return 0;
        }

        if (FLAGS_SET(item->flags, BUS_WAIT_NO_JOB) && item->meta.job_id != 0)
                return 0;

        /* Only service units would auto restart */
        if (FLAGS_SET(item->flags, BUS_WAIT_NO_RESTART) && item->meta.type == UNIT_SERVICE)
                if (STRPTR_IN_SET(item->sub_state,
                                  "dead-before-auto-restart", "failed-before-auto-restart",
                                  "auto-restart", "auto-restart-queued"))
                        return 0;

        if (FLAGS_SET(item->flags, BUS_WAIT_FOR_INACTIVE)) {

                if (streq_ptr(item->meta.active_state, "failed"))
                        item->parent->has_failed = true;
                else if (!streq_ptr(item->meta.active_state, "inactive"))
                        return 0;
        }

        return 1;
}

static int property_map_job_id(
                sd_bus *bus,
                const char *member,
                sd_bus_message *m,
                sd_bus_error *error,
                void *userdata) {

        uint32_t *job_id = ASSERT_PTR(userdata);

        assert(m);

        return sd_bus_message_read(m, "(uo)", job_id, /* path = */ NULL);
}

static int wait_for_item_process_properties(WaitForItem *item, sd_bus_message *m) {

        static const struct bus_properties_map map[] = {
                { "ActiveState", "s",    NULL,                offsetof(BusWaitForUnitMetadata, active_state) },
                { "SubState",    "s",    NULL,                offsetof(BusWaitForUnitMetadata, sub_state)    },
                { "CleanResult", "s",    NULL,                offsetof(BusWaitForUnitMetadata, clean_result) },
                { "Job",         "(uo)", property_map_job_id, offsetof(BusWaitForUnitMetadata, job_id)       },
                {}
        };

        BusWaitForUnitMetadata changed_meta = {
                .type = item->meta.type,
                .bus_path = item->bus_path,
                .job_id = UINT32_MAX,
        };
        int r;

        assert(item);
        assert(m);

        r = bus_message_map_all_properties(m, map, /* flags = */ 0, /* error = */ NULL, &changed_meta);
        if (r < 0)
                return r;

        if (changed_meta.active_state)
                RET_GATHER(r, free_and_strdup(&item->meta.active_state, changed_meta.active_state));
        if (changed_meta.sub_state)
                RET_GATHER(r, free_and_strdup(&item->meta.sub_state, changed_meta.sub_state));
        if (changed_meta.clean_result)
                RET_GATHER(r, free_and_strdup(&item->meta.clean_result, changed_meta.clean_result));
        if (changed_meta.job_id != UINT32_MAX)
                item->meta.job_id = changed_meta.job_id;
        if (r < 0)
                return r;

        r = wait_for_item_check_complete(item);
        wait_for_item_changed(item, changed_meta, r > 0);

        return 0;
}

static int on_properties_changed(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        WaitForItem *item = ASSERT_PTR(userdata);
        const char *interface;
        int r;

        assert(m);

        r = sd_bus_message_read(m, "s", &interface);
        if (r < 0) {
                log_debug_errno(r, "Failed to parse PropertiesChanged signal, ignoring: %m");
                return 0;
        }

        if (!streq(interface, "org.freedesktop.systemd1.Unit"))
                return 0;

        r = wait_for_item_process_properties(item, m);
        if (r < 0)
                log_debug_errno(r, "Failed to process PropertiesChanged signal: %m");

        return 0;
}

static int on_get_all_properties(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        WaitForItem *item = ASSERT_PTR(userdata);
        const sd_bus_error *e;
        int r;

        e = sd_bus_message_get_error(m);
        if (e) {
                item->parent->has_failed = true;

                r = sd_bus_error_get_errno(e);
                log_debug_errno(r, "GetAll() failed for %s: %s",
                                item->bus_path, bus_error_message(e, r));

                wait_for_item_changed(item, /* changed = */ NULL, /* end = */ true);
                return 0;
        }

        r = wait_for_item_process_properties(item, m);
        if (r < 0)
                log_debug_errno(r, "Failed to process GetAll method reply: %m");

        return 0;
}

int bus_wait_for_units_add_unit(
                BusWaitForUnits *d,
                const char *unit,
                BusWaitForUnitsFlags flags,
                bus_wait_for_units_unit_callback_t callback,
                void *userdata) {

        _cleanup_(wait_for_item_freep) WaitForItem *item = NULL;
        _cleanup_free_ char *bus_path = NULL;
        UnitType type;
        int r;

        assert(d);
        assert(unit);
        assert((flags & _BUS_WAIT_FOR_TARGET) != 0);

        type = unit_name_to_type(unit);
        if (type < 0)
                return -EINVAL;

        bus_path = unit_dbus_path_from_name(unit);
        if (!bus_path)
                return -ENOMEM;

        if (hashmap_contains(d->items, bus_path))
                return 0;

        item = new(WaitForItem, 1);
        if (!item)
                return -ENOMEM;

        *item = (WaitForItem) {
                .meta.type = type,
                .meta.bus_path = TAKE_PTR(bus_path),
                .meta.job_id = UINT32_MAX,
                .flags = flags,
                .unit_callback = callback,
                .userdata = userdata,
        };

        if (!FLAGS_SET(item->flags, BUS_WAIT_REFFED)) {
                r = sd_bus_call_method_async(
                                d->bus,
                                NULL,
                                "org.freedesktop.systemd1",
                                item->bus_path,
                                "org.freedesktop.systemd1.Unit",
                                "Ref",
                                NULL,
                                NULL,
                                NULL);
                if (r < 0)
                        return log_debug_errno(r, "Failed to add reference to unit %s: %m", unit);

                item->flags |= BUS_WAIT_REFFED;
        }

        r = sd_bus_match_signal_async(
                        d->bus,
                        &item->slot_properties_changed,
                        "org.freedesktop.systemd1",
                        item->bus_path,
                        "org.freedesktop.DBus.Properties",
                        "PropertiesChanged",
                        on_properties_changed,
                        NULL,
                        item);
        if (r < 0)
                return log_debug_errno(r, "Failed to request match for PropertiesChanged signal: %m");

        r = sd_bus_call_method_async(
                        d->bus,
                        &item->slot_get_all,
                        "org.freedesktop.systemd1",
                        item->bus_path,
                        "org.freedesktop.DBus.Properties",
                        "GetAll",
                        on_get_all_properties,
                        item,
                        "s", FLAGS_SET(item->flags, BUS_WAIT_FOR_MAINTENANCE_END) ? NULL : "org.freedesktop.systemd1.Unit");
        if (r < 0)
                return log_debug_errno(r, "Failed to request properties of unit %s: %m", unit);

        r = hashmap_ensure_put(d->items, &string_hash_ops, item->bus_path, item);
        if (r < 0)
                return r;
        assert(r > 0);

        d->state = BUS_WAIT_RUNNING;
        item->parent = d;
        TAKE_PTR(item);

        return 1;
}

int bus_wait_for_units_run(BusWaitForUnits *d) {
        int r;

        assert(d);

        while (d->state == BUS_WAIT_RUNNING) {

                r = sd_bus_process(d->bus, NULL);
                if (r < 0)
                        return r;
                if (r > 0) {
                        bus_wait_for_units_check_complete(d);
                        continue;
                }

                r = sd_bus_wait(d->bus, UINT64_MAX);
                if (r < 0)
                        return r;
        }

        return d->state;
}

BusWaitForUnitsState bus_wait_for_units_state(BusWaitForUnits *d) {
        assert(d);

        return d->state;
}
