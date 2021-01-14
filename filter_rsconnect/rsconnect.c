/* -*- mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_filter_plugin.h>

static int cb_rsconnect_init(struct flb_filter_instance *f_ins,
                             struct flb_config *config,
                             void *data)
{
    return 0;
}

static int cb_rsconnect_filter(const void *data, size_t bytes,
                               const char *tag, int tag_len,
                               void **out_buf, size_t *out_size,
                               struct flb_filter_instance *f_ins,
                               void *context,
                               struct flb_config *config)
{
    return FLB_FILTER_NOTOUCH;
}

static int cb_rsconnect_exit(void *data, struct flb_config *config)
{
    return 0;
}

static struct flb_config_map config_map[] = {
    {0}
};

struct flb_filter_plugin filter_rsconnect_plugin = {
    .name         = "rsconnect",
    .description  = "Add RStudio Connect Metadata",
    .cb_init      = cb_rsconnect_init,
    .cb_filter    = cb_rsconnect_filter,
    .cb_exit      = cb_rsconnect_exit,
    .config_map   = config_map,
    .flags        = 0
};
