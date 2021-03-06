/* -*- mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * Copyright 2021 Aaron Jacobs
 *
 * This plugin is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This plugin is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this plugin; if not, see https://www.gnu.org/licenses/.
 */

#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_pack.h>

struct rsconnect_ctx {
    /* API configuration. */
    flb_sds_t api_url;
    flb_sds_t api_key;

    /* HTTP client buffer size. */
    size_t buffer_size;

    /* TLS configuration. */
    int tls_debug;
    int tls_verify;
    flb_sds_t tls_vhost;

    /* Computed Authorization header. */
    flb_sds_t auth;

    /* Connection to the RStudio Connect API. */
    struct flb_tls *tls;
    struct flb_upstream *upstream;

    /* RStudio Connect job metadata cache. */
    struct flb_hash *hash_table;
};

struct rsconnect_meta {
    int bundle_id;
    flb_sds_t name;
    flb_sds_t mode;
    int fields;
};

static void rsconnect_ctx_destroy(struct rsconnect_ctx *ctx)
{
    if (!ctx) {
        return;
    }

    if (ctx->hash_table) {
        flb_hash_destroy(ctx->hash_table);
    }
    if (ctx->upstream) {
        flb_upstream_destroy(ctx->upstream);
    }
    if (ctx->tls) {
        flb_tls_destroy(ctx->tls);
    }
    if (ctx->auth) {
        flb_sds_destroy(ctx->auth);
    }

    flb_free(ctx);
}

static int cb_rsconnect_init(struct flb_filter_instance *f_ins,
                             struct flb_config *config,
                             void *data)
{
    int off;
    int ret;
    flb_sds_t api_host;
    int api_port;
    struct rsconnect_ctx *ctx = NULL;
    const char *tmp = NULL;
    const char *ptr = NULL;
    int io_type = FLB_IO_TCP;
    (void) config;
    (void) data;

    ctx = flb_calloc(1, sizeof(struct rsconnect_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    ret = flb_filter_config_map_set(f_ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(f_ins, "configuration error");
        rsconnect_ctx_destroy(ctx);
        return -1;
    }

    /* Required fields. */

    if (!ctx->api_key) {
        flb_plg_error(f_ins, "configuration error: missing 'api_key'");
        rsconnect_ctx_destroy(ctx);
        return -1;
    }
    ctx->auth = flb_sds_create_len("Key ", 4);
    ctx->auth = flb_sds_cat(ctx->auth, ctx->api_key, flb_sds_len(ctx->api_key));

    /* Parse the URL for port/scheme info. This is mostly cribbed from the
       Kubernetes filter plugin. */

    tmp = ctx->api_url;
    if (!tmp) {
        flb_plg_error(f_ins, "missing URL");
        rsconnect_ctx_destroy(ctx);
        return -1;
    }
    if (strncmp(tmp, "http://", 7) == 0) {
        off = 7;
    }
    else if (strncmp(tmp, "https://", 8) == 0) {
        off = 8;
        io_type = FLB_IO_TLS;
    }
    else {
        flb_plg_error(f_ins, "invalid URL scheme: %s", tmp);
        rsconnect_ctx_destroy(ctx);
        return -1;
    }
    ptr = tmp + off;
    tmp = strchr(ptr, ':');
    if (tmp) {
        api_host = flb_sds_create_len(ptr, tmp - ptr);
        tmp++;
        api_port = atoi(tmp);
    }
    else {
        api_host = flb_sds_create(ptr);
        api_port = io_type == FLB_IO_TLS ? 443 : 80;
    }

    flb_plg_info(f_ins, "https=%i host=%s port=%i", io_type == FLB_IO_TLS,
                 api_host, api_port);

    if (io_type == FLB_IO_TLS) {
        ctx->tls = flb_tls_create(ctx->tls_verify, ctx->tls_debug,
                                  ctx->tls_vhost, NULL, NULL, NULL, NULL, NULL);
        if (!ctx->tls) {
            flb_plg_error(f_ins, "TLS initialization error");
            flb_sds_destroy(api_host);
            rsconnect_ctx_destroy(ctx);
            return -1;
        }
        flb_plg_info(f_ins, "tls.verify=%d tls.debug=%d tls.vhost=%s",
                     ctx->tls->verify, ctx->tls->debug,
                     ctx->tls->vhost ? ctx->tls->vhost : "(nil)");
    }

    ctx->upstream = flb_upstream_create(config, api_host, api_port, io_type,
                                        ctx->tls);
    flb_sds_destroy(api_host);
    if (!ctx->upstream) {
        flb_plg_error(f_ins, "connection initialization error");
        rsconnect_ctx_destroy(ctx);
        return -1;
    }
    /* Remove async flag from upstream */
    ctx->upstream->flags &= ~(FLB_IO_ASYNC);

    ctx->hash_table = flb_hash_create(FLB_HASH_EVICT_LESS_USED, 256, 256);
    if (!ctx->hash_table) {
        flb_plg_error(f_ins, "hash table initialization error");
        flb_free(ctx);
        return -1;
    }

    flb_filter_set_context(f_ins, ctx);
    return 0;
}

static int parse_tag(struct flb_filter_instance *f_ins,
                     const char *tag, int tag_len,
                     flb_sds_t *job, flb_sds_t *session, flb_sds_t *stream)
{
    char *ptr;
    char *tmp;

    ptr = strstr(tag, ".jobs.");
    if (!ptr) {
        /* This is not tagged like an RStudio Connect job log. */
        flb_plg_warn(f_ins, "invalid tag pattern: no matching /jobs/ directory");
        return -1;
    }
    ptr += 6;

    /* We should now have something like "1016.C8gnyvdqvAF1ZVd8.job.stderr". */
    tmp = strchr(ptr, '.');
    if (!tmp) {
        flb_plg_warn(f_ins, "invalid tag pattern: no matching job id");
        return -1;
    }
    else {
        *job = flb_sds_create_len(ptr, tmp - ptr);
        ptr = tmp;
        ptr++;
    }

    tmp = strchr(ptr, '.');
    if (!tmp) {
        flb_plg_warn(f_ins, "invalid tag pattern: no matching session id");
        flb_sds_destroy(*job);
        return -1;
    }
    else {
        *session = flb_sds_create_len(ptr, tmp - ptr);
        ptr = tmp;
        ptr++;
    }

    tmp = strstr(ptr, "job.");
    if (!tmp) {
        flb_plg_warn(f_ins, "invalid tag pattern: no matching stream");
        flb_sds_destroy(*job);
        flb_sds_destroy(*session);
        return -1;
    }
    ptr += 4;
    *stream = flb_sds_create_len(ptr, tag_len - (ptr - tag));

    return 0;
}

/*
 * Small helper for the common operation of writing key-value string pairs into
 * a msgpack packer.
 */
static void pack_sds_kv(msgpack_packer *pck, char *key, size_t key_len,
                        flb_sds_t val)
{
    msgpack_pack_str(pck, key_len);
    msgpack_pack_str_body(pck, key, key_len);
    msgpack_pack_str(pck, flb_sds_len(val));
    msgpack_pack_str_body(pck, val, flb_sds_len(val));
}

/* Gather metadata from API Server */
static int get_job_api_metadata(struct flb_filter_instance *f_ins,
                                struct rsconnect_ctx *ctx,
                                const char *job,
                                struct rsconnect_meta *meta)
{
    int i;
    int root_type;
    size_t bytes_sent;
    char uri[64];
    struct flb_http_client *client;
    struct flb_upstream_conn *conn;
    size_t size;
    msgpack_unpacked result;
    msgpack_object k;
    msgpack_object v;
    int ret = 0;
    size_t off = 0;
    char *data = NULL;
    char *guid = NULL;

    if (!job) {
        return 0;
    }

    conn = flb_upstream_conn_get(ctx->upstream);
    if (!conn) {
        flb_plg_error(f_ins, "upstream connection error");
        return -1;
    }

    /*
     * First, we need to get the "content GUID" for these logs, so that we can
     * query the official content endpoint for relevant info. There is currently
     * no official way to map from job IDs to applications, but there is an
     * undocumented API I have been told is relatively safe to use for now.
     *
     * This involves (1) building and making an HTTP request; and (2) parsing
     * the necessary keys out the JSON (by converting to msgpack, first).
     */

    snprintf(uri, sizeof(uri) - 1, "/__api__/applications/%s", job);

    client = flb_http_client(conn, FLB_HTTP_GET, uri, NULL, 0, NULL, 0, NULL, 0);
    if (!client) {
        flb_plg_error(f_ins, "http client error");
        flb_upstream_conn_release(conn);
        return -1;
    }

    flb_http_buffer_size(client, ctx->buffer_size);
    flb_http_add_header(client, "User-Agent", 10, "Fluent-Bit", 10);
    flb_http_add_header(client, "Authorization", 13, ctx->auth,
                        flb_sds_len(ctx->auth));

    ret = flb_http_do(client, &bytes_sent);
    if (ret < 0) {
        flb_plg_error(f_ins, "http_do=%d", ret);
        goto release;
    }

    if (client->resp.status == 404) {
        /* It's arguable that this should be a hard error instead. */
        flb_plg_warn(f_ins, "can't find job %s in the API", job);
        ret = -1;
        goto release;
    }
    else if (client->resp.status != 200) {
        if (client->resp.payload_size > 0) {
            flb_plg_warn(f_ins, "unexpected job lookup response: status=%d body=\"%s\"",
                         client->resp.status, client->resp.payload);
        }
        else {
            flb_plg_warn(f_ins, "unexpected job lookup response: status=%d",
                         client->resp.status);
        }
        ret = -1;
        goto release;
    }

    ret = flb_pack_json(client->resp.payload, client->resp.payload_size, &data,
                        &size, &root_type);
    if (ret < 0) {
        flb_plg_error(f_ins, "failed to deserialize job lookup: error=%d size=%d body=\"%s\"",
                      ret, client->resp.payload_size, client->resp.payload);
        goto release;
    }

    msgpack_unpacked_init(&result);
    if (msgpack_unpack_next(&result, data, size, &off) != MSGPACK_UNPACK_SUCCESS) {
        flb_plg_error(f_ins, "unexpected unpack error");
        msgpack_unpacked_destroy(&result);
        ret = -1;
        goto release;
    }
    if (result.data.type != MSGPACK_OBJECT_MAP){
        flb_plg_error(f_ins, "unexpected job lookup response: not a JSON object");
        msgpack_unpacked_destroy(&result);
        flb_free(data);
        ret = -1;
        goto release;
    }
    for (i = 0; i < result.data.via.map.size; i++) {
        k = result.data.via.map.ptr[i].key;
        v = result.data.via.map.ptr[i].val;
        if (k.via.str.size == 4 && strncmp(k.via.str.ptr, "guid", 4) == 0) {
            guid = flb_strndup(v.via.str.ptr, v.via.str.size);
        }
        if (k.via.str.size == 9 && strncmp(k.via.str.ptr, "bundle_id", 9) == 0) {
            meta->bundle_id = (int) v.via.i64;
            meta->fields++;
        }
    }
    msgpack_unpacked_destroy(&result);
    flb_free(data);

    if (!guid) {
        flb_plg_error(f_ins, "unexpected job lookup response: no \"guid\" key");
        ret = -1;
        goto release;
    }
    if (!meta->bundle_id) {
        flb_plg_warn(f_ins, "unexpected job lookup response: no \"bundle_id\" key");
    }

    flb_http_client_destroy(client);

    /* Second, we use "content GUID" to get further information for the job. */

    snprintf(uri, sizeof(uri) - 1, "/__api__/v1/content/%s", guid);
    flb_free(guid);

    client = flb_http_client(conn, FLB_HTTP_GET, uri, NULL, 0, NULL, 0, NULL, 0);
    if (!client) {
        flb_plg_error(f_ins, "http client error");
        flb_upstream_conn_release(conn);
        return -1;
    }

    flb_http_buffer_size(client, ctx->buffer_size);
    flb_http_add_header(client, "User-Agent", 10, "Fluent-Bit", 10);
    flb_http_add_header(client, "Authorization", 13, ctx->auth,
                        flb_sds_len(ctx->auth));

    ret = flb_http_do(client, &bytes_sent);
    if (ret < 0) {
        flb_plg_error(f_ins, "http_do=%d", ret);
        goto release;
    }

    if (client->resp.status == 404) {
        flb_plg_warn(f_ins, "guid not found -- RSConnect may be outdated");
        ret = -1;
        goto release;
    }
    else if (client->resp.status != 200) {
        if (client->resp.payload_size > 0) {
            flb_plg_warn(f_ins, "unexpected content lookup response: status=%d body=\"%s\"",
                         client->resp.status, client->resp.payload);
        }
        else {
            flb_plg_warn(f_ins, "unexpected content lookup response: status=%d",
                         client->resp.status);
        }
        ret = -1;
        goto release;
    }

    ret = flb_pack_json(client->resp.payload, client->resp.payload_size, &data,
                        &size, &root_type);
    if (ret < 0) {
        flb_plg_error(f_ins, "failed to deserialize content lookup: error=%d size=%d body=\"%s\"",
                      ret, client->resp.payload_size, client->resp.payload);
        goto release;
    }

    /* flb_pack_print(data, size); */

    off = 0;
    msgpack_unpacked_init(&result);
    if (msgpack_unpack_next(&result, data, size, &off) != MSGPACK_UNPACK_SUCCESS) {
        flb_plg_error(f_ins, "unexpected unpack error");
        msgpack_unpacked_destroy(&result);
        ret = -1;
        goto release;
    }
    if (result.data.type != MSGPACK_OBJECT_MAP){
        flb_plg_error(f_ins, "unexpected content lookup response: not a JSON object");
        msgpack_unpacked_destroy(&result);
        flb_free(data);
        ret = -1;
        goto release;
    }
    for (i = 0; i < result.data.via.map.size; i++) {
        k = result.data.via.map.ptr[i].key;
        v = result.data.via.map.ptr[i].val;
        if (k.via.str.size == 4 && strncmp(k.via.str.ptr, "name", 4) == 0) {
            meta->name = flb_sds_create_len(v.via.str.ptr, v.via.str.size);
            meta->fields++;
        }
        if (k.via.str.size == 8 && strncmp(k.via.str.ptr, "app_mode", 8) == 0) {
            meta->mode = flb_sds_create_len(v.via.str.ptr, v.via.str.size);
            meta->fields++;
        }
    }
    msgpack_unpacked_destroy(&result);
    flb_free(data);

    if (!meta->name) {
        flb_plg_warn(f_ins, "unexpected content lookup response: no \"name\" key");
    }
    if (!meta->mode) {
        flb_plg_warn(f_ins, "unexpected content lookup response: no \"app_mode\" key");
    }

    ret = 0;
 release:
    flb_http_client_destroy(client);
    flb_upstream_conn_release(conn);
    return ret;
}

static int cb_rsconnect_filter(const void *data, size_t bytes,
                               const char *tag, int tag_len,
                               void **out_buf, size_t *out_size,
                               struct flb_filter_instance *f_ins,
                               void *context,
                               struct flb_config *config)
{
    msgpack_unpacked result;
    msgpack_sbuffer buffer;
    msgpack_packer packer;
    struct flb_time tm;
    msgpack_object *obj;
    msgpack_object map;
    int i;
    flb_sds_t job;
    flb_sds_t session;
    flb_sds_t stream;
    int id;
    const char *meta_buff;
    size_t meta_size;
    msgpack_unpacked fields;
    msgpack_sbuffer meta_sbuf;
    msgpack_packer meta_pck;
    struct rsconnect_ctx *ctx = context;
    size_t off = 0;
    int modified = 0;
    size_t meta_off = 0;
    struct rsconnect_meta meta = {0};
    (void) config;

    /* Parse the tag to determine job-related metadata. */

    if (parse_tag(f_ins, tag, tag_len, &job, &session, &stream) < 0) {
        return FLB_FILTER_NOTOUCH;
    }
    /* flb_plg_debug(f_ins, "job=%s session=%s stream=%s path=%s", job, session, stream, path); */

    /* Look up (or create) the remaining job-related metadata. */

    id = flb_hash_get(ctx->hash_table, job, strlen(job),
                      (void **) &meta_buff, &meta_size);
    if (id == -1) {
        /* Grab metadata from the RStudio Connect API. */
        get_job_api_metadata(f_ins, ctx, job, &meta);
        flb_plg_info(f_ins, "get_job_api_metadata(): job=%s bundle_id=%d name=%s app_mode=%s",
                     job, meta.bundle_id, meta.name ? meta.name : "(nil)",
                     meta.mode ? meta.mode : "(nil)");

        /* Serialise all metadata fields via msgpack. */

        msgpack_sbuffer_init(&meta_sbuf);
        msgpack_packer_init(&meta_pck, &meta_sbuf, msgpack_sbuffer_write);
        msgpack_pack_map(&meta_pck, meta.fields);

        if (meta.bundle_id) {
            msgpack_pack_str(&meta_pck, 6);
            msgpack_pack_str_body(&meta_pck, "bundle", 6);
            msgpack_pack_int(&meta_pck, meta.bundle_id);
        }
        if (meta.name) {
            pack_sds_kv(&meta_pck, "name", 4, meta.name);
            flb_sds_destroy(meta.name);
        }
        if (meta.mode) {
            pack_sds_kv(&meta_pck, "app_mode", 8, meta.mode);
            flb_sds_destroy(meta.mode);
        }

        id = flb_hash_add(ctx->hash_table, job, flb_sds_len(job),
                          meta_sbuf.data, meta_sbuf.size);
        if (id >= 0) {
            flb_hash_get_by_id(ctx->hash_table, id, job, &meta_buff, &meta_size);
        }
        else {
            flb_plg_error(f_ins, "failed to add hash: job=%s error=%d", job, id);
        }
        msgpack_sbuffer_destroy(&meta_sbuf);
    }

    msgpack_unpacked_init(&result);
    msgpack_sbuffer_init(&buffer);
    msgpack_packer_init(&packer, &buffer, msgpack_sbuffer_write);

    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        /* Ignore records that do not come in the usual format:
           [ TIMESTAMP, { K:V, ...} ], ... */
        if (result.data.type != MSGPACK_OBJECT_ARRAY ||
            result.data.via.array.size != 2 ||
            result.data.via.array.ptr[1].type != MSGPACK_OBJECT_MAP) {
            flb_plg_warn(f_ins, "unexpected record format");
            msgpack_pack_object(&packer, result.data);
            continue;
        }

        /* Initialize the metadata map. */
        msgpack_unpacked_init(&fields);
        msgpack_unpack_next(&fields, meta_buff, meta_size, &meta_off);

        /* Add the existing timestamp and key-value pairs. */
        flb_time_pop_from_msgpack(&tm, &result, &obj);
        msgpack_pack_array(&packer, 2);
        flb_time_append_to_msgpack(&tm, &packer, 0);
        map = result.data.via.array.ptr[1];
        msgpack_pack_map(&packer, map.via.map.size + fields.data.via.map.size + 3);
        for (i = 0; i < map.via.map.size; i++) {
            msgpack_pack_object(&packer, map.via.map.ptr[i].key);
            msgpack_pack_object(&packer, map.via.map.ptr[i].val);
        }

        /* Add stream-specific metadata. */
        pack_sds_kv(&packer, "job", 3, job);
        pack_sds_kv(&packer, "session", 7, session);
        pack_sds_kv(&packer, "stream", 6, stream);

        /* Add Connect metadata. */
        for (i = 0; i < fields.data.via.map.size; i++) {
            msgpack_pack_object(&packer, fields.data.via.map.ptr[i].key);
            msgpack_pack_object(&packer, fields.data.via.map.ptr[i].val);
        }
        msgpack_unpacked_destroy(&fields);

        modified++;
    }
    msgpack_unpacked_destroy(&result);
    flb_sds_destroy(job);
    flb_sds_destroy(session);
    flb_sds_destroy(stream);

    if (!modified) {
        msgpack_sbuffer_destroy(&buffer);
        return FLB_FILTER_NOTOUCH;
    }

    *out_buf = buffer.data;
    *out_size = buffer.size;

    return FLB_FILTER_MODIFIED;
}

static int cb_rsconnect_exit(void *data, struct flb_config *config)
{
    (void) config;
    rsconnect_ctx_destroy((struct rsconnect_ctx *) data);
    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "api_url", "http://localhost:3939",
     0, FLB_TRUE, offsetof(struct rsconnect_ctx, api_url),
     "RStudio Connect server URL."
    },
    {
     FLB_CONFIG_MAP_STR, "api_key", NULL,
     0, FLB_TRUE, offsetof(struct rsconnect_ctx, api_key),
     "RStudio Connect API Key."
    },
    {
     FLB_CONFIG_MAP_SIZE, "buffer_size", "32K",
     0, FLB_TRUE, offsetof(struct rsconnect_ctx, buffer_size),
     "Buffer size for the API client",
    },
    /* TLS */
    {
     FLB_CONFIG_MAP_INT, "tls.debug", "4",
     0, FLB_TRUE, offsetof(struct rsconnect_ctx, tls_debug),
     "set TLS debug level: 0 (no debug), 1 (error), "
     "2 (state change), 3 (info) and 4 (verbose)"
    },
    {
     FLB_CONFIG_MAP_BOOL, "tls.verify", "true",
     0, FLB_TRUE, offsetof(struct rsconnect_ctx, tls_verify),
     "enable or disable verification of TLS peer certificate"
    },
    {
     FLB_CONFIG_MAP_STR, "tls.vhost", NULL,
     0, FLB_TRUE, offsetof(struct rsconnect_ctx, tls_vhost),
     "set optional TLS virtual host"
    },
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
