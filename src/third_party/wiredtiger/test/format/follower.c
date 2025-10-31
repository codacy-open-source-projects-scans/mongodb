/*-
 * Public Domain 2014-present MongoDB, Inc.
 * Public Domain 2008-2014 WiredTiger, Inc.
 *
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include "format.h"

/*
 * follower --
 *     Periodically check for a new checkpoint from the leader, and reconfigure to use it.
 */
WT_THREAD_RET
follower(void *arg)
{
    SAP sap;
    WT_CONNECTION *conn;
    WT_ITEM checkpoint_metadata;
    WT_PAGE_LOG *page_log;
    WT_SESSION *session;
    const char *disagg_page_log;
    char config[128];
    u_int period;
    uint64_t checkpoint_ts;

    (void)(arg); /* Unused parameter */
    conn = g.wts_conn;
    disagg_page_log = (char *)GVS(DISAGG_PAGE_LOG);
    memset(&sap, 0, sizeof(sap));
    memset(&checkpoint_metadata, 0, sizeof(checkpoint_metadata));

    wt_wrap_open_session(conn, &sap, NULL, NULL, &session);
    testutil_check(conn->get_page_log(conn, disagg_page_log, &page_log));

    while (!g.workers_finished) {
        /*
         * FIXME-WT-15788: Eventually have the leader send checkpoint metadata to the follower (via
         * shared memory or pipe) so it can be picked up. Required once we start running against the
         * library version of PALI, which doesn't implement pl_get_complete_checkpoint_ext().
         */
        testutil_check(page_log->pl_get_complete_checkpoint_ext(
          page_log, session, NULL, NULL, &checkpoint_ts, &checkpoint_metadata));
        /* Only reconfigure if there's a new checkpoint. */
        if (g.last_checkpoint_ts != checkpoint_ts) {
            testutil_snprintf(config, sizeof(config), "disaggregated=(checkpoint_meta=\"%.*s\")",
              (int)checkpoint_metadata.size, (const char *)checkpoint_metadata.data);
            testutil_check(conn->reconfigure(conn, config));
            printf("--- [Follower] Picked up checkpoint (LSN=%.*s,timestamp=%" PRIu64 ") ---\n",
              (int)checkpoint_metadata.size, (const char *)checkpoint_metadata.data, checkpoint_ts);
            g.last_checkpoint_ts = checkpoint_ts;
        }
        period = mmrand(&g.extra_rnd, 1, 3);
        while (period > 0 && !g.workers_finished) {
            --period;
            __wt_sleep(1, 0);
        }
    }

    wt_wrap_close_session(session);

    return (WT_THREAD_RET_VALUE);
}
