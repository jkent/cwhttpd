/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
ESP32 route handler/template routines for the /wifi url.
 */

#include "log.h"
#include "kref.h"
#include "libesphttpd/route.h"

#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <freertos/FreeRTOS.h>
#include <freertos/timers.h>
#include <freertos/event_groups.h>

#include <esp_event.h>
#include <esp_wifi_types.h>
#include <esp_wifi.h>
#include <esp_wps.h>


static const char *TAG = "cgiwifi";
/* Enable this to disallow any changes in AP settings. */
//#define DEMO_MODE

#define MAX_NUM_APS     32
#define SCAN_TIMEOUT    (60 * 1000 / portTICK_PERIOD_MS)
#define CFG_TIMEOUT     (60 * 1000 / portTICK_PERIOD_MS)
#define CFG_TICKS       (1000 / portTICK_PERIOD_MS)
#define CFG_DELAY       (100 / portTICK_PERIOD_MS)

/* Jiffy overflow handling stolen from Linux kernel. Needed to check *\
\* for timeouts.                                                     */
#define typecheck(type,x) \
        ({  type __dummy; \
        typeof(x) __dummy2; \
        (void)(&__dummy == &__dummy2); \
        1; \
})

#define time_after(a,b)     \
        (typecheck(unsigned int, a) && \
                typecheck(unsigned int, b) && \
                ((long)((b) - (a)) < 0))

/* States used during WiFi (re)configuration. */
enum cfg_state {
    /* "stable" states */
    cfg_state_failed,
    cfg_state_connected,
    cfg_state_idle,

    /* transitional states */
    cfg_state_update,
    cfg_state_wps_start,
    cfg_state_wps_active,
    cfg_state_connecting,
    cfg_state_fallback,
};

const char *state_names[] = {
        "Failed",
        "Connected",
        "Idle",
        "Update",
        "WPS Start",
        "WPS Active",
        "Connecting",
        "Fall Back"
};

/* Holds complete WiFi config for both STA and AP, the mode and whether *\
\* the WiFi should connect to an AP in STA or APSTA mode.               */
struct wifi_cfg {
    bool connect;
    wifi_mode_t mode;
    wifi_config_t sta;
    wifi_config_t ap;
};

/* This holds all the information needed to transition from the current  *\
 * to the requested WiFi configuration. See handle_config_timer() and    *
\* update_wifi() on how to use this.                                     */
struct wifi_cfg_state {
    SemaphoreHandle_t lock;
    TickType_t timestamp;
    enum cfg_state state;
    struct wifi_cfg saved_cfg;
    struct wifi_cfg new_cfg;
};

static struct wifi_cfg_state cfg_state;

/* For keeping track of system events. */
const static int BIT_CONNECTED      = BIT0;
const static int BIT_WPS_SUCCESS    = BIT1;
const static int BIT_WPS_FAILED     = BIT2;
#define BITS_WPS    (BIT_WPS_SUCCESS | BIT_WPS_FAILED)

static EventGroupHandle_t wifi_events = NULL;

struct scan_data {
    struct kref ref_cnt;
    wifi_ap_record_t *ap_records;
    uint16_t num_records;
};

struct ap_data_iter{
    struct scan_data *data;
    uint16_t idx;
};


static volatile atomic_bool scan_in_progress = ATOMIC_VAR_INIT(false);
static SemaphoreHandle_t data_lock = NULL;
static struct scan_data *last_scan = NULL;
static TimerHandle_t *scan_timer = NULL;
static TimerHandle_t *config_timer = NULL;

static void handle_scan_timer(TimerHandle_t timer);
static void handle_config_timer(TimerHandle_t timer);


/* Initialise data structures. Needs to be called before any other function, *\
\* including the system event handler.                                       */
esp_err_t ehttpd_wifi_init(void)
{
    esp_err_t result;

    configASSERT(wifi_events == NULL);
    configASSERT(data_lock == NULL);
    configASSERT(cfg_state.lock == NULL);
    configASSERT(scan_timer == NULL);
    configASSERT(config_timer == NULL);

    result = ESP_OK;
    memset(&cfg_state, 0x0, sizeof(cfg_state));
    cfg_state.state = cfg_state_idle;

    wifi_events = xEventGroupCreate();
    if (wifi_events == NULL) {
        EHTTPD_LOGE(TAG, "Unable to create event group.");
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }

    data_lock = xSemaphoreCreateMutex();
    if (data_lock == NULL) {
        EHTTPD_LOGE(TAG, "Unable to create scan data lock.");
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }

    cfg_state.lock = xSemaphoreCreateMutex();
    if (cfg_state.lock == NULL) {
        EHTTPD_LOGE(TAG, "Unable to create state lock.");
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }

    scan_timer = xTimerCreate("Scan_Timer",
            SCAN_TIMEOUT,
            pdFALSE, NULL, handle_scan_timer);
    if (scan_timer == NULL) {
        EHTTPD_LOGE(TAG, "[%s] Failed to create scan timeout timer",
                __FUNCTION__);
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }

    config_timer = xTimerCreate("Config_Timer",
            CFG_TICKS,
            pdFALSE, NULL, handle_config_timer);
    if (config_timer == NULL) {
        EHTTPD_LOGE(TAG, "[%s] Failed to create config validation timer",
                __FUNCTION__);
        result = ESP_ERR_NO_MEM;
        goto err_out;
    }

    err_out:
    if (result != ESP_OK) {
        if (wifi_events != NULL) {
            vEventGroupDelete(wifi_events);
            wifi_events = NULL;
        }

        if (data_lock != NULL) {
            vSemaphoreDelete(data_lock);
            data_lock = NULL;
        }

        if (cfg_state.lock != NULL) {
            vSemaphoreDelete(cfg_state.lock);
            cfg_state.lock = NULL;
        }

        if (scan_timer != NULL) {
            xTimerDelete(scan_timer, 0);
            scan_timer = NULL;
        }

        if (config_timer != NULL) {
            xTimerDelete(config_timer, 0);
            config_timer = NULL;
        }
    }

    return result;
}


/* Get a reference counted pointer to the current set of AP scan data. *\
\* Must be released via put_scan_data().                               */
static struct scan_data *get_scan_data(void)
{
    struct scan_data *data;

    configASSERT(data_lock != NULL);

    data = NULL;
    if (data_lock == NULL || last_scan == NULL) {
        goto err_out;
    }

    if (xSemaphoreTake(data_lock, CFG_DELAY) == pdTRUE) {
        data = last_scan;
        kref_get(&(data->ref_cnt));
        xSemaphoreGive(data_lock);
    }

    err_out:
    return data;
}


/* Free scan data, should only be called kref_put(). */
static void free_scan_data(struct kref *ref)
{
    struct scan_data *data;

    data = kcontainer_of(ref, struct scan_data, ref_cnt);
    free(data->ap_records);
    free(data);
}


/* Drop a reference to a scan data set, possibly freeing it. */
static void put_scan_data(struct scan_data *data)
{
    configASSERT(data != NULL);

    kref_put(&(data->ref_cnt), free_scan_data);
}


/* Fetch the latest AP scan data and make it available. */
static void wifi_scan_done(system_event_t *event)
{
    uint16_t num_aps;
    struct scan_data *old_data, *new_data;
    esp_err_t result;

    result = ESP_OK;
    new_data = NULL;

    /* cgiWifiSetup() must have been called prior to this point. */
    configASSERT(data_lock != NULL);

    /* Receiving anything other than scan done means something is *\
    \* really messed up.                                          */
    configASSERT(event->event_id == SYSTEM_EVENT_SCAN_DONE);

    if (atomic_load(&scan_in_progress) == false) {
        /* Either scan was cancelled due to timeout or somebody else *\
        \* is triggering scans.                                      */
        EHTTPD_LOGE(TAG, "[%s] Received unsolicited scan done event.",
                __FUNCTION__);
        return;
    }

    if (event->event_info.scan_done.status != ESP_OK) {
        EHTTPD_LOGI(TAG, "Scan failed. Event status: 0x%x",
                event->event_info.scan_done.status);
        goto err_out;
    }

    /* Fetch number of APs found. Bail out early if there is nothing to get. */
    result = esp_wifi_scan_get_ap_num(&num_aps);
    if (result != ESP_OK || num_aps == 0) {
        EHTTPD_LOGI(TAG, "Scan error or empty scan result");
        goto err_out;
    }

    /* Limit number of records to fetch. Prevents possible DoS by tricking   *\
    \* us into allocating storage for a very large amount of scan results.   */
    if (num_aps > MAX_NUM_APS) {
        EHTTPD_LOGI(TAG, "Limiting AP records to %d (Actually found %d)",
                MAX_NUM_APS, num_aps);
        num_aps = MAX_NUM_APS;
    }

    /* Allocate and initialise memory for scan data and AP records. */
    new_data = calloc(1, sizeof(*new_data));
    if (new_data == NULL) {
        EHTTPD_LOGE(TAG, "Out of memory creating scan data");
        goto err_out;
    }

    kref_init(&(new_data->ref_cnt)); // initialises ref_cnt to 1
    new_data->ap_records = calloc(num_aps, sizeof(*(new_data->ap_records)));
    if (new_data->ap_records == NULL) {
        EHTTPD_LOGE(TAG, "Out of memory for fetching records");
        goto err_out;
    }

    /* Fetch actual AP scan data */
    new_data->num_records = num_aps;
    result = esp_wifi_scan_get_ap_records(&(new_data->num_records), new_data->ap_records);
    if (result != ESP_OK) {
        EHTTPD_LOGE(TAG, "Error getting scan results");
        goto err_out;
    }

    EHTTPD_LOGI(TAG, "Scan done: found %d APs", num_aps);

    /* Make new scan data available. */
    if (xSemaphoreTake(data_lock, portTICK_PERIOD_MS) == pdTRUE) {
        /* The new data set will be asigned to the global pointer, so fetch *\
        \* another reference.                                               */
        kref_get(&(new_data->ref_cnt));

        old_data = last_scan;
        last_scan = new_data;

        if (old_data != NULL) {
            /* Drop global reference to old data set so it will be freed    *\
            \* when the last connection using it gets closed.               */
            put_scan_data(old_data);
        }

        xSemaphoreGive(data_lock);
    }

    err_out:
    /* Drop one reference to the new scan data. */
    if (new_data != NULL) {
        put_scan_data(new_data);
    }

    /* Clear scan flag so a new scan can be triggered. */
    atomic_store(&scan_in_progress, false);
    if (scan_timer != NULL) {
        xTimerStop(scan_timer, 0);
    }
}


/* Timer function to stop a hanging AP scan. */
static void handle_scan_timer(TimerHandle_t timer)
{
    atomic_bool tmp = ATOMIC_VAR_INIT(true);

    if (atomic_compare_exchange_strong(&scan_in_progress, &tmp, true) == true) {
        EHTTPD_LOGI(TAG, "[%s] Timeout, stopping scan.", __FUNCTION__);
        (void) esp_wifi_scan_stop();
        atomic_store(&scan_in_progress, false);
    }
}


/* Function to trigger an AP scan. */
static esp_err_t wifi_start_scan(void)
{
    wifi_scan_config_t scan_cfg;
    wifi_mode_t mode;
    esp_err_t result;

    /* Make sure we do not try to start a scan while the WiFi config is *\
    \* is in a transitional state.                                      */
    if (xSemaphoreTake(cfg_state.lock, CFG_DELAY) != pdTRUE) {
        EHTTPD_LOGW(TAG, "[%s] Unable to acquire config lock.", __FUNCTION__);
        return ESP_FAIL;
    }

    if (cfg_state.state > cfg_state_idle) {
        EHTTPD_LOGI(TAG, "[%s] WiFi connecting, not starting scan.", __FUNCTION__);
        result = ESP_FAIL;
        goto err_out;
    }

    /* Check that we are in a suitable mode for scanning. */
    result =  esp_wifi_get_mode(&mode);
    if (result != ESP_OK) {
        EHTTPD_LOGE(TAG, "[%s] Error fetching WiFi mode.", __FUNCTION__);
        goto err_out;
    }

    if (mode != WIFI_MODE_APSTA && mode != WIFI_MODE_STA) {
        EHTTPD_LOGE(TAG, "[%s] Invalid WiFi mode for scanning.", __FUNCTION__);
        result = ESP_FAIL;
        goto err_out;
    }

    /* Finally, start a scan. Unless there is one running already. */
    if (atomic_exchange(&scan_in_progress, true) == false) {
        EHTTPD_LOGI(TAG, "[%s] Starting scan.", __FUNCTION__);

        memset(&scan_cfg, 0x0, sizeof(scan_cfg));
        scan_cfg.show_hidden = true;
        scan_cfg.scan_type = WIFI_SCAN_TYPE_ACTIVE;

        result = esp_wifi_scan_start(&scan_cfg, false);
        if (result == ESP_OK) {
            EHTTPD_LOGI(TAG, "[%s] Starting timer.", __FUNCTION__);

            /* Trigger the timer so scan will be aborted after timeout. */
            xTimerReset(scan_timer, 0);
        } else {
            EHTTPD_LOGE(TAG, "[%s] Starting AP scan failed.", __FUNCTION__);

            atomic_store(&scan_in_progress, false);
        }
    } else {
        EHTTPD_LOGI(TAG, "[%s] Scan already running.", __FUNCTION__);
        result = ESP_OK;
    }

    err_out:
    xSemaphoreGive(cfg_state.lock);
    return result;
}


/* This route handler is called from the bit of AJAX-code in wifi.tpl. It will       *\
 * initiate a scan for access points and if available will return the      *
 * result of an earlier scan. The result is embedded in a bit of JSON      *
\* parsed by the javascript in wifi.tpl.                                   */
ehttpd_status_t ehttpd_route_wifi_scan(ehttpd_conn_t *conn)
{
    struct ap_data_iter *iter;
    struct scan_data *data;
    wifi_ap_record_t *record;
    wifi_mode_t mode;
    ehttpd_status_t result;
    int len;
    char buf[1024];

    result = EHTTPD_STATUS_DONE;
    iter = (struct ap_data_iter *) conn->user;

    if (conn->closed) {
        goto err_out;
    }

    if (esp_wifi_get_mode(&mode) != ESP_OK) {
        EHTTPD_LOGE(TAG, "[%s] Error fetching WiFi mode.", __FUNCTION__);
        goto err_out;
    }

    /* First call. Send header, fetch scan data and set up iterator. */
    if (iter == NULL) {
        ehttpd_response(conn, 200);
        ehttpd_send_header(conn, "Content-Type", "text/json");
        ehttpd_end_headers(conn);

        data = get_scan_data();
        if (data != NULL) {
            iter = calloc(1, sizeof(*iter));
            if (iter != NULL) {
                iter->data = data;
                iter->idx = 0;
                conn->user = (void *) iter;
            } else {
                EHTTPD_LOGE(TAG, "[%s] Iterator allocation failed.", __FUNCTION__);
                put_scan_data(data);
            }
        } else {
            if (wifi_start_scan() != ESP_OK) {
                /* Start_scan failed. Tell the user there is an error and don't just keep trying.  */
                len=sprintf(buf, "{\n \"result\": { \n\"inProgress\": \"ERROR\"\n }\n}\n");
                ehttpd_send(conn, (uint8_t *) buf, len);
                goto err_out;
            }
        }
    }

    if (iter == NULL) {
        /* There is either no scan data available or iterator allocation    *\
        \* failed. Tell the user we are still trying...                     */
        len=sprintf(buf, "{\n \"result\": { \n\"inProgress\": \"1\"\n }\n}\n");
        ehttpd_send(conn, (uint8_t *) buf, len);
    } else {
        /* We have data to send. Send JSON opening before sending first AP  *\
        \* data from the list.                                              */
        if (iter->idx == 0) {
            len = sprintf(buf, "{\n \"result\": { \n"
                    "\"inProgress\": \"0\", \n"
                    "\"APs\": [\n");
            ehttpd_send(conn, (uint8_t *) buf, len);
        }

        /* Skip sending stale AP data if we are in AP mode. */
        if (mode == WIFI_MODE_AP) {
            iter->idx = iter->data->num_records;
        }

        /* If list is not empty, send current AP element data and advance   *\
        \* element pointer.                                                 */
        if (iter->idx < iter->data->num_records) {
            record = &(iter->data->ap_records[iter->idx]);
            ++iter->idx;

            len = sprintf(buf, "{\"essid\": \"%s\", "
                    "\"bssid\": \"" MACSTR "\", "
                    "\"rssi\": \"%d\", "
                    "\"enc\": \"%d\", "
                    "\"channel\": \"%d\"}%s\n",
                    record->ssid,
                    MAC2STR(record->bssid),
                    record->rssi,
                    record->authmode == WIFI_AUTH_OPEN ? 0 :
                            record->authmode == WIFI_AUTH_WEP  ? 1 : 2,
                                    record->primary,
                                    iter->idx < iter->data->num_records ? "," : "");
            ehttpd_send(conn, (uint8_t *) buf, len);
        }

        /* Close JSON statement when all elements have been sent. */
        if (iter->idx >= iter->data->num_records) {
            len = sprintf(buf, "]\n}\n}\n");
            ehttpd_send(conn, (uint8_t *) buf, len);

            /* Also start a new scan. */
            wifi_start_scan();
        } else {
            /* Still more data to send... */
            result = EHTTPD_STATUS_MORE;
        }
    }

    err_out:
    if (result == EHTTPD_STATUS_DONE && iter != NULL) {
        put_scan_data(iter->data);
        free(iter);
        conn->user = NULL;
    }

    return result;
}


/* Helper function to check if WiFi is connected in station mode. */
static bool sta_connected(void)
{
    EventBits_t events;

    events = xEventGroupGetBits(wifi_events);

    return !!(events & BIT_CONNECTED);
}


/* Helper function to set WiFi configuration from struct wifi_cfg. */
static void set_wifi_cfg(struct wifi_cfg *cfg)
{
    esp_err_t result;

    if (cfg->mode == WIFI_MODE_NULL) {
        // turning off WiFi
        result = esp_wifi_stop();
        if (result != ESP_OK) {
            EHTTPD_LOGE(TAG, "[%s] esp_wifi_stop(): %d %s",
                    __FUNCTION__, result, esp_err_to_name(result));
        }
    }

    /* FIXME: we should check for errors. OTOH, this is also used  *\
     *        for the fall-back mechanism, so aborting on error is *
    \*        probably a bad idea.                                 */
    result = esp_wifi_set_mode(cfg->mode);
    if (result != ESP_OK) {
        EHTTPD_LOGE(TAG, "[%s] esp_wifi_set_mode(): %d %s",
                __FUNCTION__, result, esp_err_to_name(result));
    }

    if (cfg->mode == WIFI_MODE_NULL) {
        // turning off WiFi
        return;
    }

    if (cfg->mode == WIFI_MODE_APSTA || cfg->mode == WIFI_MODE_AP) {
        result = esp_wifi_set_config(WIFI_IF_AP, &(cfg->ap));
        if (result != ESP_OK) {
            EHTTPD_LOGE(TAG, "[%s] esp_wifi_set_config() AP: %d %s",
                    __FUNCTION__, result, esp_err_to_name(result));
        }
    }

    if (cfg->mode == WIFI_MODE_APSTA || cfg->mode == WIFI_MODE_STA) {
        result = esp_wifi_set_config(WIFI_IF_STA, &(cfg->sta));
        if (result != ESP_OK) {
            EHTTPD_LOGE(TAG, "[%s] esp_wifi_set_config() STA: %d %s",
                    __FUNCTION__, result, esp_err_to_name(result));
        }
    }

    result = esp_wifi_start();
    if (result != ESP_OK) {
        EHTTPD_LOGE(TAG, "[%s] esp_wifi_start(): %d %s",
                __FUNCTION__, result, esp_err_to_name(result));
    }

    if (cfg->connect
            && (   cfg->mode == WIFI_MODE_STA
                    || cfg->mode == WIFI_MODE_APSTA))
    {
        result = esp_wifi_connect();
        if (result != ESP_OK) {
            EHTTPD_LOGE(TAG, "[%s] esp_wifi_connect(): %d %s",
                    __FUNCTION__, result, esp_err_to_name(result));
        }
    }
}


/* Helper to store current WiFi configuration into a struct wifi_cfg. */
static esp_err_t get_wifi_cfg(struct wifi_cfg *cfg)
{
    esp_err_t result;

    result = ESP_OK;
    memset(cfg, 0x0, sizeof(*cfg));

    cfg->connect = sta_connected();

    result = esp_wifi_get_config(WIFI_IF_STA, &(cfg->sta));
    if (result != ESP_OK) {
        EHTTPD_LOGE(TAG, "[%s] Error fetching STA config.", __FUNCTION__);
        goto err_out;
    }

    result = esp_wifi_get_config(WIFI_IF_AP, &(cfg->ap));
    if (result != ESP_OK) {
        EHTTPD_LOGE(TAG, "[%s] Error fetching AP config.", __FUNCTION__);
        goto err_out;
    }

    result = esp_wifi_get_mode(&(cfg->mode));
    if (result != ESP_OK) {
        EHTTPD_LOGE(TAG, "[%s] Error fetching WiFi mode.", __FUNCTION__);
        goto err_out;
    }

    err_out:
    return result;
}


/* This function is called from the config_timer and handles all WiFi        *\
 * configuration changes. It takes its information from the global           *
 * cfg_state struct and tries to set the WiFi configuration to the one       *
 * found in the "new_cfg" member. If things go wrong, it will try to fall    *
 * back to the configuration found in "saved_cfg". This should minimise      *
 * the risk of users locking themselves out of the device by setting         *
 * wrong WiFi credentials in STA-only mode.                                  *
 *                                                                           *
 * This function will keep triggering itself until it reaches a "stable"     *
 * (idle, connected, failed) state in cfg_state.state.                       *
 *                                                                           *
 * cfg_state must not be modified without first obtaining the cfg_state.lock *
 * mutex and then checking that cfg_state.state is in a stable state.        *
 * To set a new configuration, just store the current config to .saved_cfg,  *
 * update .new_cfg to the desired config, set .state to cfg_state_update     *
 * and start the config_timer.                                               *
 * To connect to an AP with WPS, save the current state, set .state          *
 * to cfg_state_wps_start and start the config_timer.                        *
 \*                                                                          */
static void handle_config_timer(TimerHandle_t timer)
{
    bool connected;
    wifi_mode_t mode;
    esp_wps_config_t config = WPS_CONFIG_INIT_DEFAULT(WPS_TYPE_PBC);
    TickType_t now, delay;
    EventBits_t events;
    esp_err_t result;

    /* If we can not get the config state lock, we try to reschedule the    *\
     * timer. If that also fails, we are SOL...                             *
    \* Maybe we should trigger a reboot.                                    */
    if (xSemaphoreTake(cfg_state.lock, 0) != pdTRUE) {
        if (xTimerChangePeriod(config_timer, CFG_DELAY, CFG_DELAY) != pdPASS) {
            EHTTPD_LOGE(TAG, "[%s] Failure to get config lock and change timer.",
                    __FUNCTION__);
        }
        return;
    }

    EHTTPD_LOGD(TAG, "[%s] Called. State: %s",
            __FUNCTION__, state_names[cfg_state.state]);

    /* If delay gets set later, the timer will be re-scheduled on exit. */
    delay = 0;

    /* Gather various information about the current system state. */
    connected = sta_connected();
    events = xEventGroupGetBits(wifi_events);
    now = xTaskGetTickCount();

    result = esp_wifi_get_mode(&mode);
    if (result != ESP_OK) {
        EHTTPD_LOGE(TAG, "[%s] Error fetching WiFi mode.", __FUNCTION__);
        cfg_state.state = cfg_state_failed;
        goto err_out;
    }

    switch(cfg_state.state) {
    case cfg_state_wps_start:

        /* Try connecting to AP with WPS. First, tear down any connection *\
        \* we might currently have.                                       */
        get_wifi_cfg(&cfg_state.new_cfg);
        memset(&cfg_state.new_cfg.sta, 0x0, sizeof(cfg_state.new_cfg.sta));
        cfg_state.new_cfg.mode = WIFI_MODE_APSTA;
        cfg_state.new_cfg.connect = false;

        set_wifi_cfg(&cfg_state.new_cfg);

        /* Clear previous results and start WPS. */
        xEventGroupClearBits(wifi_events, BITS_WPS);
        result = esp_wifi_wps_enable(&config);
        if (result != ESP_OK) {
            EHTTPD_LOGE(TAG, "[%s] esp_wifi_wps_enable() failed: %d %s",
                    __FUNCTION__, result, esp_err_to_name(result));
            cfg_state.state = cfg_state_fallback;
            delay = CFG_DELAY;
        }

        result = esp_wifi_wps_start(0);
        if (result != ESP_OK) {
            EHTTPD_LOGE(TAG, "[%s] esp_wifi_wps_start() failed: %d %s",
                    __FUNCTION__, result, esp_err_to_name(result));
            cfg_state.state = cfg_state_fallback;
            delay = CFG_DELAY;
        }

        /* WPS is running, set time stamp and transition to next state. */
        cfg_state.timestamp = now;
        cfg_state.state = cfg_state_wps_active;
        delay = CFG_TICKS;
        break;
    case cfg_state_wps_active:
        /* WPS is running. Check for events and timeout. */
        if (events & BIT_WPS_SUCCESS) {
            /* WPS succeeded. Disable WPS and use the received credentials *\
             * to connect to the AP by transitioning to the updating state.*/
            EHTTPD_LOGI(TAG, "[%s] WPS success.", __FUNCTION__);
            result = esp_wifi_wps_disable();
            if (result != ESP_OK) {
                EHTTPD_LOGE(TAG, "[%s] wifi wps disable: %d %s",
                        __FUNCTION__, result, esp_err_to_name(result));
            }

            /* Get received STA config, then force APSTA mode, set  *\
            \* connect flag and trigger update.                     */
            get_wifi_cfg(&cfg_state.new_cfg);
            cfg_state.new_cfg.mode = WIFI_MODE_APSTA;
            cfg_state.new_cfg.connect = true;
            cfg_state.state = cfg_state_update;
            delay = CFG_DELAY;
        } else if (   time_after(now, (cfg_state.timestamp + CFG_TIMEOUT))
                || (events & BIT_WPS_FAILED))
        {
            /* Failure or timeout. Trigger fall-back to the previous config. */
            EHTTPD_LOGI(TAG, "[%s] WPS failed, restoring saved_cfg config.",
                    __FUNCTION__);

            result = esp_wifi_wps_disable();
            if (result != ESP_OK) {
                EHTTPD_LOGE(TAG, "[%s] wifi wps disable: %d %s",
                        __FUNCTION__, result, esp_err_to_name(result));
            }

            cfg_state.state = cfg_state_fallback;
            delay = CFG_DELAY;
        } else {
            delay = CFG_TICKS;
        }
        break;
    case cfg_state_update:
        /* Start changing WiFi to new configuration. */
        (void) esp_wifi_scan_stop();
        (void) esp_wifi_disconnect();
        set_wifi_cfg(&(cfg_state.new_cfg));

        if (cfg_state.new_cfg.mode == WIFI_MODE_AP ||
          cfg_state.new_cfg.mode == WIFI_MODE_NULL ||
          !cfg_state.new_cfg.connect) {
            /* AP-only mode or not connecting, we are done. */
            cfg_state.state = cfg_state_idle;
        } else {
            /* System should now connect to the AP. */
            cfg_state.timestamp = now;
            cfg_state.state = cfg_state_connecting;
            delay = CFG_TICKS;
        }
        break;
    case cfg_state_connecting:
        /* We are waiting for a connection to an AP. */
        if (connected) {
            /* We have a connection! \o/ */
            cfg_state.state = cfg_state_connected;
        } else if (time_after(now, (cfg_state.timestamp + CFG_TIMEOUT))) {
            /* Timeout while waiting for connection. Try falling back to the *\
            \* saved_cfg configuration.                                      */
            cfg_state.state = cfg_state_fallback;
            delay = CFG_DELAY;
        } else {
            /* Twiddle our thumbs and keep waiting for the connection.  */
            delay = CFG_TICKS;
        }
        break;
    case cfg_state_fallback:
        /* Something went wrong, try going back to the previous config. */
        EHTTPD_LOGI(TAG, "[%s] restoring saved_cfg Wifi config.",
                 __FUNCTION__);
        (void) esp_wifi_disconnect();
        set_wifi_cfg(&(cfg_state.saved_cfg));
        cfg_state.state = cfg_state_failed;
        break;
    case cfg_state_idle:
    case cfg_state_connected:
    case cfg_state_failed:
        break;
    }

    err_out:
    if (delay > 0) {
        /* We are in a transitional state, re-arm the timer. */
        if (xTimerChangePeriod(config_timer, delay, CFG_DELAY) != pdPASS) {
            cfg_state.state = cfg_state_failed;
        }
    }

    EHTTPD_LOGD(TAG, "[%s] Leaving. State: %s delay: %d",
            __FUNCTION__, state_names[cfg_state.state], delay);

    xSemaphoreGive(cfg_state.lock);
    return;
}


static const char *event_names[] = {
        "WIFI_READY",
        "SCAN_DONE",
        "STA_START",
        "STA_STOP",
        "STA_CONNECTED",
        "STA_DISCONNECTED",
        "STA_AUTHMODE_CHANGE",
        "STA_GOT_IP",
        "STA_LOST_IP",
        "STA_WPS_ER_SUCCESS",
        "STA_WPS_ER_FAILED",
        "STA_WPS_ER_TIMEOUT",
        "STA_WPS_ER_PIN",
        "AP_START",
        "AP_STOP",
        "AP_STACONNECTED",
        "AP_STADISCONNECTED",
        "AP_STAIPASSIGNED",
        "AP_PROBEREQRECVED",
        "GOT_IP6",
        "ETH_START",
        "ETH_STOP",
        "ETH_CONNECTED",
        "ETH_DISCONNECTED",
        "ETH_GOT_IP",
};


/* Update state information from system events. This function must be   *\
 * called from the main event handler to keep this module updated about *
\* the current system state.                                            */
void ehttpd_wifi_event_cb(system_event_t *event)
{
    EHTTPD_LOGD(TAG, "[%s] Received %s.",
            __FUNCTION__, event_names[event->event_id]);

    switch(event->event_id) {
    case SYSTEM_EVENT_SCAN_DONE:
        wifi_scan_done(event);
        break;
    case SYSTEM_EVENT_STA_GOT_IP:
    case SYSTEM_EVENT_GOT_IP6:
        xEventGroupSetBits(wifi_events, BIT_CONNECTED);
        break;
    case SYSTEM_EVENT_STA_DISCONNECTED:
        xEventGroupClearBits(wifi_events, BIT_CONNECTED);
        break;
    case SYSTEM_EVENT_STA_WPS_ER_SUCCESS:
        xEventGroupSetBits(wifi_events, BIT_WPS_SUCCESS);
        break;
    case SYSTEM_EVENT_STA_WPS_ER_FAILED:
    case SYSTEM_EVENT_STA_WPS_ER_TIMEOUT:
    case SYSTEM_EVENT_STA_WPS_ER_PIN:
        xEventGroupSetBits(wifi_events, BIT_WPS_FAILED);
        break;
    default:
        break;
    }
}


/* Set a new WiFi configuration. This function will save the current config  *\
 * to cfg->saved_cfg, then compare it to the requested new configuration. If *
 * the two configurations are different, it will store the new config in     *
\* cfg->new_cfg and trigger the asynchronous mechanism to handle the update. */
static esp_err_t update_wifi(struct wifi_cfg_state *cfg, struct wifi_cfg *new_cfg)
{
    bool connected;
    bool update;
    esp_err_t result;

    if (xSemaphoreTake(cfg->lock, CFG_DELAY) != pdTRUE) {
        EHTTPD_LOGE(TAG, "[%s] Error taking mutex.", __FUNCTION__);
        return ESP_ERR_TIMEOUT;
    }

    if (new_cfg->mode != WIFI_MODE_NULL && cfg->state > cfg_state_idle)
    {
        EHTTPD_LOGI(TAG, "[%s] Already connecting.", __FUNCTION__);
        result = ESP_ERR_INVALID_STATE;
        goto err_out;
    }

    result = ESP_OK;

    /* Save current configuration for fall-back. */
    result = get_wifi_cfg(&(cfg->saved_cfg));
    if (result != ESP_OK) {
        EHTTPD_LOGI(TAG, "[%s] Error fetching current WiFi config.",
                __FUNCTION__);
        goto err_out;
    }

    /* Clear station configuration if we are not connected to an AP. */
    connected = sta_connected();
    if (connected) {
        memset(&(cfg->saved_cfg.sta), 0x0, sizeof(cfg->saved_cfg.sta));
    }

    memmove(&(cfg->new_cfg), new_cfg, sizeof(cfg->new_cfg));
    update = false;

    /* Do some naive checks to see if the new configuration is an actual   *\
    \* change. Should be more thorough by actually comparing the elements. */
    if (cfg->new_cfg.mode != cfg->saved_cfg.mode) {
        update = true;
    }

    if ((new_cfg->mode == WIFI_MODE_AP || new_cfg->mode == WIFI_MODE_APSTA)
            && memcmp(&(cfg->new_cfg.ap), &(cfg->saved_cfg.ap), sizeof(cfg->new_cfg.ap)))
    {
        update = true;
    }

    if ((new_cfg->mode == WIFI_MODE_STA || new_cfg->mode == WIFI_MODE_APSTA)
            && memcmp(&(cfg->new_cfg.sta), &(cfg->saved_cfg.sta), sizeof(cfg->new_cfg.sta)))
    {
        update = true;
    }

    /* If new config is different, trigger asynchronous update. This gives *\
     * the httpd some time to send out the reply before possibly tearing   *
    \* down the connection.                                                */
    if (update == true) {
        cfg->state = cfg_state_update;
        if (xTimerChangePeriod(config_timer, CFG_DELAY, CFG_DELAY) != pdPASS) {
            cfg->state = cfg_state_failed;
            result = ESP_ERR_TIMEOUT;
            goto err_out;
        }
    }

    err_out:
    xSemaphoreGive(cfg->lock);
    return result;
}


/* Trigger a connection attempt to the AP with the given SSID and password. */
ehttpd_status_t ehttpd_route_wifi_connect(ehttpd_conn_t *conn)
{
    size_t len;
    const char *redirect;
    struct wifi_cfg cfg;
    wifi_sta_config_t *sta;
    esp_err_t result;

    if (conn->closed) {
        /* Connection aborted. Clean up. */
        return EHTTPD_STATUS_DONE;
    }

    redirect = "wifi.tpl";

    if (conn->post == NULL) {
        EHTTPD_LOGE(TAG, "POST data missing");
        goto err_out;
    }

    memset(&cfg, 0x0, sizeof(cfg));

    /* We are only changing SSID and password, so fetch the current *\
    \* configuration and update just these two entries.             */
    result = get_wifi_cfg(&cfg);
    if (result != ESP_OK) {
        EHTTPD_LOGE(TAG, "[%s] Error fetching WiFi config.", __FUNCTION__);
        goto err_out;
    }

    sta = &(cfg.sta.sta);
    len = sizeof(sta->ssid);
    len = ehttpd_find_param("essid", conn->post->buf, (char *) sta->ssid,
            &len);
    if (len <= 1) {
        EHTTPD_LOGE(TAG, "[%s] essid invalid or missing.", __FUNCTION__);
        goto err_out;
    }

    len = sizeof(sta->password);
    len = ehttpd_find_param("passwd", conn->post->buf, (char *) sta->password,
            &len);
    if (len <= 1) {
        /* FIXME: What about unsecured APs? */
        EHTTPD_LOGE(TAG, "[%s] Password parameter missing.", __FUNCTION__);
        goto err_out;
    }

    /* And of course we want to actually connect to the AP. */
    cfg.connect = true;

#ifndef DEMO_MODE
    EHTTPD_LOGI(TAG, "Trying to connect to AP %s pw %s",
            sta->ssid, sta->password);

    result = update_wifi(&cfg_state, &cfg);
    if (result == ESP_OK) {
        redirect = "connecting.html";
    }
#else
    EHTTPD_LOGI(TAG, "Demo mode, not actually connecting to AP %s pw %s",
            sta->ssid, sta->password);
#endif

    err_out:
    ehttpd_redirect(conn, redirect);
    return EHTTPD_STATUS_DONE;
}


/* route handler used to set the WiFi mode. */
ehttpd_status_t ehttpd_route_wifi_set_mode(ehttpd_conn_t *conn)
{
    size_t len;
    wifi_mode_t mode;
    struct wifi_cfg cfg;
    char buf[16];
    esp_err_t result;

    if (conn->closed) {
        /* Connection aborted. Clean up. */
        return EHTTPD_STATUS_DONE;
    }

    len = sizeof(buf);
    len = ehttpd_find_param("mode", conn->args, buf, &len);
    if (len!=0) {
        errno = 0;
        mode = strtoul(buf, NULL, 10);
        if (errno != 0 || mode < WIFI_MODE_NULL || mode >= WIFI_MODE_MAX) {
            EHTTPD_LOGE(TAG, "[%s] Invalid WiFi mode: %d", __FUNCTION__, mode);
            goto err_out;
        }

#ifndef DEMO_MODE
        memset(&cfg, 0x0, sizeof(cfg));

        result = get_wifi_cfg(&cfg);
        if (result != ESP_OK) {
            EHTTPD_LOGE(TAG, "[%s] Error fetching current WiFi config.",
                    __FUNCTION__);
            goto err_out;
        }

        /* Do not switch to STA mode without being connected to an AP. */
        if (mode == WIFI_MODE_STA && !sta_connected()) {
            EHTTPD_LOGE(TAG, "[%s] No connection to AP, not switching to "
                    "client-only mode.", __FUNCTION__);
            goto err_out;
        }

        cfg.mode = mode;

        EHTTPD_LOGI(TAG, "[%s] Switching to WiFi mode %s", __FUNCTION__,
                mode == WIFI_MODE_AP    ? "SoftAP" :
                        mode == WIFI_MODE_APSTA ? "STA+AP" :
                                mode == WIFI_MODE_STA   ? "Client" : "Disabled");

        result = update_wifi(&cfg_state, &cfg);
        if (result != ESP_OK) {
            EHTTPD_LOGE(TAG, "[%s] Setting WiFi config failed", __FUNCTION__);
        }
#else
        EHTTPD_LOGI(TAG, "[%s] Demo mode, not switching to WiFi mode %s",
                __FUNCTION__,
                mode == WIFI_MODE_AP    ? "SoftAP" :
                        mode == WIFI_MODE_APSTA ? "STA+AP" :
                                mode == WIFI_MODE_STA   ? "Client" : "Disabled");
#endif
    }

    err_out:
    ehttpd_redirect(conn, "working.html"); // changing mode takes some time, so redirect user to wait
    return EHTTPD_STATUS_DONE;
}


/* route handler for triggering a WPS push button connection attempt. */
ehttpd_status_t ehttpd_route_wifi_start_wps(ehttpd_conn_t *conn)
{
    struct wifi_cfg cfg;
    esp_err_t result;

    result = ESP_OK;

    if (conn->closed) {
        /* Connection aborted. Clean up. */
        return EHTTPD_STATUS_DONE;
    }

    /* Make sure we are not in the middle of setting a new WiFi config. */
    if (xSemaphoreTake(cfg_state.lock, CFG_DELAY) != pdTRUE) {
        EHTTPD_LOGE(TAG, "[%s] Error taking mutex.", __FUNCTION__);
        ehttpd_redirect(conn, "wifi.tpl");
        return EHTTPD_STATUS_DONE;
    }

    if (cfg_state.state > cfg_state_idle) {
        EHTTPD_LOGI(TAG, "[%s] Already connecting.", __FUNCTION__);
        goto err_out;
    }

#ifndef DEMO_MODE
    EHTTPD_LOGI(TAG, "[%s] Starting WPS.", __FUNCTION__);

    /* Save current config for fall-back. */
    result = get_wifi_cfg(&cfg);
    if (result != ESP_OK) {
        EHTTPD_LOGE(TAG, "[%s] Error fetching WiFi config.", __FUNCTION__);
        goto err_out;
    }

    memmove(&cfg_state.saved_cfg, &cfg, sizeof(cfg_state.saved_cfg));
    cfg_state.state = cfg_state_wps_start;

    if (xTimerChangePeriod(config_timer,CFG_DELAY,CFG_DELAY) != pdTRUE) {
        cfg_state.state = cfg_state_failed;
    }
#else
    EHTTPD_LOGI(TAG, "[%s] Demo mode, not starting WPS.", __FUNCTION__);
#endif

    err_out:
    xSemaphoreGive(cfg_state.lock);
    ehttpd_redirect(conn, "connecting.html");

    return EHTTPD_STATUS_DONE;
}


/* route handler for settings in AP mode. */
ehttpd_status_t ehttpd_route_wifi_ap_settings(ehttpd_conn_t *conn)
{
    size_t len;
    char buf[64];

    esp_err_t result;

    if (conn->closed) {
        return EHTTPD_STATUS_DONE;
    }

    if (conn->post == NULL) {
        EHTTPD_LOGE(TAG, "POST data missing");
        goto err_out;
    }

    bool has_arg_chan = false;
    unsigned int chan;
    len = sizeof(buf);
    len = ehttpd_find_param("chan", conn->post->buf, buf, &len);
    if (len > 0) {
        errno = 0;
        chan = strtoul(buf, NULL, 10);
        if (errno != 0 || chan < 1 || chan > 15) {
            EHTTPD_LOGW(TAG, "[%s] Not setting invalid channel %s",
                    __FUNCTION__, buf);
        } else {
            has_arg_chan = true;
        }
    }

    bool has_arg_ssid = false;
    char ssid[32];           /** SSID of ESP32 soft-AP */
    len = sizeof(buf);
    len = ehttpd_find_param("ssid", conn->post->buf, buf, &len);
    if (len > 0) {
        int n;
        n = sscanf(buf, "%s", (char *) &ssid); // find a string without spaces
        if (n == 1) {
            has_arg_ssid = true;
        } else {
            EHTTPD_LOGW(TAG, "[%s] Not setting invalid ssid %s",
                    __FUNCTION__, buf);
        }
    }

    bool has_arg_pass = false;
    char pass[64];       /** Password of ESP32 soft-AP */
    len = sizeof(buf);
    len = ehttpd_find_param("pass", conn->post->buf, buf, &len);
    if (len > 0) {
        int n;
        n = sscanf(buf, "%s", (char *) &pass); // find a string without spaces
        if (n == 1) {
            has_arg_pass = true;
        } else {
            EHTTPD_LOGW(TAG, "[%s] Not setting invalid pass %s",
                    __FUNCTION__, buf);
        }
    }

    if (has_arg_chan || has_arg_ssid || has_arg_pass) {
#ifndef DEMO_MODE
        struct wifi_cfg cfg;
        result = get_wifi_cfg(&cfg);
        if (result != ESP_OK) {
            EHTTPD_LOGE(TAG, "[%s] Fetching WiFi config failed", __FUNCTION__);
            goto err_out;
        }

        if (has_arg_chan) {
            EHTTPD_LOGI(TAG, "[%s] Setting ch=%d", __FUNCTION__, chan);
            cfg.ap.ap.channel = (uint8_t) chan;
        }

        if (has_arg_ssid) {
            EHTTPD_LOGI(TAG, "[%s] Setting ssid=%s", __FUNCTION__, ssid);
            strlcpy((char *) cfg.ap.ap.ssid, ssid, sizeof(cfg.ap.ap.ssid));
            cfg.ap.ap.ssid_len = 0;  // if ssid_len==0, check the SSID until there is a termination character; otherwise, set the SSID length according to softap_config.ssid_len.
            EHTTPD_LOGI(TAG, "[%s] Set ssid=%s", __FUNCTION__, cfg.ap.ap.ssid);
        }

        if (has_arg_pass) {
            EHTTPD_LOGI(TAG, "[%s] Setting pass=%s", __FUNCTION__, pass);
            strlcpy((char *) cfg.ap.ap.password, pass, sizeof(cfg.ap.ap.password));
        }

        result = update_wifi(&cfg_state, &cfg);
        if (result != ESP_OK) {
            EHTTPD_LOGE(TAG, "[%s] Setting WiFi config failed", __FUNCTION__);
        }
#else
        EHTTPD_LOGI(TAG, "[%s] Demo mode, not setting ch=%d", __FUNCTION__, chan);
#endif
    }

    err_out:
    ehttpd_redirect(conn, "working.html");
    return EHTTPD_STATUS_DONE;
}


/* route handler returning the current state of the WiFi connection. */
ehttpd_status_t ehttpd_route_wifi_status(ehttpd_conn_t *conn)
{
    char buf[128];
    tcpip_adapter_ip_info_t info;
    esp_err_t result;

    if (conn->closed) {
        return EHTTPD_STATUS_DONE;
    }

    snprintf(buf, sizeof(buf) - 1, "{\n \"status\": \"fail\"\n }\n");

    switch(cfg_state.state) {
    case cfg_state_idle:
        snprintf(buf, sizeof(buf) - 1, "{\n \"status\": \"idle\"\n }\n");
        break;
    case cfg_state_update:
    case cfg_state_connecting:
    case cfg_state_wps_start:
    case cfg_state_wps_active:
        snprintf(buf, sizeof(buf) - 1, "{\n \"status\": \"working\"\n }\n");
        break;
    case cfg_state_connected:
        result = tcpip_adapter_get_ip_info(TCPIP_ADAPTER_IF_STA, &info);
        if (result != ESP_OK) {
            EHTTPD_LOGE(TAG, "[%s] Error fetching IP config.", __FUNCTION__);
            goto err_out;
        }
        snprintf(buf, sizeof(buf) - 1,
                "{\n \"status\": \"success\",\n \"ip\": \"%s\" }\n",
                ip4addr_ntoa(&(info.ip)));
        break;
    case cfg_state_failed:
    default:
        break;
    }

    ehttpd_response(conn, 200);
    ehttpd_send_header(conn, "Content-Type", "text/json");
    ehttpd_end_headers(conn);
    ehttpd_send(conn, (uint8_t *) buf, -1);
    return EHTTPD_STATUS_DONE;

    err_out:
    EHTTPD_LOGE(TAG, "[%s] Failed.", __FUNCTION__);
    ehttpd_response(conn, 500);
    ehttpd_end_headers(conn);

    return EHTTPD_STATUS_DONE;
}


/* Template code for the WiFi page. */
ehttpd_status_t ehttpd_tpl_wlan(ehttpd_conn_t *conn, char *token, void **arg)
{
    char buf[600];
    wifi_ap_record_t stcfg;
    wifi_mode_t mode;
    esp_err_t result;

    if (token == NULL) {
        goto err_out;
    }

    memset(buf, 0x0, sizeof(buf));

    if (strcmp(token, "WiFiMode") == 0) {
        result = esp_wifi_get_mode(&mode);
        if (result != ESP_OK) {
            goto err_out;
        }

        switch(mode) {
        case WIFI_MODE_STA:
            strlcpy(buf, "STA (Client Only)", sizeof(buf));
            break;
        case WIFI_MODE_AP:
            strlcpy(buf, "AP (Access Point Only)", sizeof(buf));
            break;
        case WIFI_MODE_APSTA:
            strlcpy(buf, "STA+AP", sizeof(buf));
            break;
        default:
            strlcpy(buf, "Disabled", sizeof(buf));
            break;
        }
    } else if (strcmp(token, "currSsid") == 0) {

        wifi_config_t cfg;
        //if (sta_connected()) {
            result = esp_wifi_get_config(WIFI_IF_STA, &cfg);
            if (result != ESP_OK) {
                EHTTPD_LOGE(TAG, "[%s] Error fetching STA config.", __FUNCTION__);
                goto err_out;
            }
            strlcpy(buf, (char *) cfg.sta.ssid, sizeof(buf));
        //}
    } else if (strcmp(token, "WiFiPasswd") == 0) {
        wifi_config_t cfg;
        //if (sta_connected()) {
            result = esp_wifi_get_config(WIFI_IF_STA, &cfg);
            if (result != ESP_OK) {
                EHTTPD_LOGE(TAG, "[%s] Error fetching STA config.", __FUNCTION__);
                goto err_out;
            }
            strlcpy(buf, (char *) cfg.sta.password, sizeof(buf));
        //}
    } else if (strcmp(token, "ApSsid") == 0) {
        wifi_config_t cfg;
        result = esp_wifi_get_config(WIFI_IF_AP, &cfg);
        if (result != ESP_OK) {
            EHTTPD_LOGE(TAG, "[%s] Error fetching AP config.", __FUNCTION__);
            goto err_out;
        }
        strlcpy(buf, (char *) cfg.ap.ssid, sizeof(buf));

    } else if (strcmp(token, "ApPass") == 0) {
        wifi_config_t cfg;
        result = esp_wifi_get_config(WIFI_IF_AP, &cfg);
        if (result != ESP_OK) {
            EHTTPD_LOGE(TAG, "[%s] Error fetching AP config.", __FUNCTION__);
            goto err_out;
        }
        strlcpy(buf, (char *) cfg.ap.password, sizeof(buf));

    } else if (strcmp(token, "ApChan") == 0) {
        wifi_config_t cfg;
        result = esp_wifi_get_config(WIFI_IF_AP, &cfg);
        if (result != ESP_OK) {
            EHTTPD_LOGE(TAG, "[%s] Error fetching AP config.", __FUNCTION__);
            goto err_out;
        }
        snprintf(buf, sizeof(buf), "%d", cfg.ap.channel);

    } else if (strcmp(token, "ModeWarn") == 0) {
        result = esp_wifi_get_mode(&mode);
        if (result != ESP_OK) {
            goto err_out;
        }

        switch(mode) {
        case WIFI_MODE_AP:
            /* In AP mode we do not offer switching to STA-only mode.   *\
             * This should minimise the risk of the system connecting   *
             * to an AP the user can not access and thereby losing      *
             * control of the device. By forcing them to go through the *
             * AP+STA mode, the user will always be able to rescue the  *
             * situation via the AP interface.                          *
             * Maybe we should also implement an aknowledge mechanism,  *
             * where the user will have to load a certain URL within    *
             * x minutes after switching to STA mode, otherwise the     *
            \* device will fall back to the previous configuration.     */
            snprintf(buf, sizeof(buf) - 1,
                    "<p><button onclick=\"location.href='setmode.cgi?mode=%d'\">Go to <b>AP+STA</b> mode</button> (Both AP and Client)</p>",
                    WIFI_MODE_APSTA);
            break;
        case WIFI_MODE_APSTA:
            snprintf(buf, sizeof(buf) - 1,
                    "<p><button onclick=\"location.href='setmode.cgi?mode=%d'\">Go to standalone <b>AP</b> mode</button> (Access Point Only)</p>",
                    WIFI_MODE_AP);

            /* Only offer switching to STA mode if we have a connection. */
            if (sta_connected()) {
                snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf) - 1,
                        "<p><button onclick=\"location.href='setmode.cgi?mode=%d'\">Go to standalone <b>STA</b> mode</button> (Client Only)</p>",
                        WIFI_MODE_STA);
            }
            break;
        case WIFI_MODE_STA:
        default:
            snprintf(buf, sizeof(buf) - 1,
                    "<p><button onclick=\"location.href='setmode.cgi?mode=%d'\">Go to standalone <b>AP</b> mode</button> (Access Point Only)</p>"
                    "<p><button onclick=\"location.href='setmode.cgi?mode=%d'\">Go to <b>AP+STA</b> mode</button> (Both AP and Client)</p>",
                    WIFI_MODE_AP, WIFI_MODE_APSTA);
            break;
        }

        /* Always offer WPS. */
        snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf) - 1,
                "<p><button onclick=\"location.href='startwps.cgi'\">Connect to AP with <b>WPS</b></button> "
                "This will switch to AP+STA mode. You can switch to STA only mode "
                "after the client has connected.</p>");

        /* Disable WiFi.  (only available if Eth connected?) */
        if (1) {//eth_connected()) {
            snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf) - 1,
                    "<p><button onclick=\"location.href='setmode.cgi?mode=%d'\">Disable WiFi</button> "
                    "This option may leave you unable to connect!"
                    " (unless via Ethernet.) </p>", WIFI_MODE_NULL);
        }

    } else if (strcmp(token, "StaWarn") == 0) {
        result = esp_wifi_get_mode(&mode);
        if (result != ESP_OK) {
            goto err_out;
        }

        switch(mode) {
        case WIFI_MODE_STA:
        case WIFI_MODE_APSTA:
            result = esp_wifi_sta_get_ap_info(&stcfg);
            if (result != ESP_OK) {
                snprintf(buf, sizeof(buf) - 1, "STA is <b>not connected</b>.");
            } else {
                snprintf(buf, sizeof(buf) - 1, "STA is connected to: <b>%s</b>", (char *) stcfg.ssid);
            }
            break;
        case WIFI_MODE_AP:
        default:
            snprintf(buf, sizeof(buf) - 1, "Warning: STA Disabled! " "<b>Can't scan in this mode.</b>");
            break;
        }
    }else if (strcmp(token, "ApWarn") == 0) {
        result = esp_wifi_get_mode(&mode);
        if (result != ESP_OK) {
            goto err_out;
        }

        switch(mode) {
        case WIFI_MODE_AP:
        case WIFI_MODE_APSTA:
            break;
        case WIFI_MODE_STA:
        default:
            snprintf(buf, sizeof(buf) - 1, "Warning: AP Disabled!  Save AP Settings will have no effect.");
            break;
        }
    }

    ehttpd_send(conn, (uint8_t *) buf, -1);

    err_out:
    return EHTTPD_STATUS_DONE;
}
