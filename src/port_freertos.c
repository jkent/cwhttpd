/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "log.h"
#include "libesphttpd/httpd.h"
#include "libesphttpd/port.h"

#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <freertos/task.h>
#include <freertos/timers.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#if defined(UNIX)
# include <sys/time.h>
# include <signal.h>
#endif


#if defined(UNIX)
#define tskNO_AFFINITY 0
#define xTaskCreatePinnedToCore(task, name, stack, arg, pri, handle, affinity) \
        xTaskCreate(task, name, stack, arg, pri, handle)
#endif

#ifndef CONFIG_EHTTPD_DEFAULT_STACK_SIZE
# define CONFIG_EHTTPD_DEFAULT_STACK_SIZE 8192
#endif

#ifndef CONFIG_EHTTPD_DEFAULT_AFFINITY
# define CONFIG_EHTTPD_DEFAULT_AFFINITY tskNO_AFFINITY
#endif

#ifndef CONFIG_EHTTPD_DEFAULT_PRIORITY
# define CONFIG_EHTTPD_DEFAULT_PRIORITY 4
#endif

struct ehttpd_mutex_t {
    bool recursive;
    SemaphoreHandle_t handle;
};

void ehttpd_delay_ms(uint32_t ms)
{
    vTaskDelay(pdMS_TO_TICKS(ms));
}

#if defined(UNIX)
long long ehttpd_log_timestamp(void)
{
    struct timeval te;
    gettimeofday(&te, NULL);
    long long ms = te.tv_sec * 1000LL + te.tv_usec / 1000;
    return ms;
}
#endif

ehttpd_mutex_t *ehttpd_mutex_create(bool recursive)
{
    struct ehttpd_mutex_t *mutex =
            (struct ehttpd_mutex_t *) malloc(sizeof(struct ehttpd_mutex_t));
    if (mutex == NULL) {
        EHTTPD_LOGE(__func__, "malloc failed");
        return NULL;
    }

    mutex->recursive = true;
    if (recursive) {
        mutex->handle = xSemaphoreCreateRecursiveMutex();
    } else {
        mutex->handle = xSemaphoreCreateMutex();
    }

    if (mutex->handle == NULL) {
        free(mutex);
        return NULL;
    }

    return mutex;
}

void ehttpd_mutex_lock(ehttpd_mutex_t *mutex)
{
    if (mutex->recursive) {
        xSemaphoreTakeRecursive(mutex->handle, portMAX_DELAY);
    } else {
        xSemaphoreTake(mutex->handle, portMAX_DELAY);
    }
}

void ehttpd_mutex_unlock(ehttpd_mutex_t *mutex)
{
    if (mutex->recursive) {
        xSemaphoreGiveRecursive(mutex->handle);
    } else {
        xSemaphoreGive(mutex->handle);
    }
}

void ehttpd_mutex_delete(ehttpd_mutex_t *mutex)
{
    vSemaphoreDelete(mutex->handle);
    free(mutex);
}

struct ehttpd_thread_t {
    xTaskHandle handle;
    ehttpd_thread_func_t fn;
    void *arg;
};

static void thread_handler(void *pvParameters)
{
    ehttpd_thread_t *thread = (ehttpd_thread_t *) pvParameters;

#if defined(UNIX)
    sigset_t sig_block;
    sigemptyset(&sig_block);
    sigaddset(&sig_block, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &sig_block, NULL);
#endif

    thread->fn(thread->arg);
}

ehttpd_thread_t *ehttpd_thread_create(ehttpd_thread_func_t fn,
        void *arg, const ehttpd_thread_attr_t *attr)
{
    ehttpd_thread_t *thread = (ehttpd_thread_t *) malloc(sizeof(ehttpd_thread_t));
    if (thread == NULL) {
        return NULL;
    }

    thread->fn = fn;
    thread->arg = arg;

    if (attr == NULL) {
        xTaskCreatePinnedToCore(thread_handler, "esphttpd",
                CONFIG_EHTTPD_DEFAULT_STACK_SIZE, thread,
                CONFIG_EHTTPD_DEFAULT_PRIORITY, &thread->handle,
                CONFIG_EHTTPD_DEFAULT_AFFINITY);
    } else {
        xTaskCreatePinnedToCore(thread_handler, "esphttpd", attr->stack_size,
                thread, attr->priority, &thread->handle, attr->affinity);
    }

    return thread;
}

void ehttpd_thread_delete(ehttpd_thread_t *thread)
{
    if (thread == NULL) {
        vTaskDelete(NULL);
    } else {
        vTaskDelete(thread->handle);
        free(thread);
    }
}

struct ehttpd_timer_t {
    TimerHandle_t handle;
    void (*cb)(void *arg);
    void *arg;
};

static void timer_handler(TimerHandle_t handle)
{
    ehttpd_timer_t *timer = (ehttpd_timer_t *) pvTimerGetTimerID(handle);
    timer->cb(timer->arg);
}

ehttpd_timer_t *ehttpd_timer_create(int ms, bool autoreload,
        ehttpd_timer_handler_t cb, void *arg)
{
    ehttpd_timer_t *timer = (ehttpd_timer_t *) malloc(sizeof(ehttpd_timer_t));
    if (timer == NULL) {
        return NULL;
    }

    timer->handle = xTimerCreate("esphttpd", pdMS_TO_TICKS(ms),
            autoreload ? pdTRUE:pdFALSE, timer, timer_handler);
    if (timer->handle == NULL) {
        free(timer);
        EHTTPD_LOGE(__func__, "xTimerCreate failed");
        return NULL;
    }

    timer->cb = cb;
    timer->arg = arg;

    return timer;
}

void ehttpd_timer_start(ehttpd_timer_t *timer)
{
    xTimerStart(timer->handle, portMAX_DELAY);
}

void ehttpd_timer_stop(ehttpd_timer_t *timer)
{
    xTimerStop(timer->handle, portMAX_DELAY);
}

void ehttpd_timer_delete(ehttpd_timer_t *timer)
{
    xTimerDelete(timer->handle, portMAX_DELAY);
    free(timer);
}
