/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "log.h"
#include "cwhttpd/httpd.h"
#include "cwhttpd/port.h"

#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <freertos/task.h>
#include <freertos/timers.h>
#include <freertos/queue.h>

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

#ifndef CONFIG_CWHTTPD_DEFAULT_STACK_SIZE
# define CONFIG_CWHTTPD_DEFAULT_STACK_SIZE 8192
#endif

#ifndef CONFIG_CWHTTPD_DEFAULT_AFFINITY
# define CONFIG_CWHTTPD_DEFAULT_AFFINITY tskNO_AFFINITY
#endif

#ifndef CONFIG_CWHTTPD_DEFAULT_PRIORITY
# define CONFIG_CWHTTPD_DEFAULT_PRIORITY 4
#endif

struct cwhttpd_mutex_t {
    bool recursive;
    SemaphoreHandle_t handle;
};

void cwhttpd_delay_ms(uint32_t ms)
{
    vTaskDelay(pdMS_TO_TICKS(ms));
}

#if defined(UNIX)
long long cwhttpd_log_timestamp(void)
{
    struct timeval te;
    gettimeofday(&te, NULL);
    long long ms = te.tv_sec * 1000LL + te.tv_usec / 1000;
    return ms;
}
#endif

cwhttpd_mutex_t *cwhttpd_mutex_create(bool recursive)
{
    struct cwhttpd_mutex_t *mutex =
            (struct cwhttpd_mutex_t *) malloc(sizeof(struct cwhttpd_mutex_t));
    if (mutex == NULL) {
        LOGE(__func__, "malloc failed");
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

void cwhttpd_mutex_lock(cwhttpd_mutex_t *mutex)
{
    if (mutex->recursive) {
        xSemaphoreTakeRecursive(mutex->handle, portMAX_DELAY);
    } else {
        xSemaphoreTake(mutex->handle, portMAX_DELAY);
    }
}

void cwhttpd_mutex_unlock(cwhttpd_mutex_t *mutex)
{
    if (mutex->recursive) {
        xSemaphoreGiveRecursive(mutex->handle);
    } else {
        xSemaphoreGive(mutex->handle);
    }
}

void cwhttpd_mutex_delete(cwhttpd_mutex_t *mutex)
{
    vSemaphoreDelete(mutex->handle);
    free(mutex);
}

cwhttpd_semaphore_t *cwhttpd_semaphore_create(uint32_t max, uint32_t initial)
{
    return (cwhttpd_semaphore_t *) xSemaphoreCreateCounting(max, initial);
}

bool cwhttpd_semaphore_take(cwhttpd_semaphore_t *semaphore, uint32_t timeout_ms)
{
    return xSemaphoreTake((SemaphoreHandle_t) semaphore,
            pdMS_TO_TICKS(timeout_ms)) == pdTRUE;
}

bool cwhttpd_semaphore_give(cwhttpd_semaphore_t *semaphore)
{
    return xSemaphoreGive((SemaphoreHandle_t) semaphore) == pdTRUE;
}

void cwhttpd_semaphore_delete(cwhttpd_semaphore_t *semaphore)
{
    vSemaphoreDelete((SemaphoreHandle_t) semaphore);
}

struct cwhttpd_thread_t {
    TaskHandle_t handle;
    cwhttpd_thread_func_t fn;
    void *arg;
};

static void thread_handler(void *pvParameters)
{
    cwhttpd_thread_t *thread = (cwhttpd_thread_t *) pvParameters;

#if defined(UNIX)
    sigset_t sig_block;
    sigemptyset(&sig_block);
    sigaddset(&sig_block, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &sig_block, NULL);
#endif

    thread->fn(thread->arg);
}

cwhttpd_thread_t *cwhttpd_thread_create(cwhttpd_thread_func_t fn,
        void *arg, const cwhttpd_thread_attr_t *attr)
{
    cwhttpd_thread_t *thread = (cwhttpd_thread_t *) malloc(sizeof(cwhttpd_thread_t));
    if (thread == NULL) {
        return NULL;
    }

    thread->fn = fn;
    thread->arg = arg;

    if (attr == NULL) {
        xTaskCreatePinnedToCore(thread_handler, "cwhttpd", 2048, thread,
                tskIDLE_PRIORITY, &thread->handle, tskNO_AFFINITY);
    } else {
        int32_t affinity =
                (attr->affinity == -1) ? tskNO_AFFINITY : attr->affinity;
        xTaskCreatePinnedToCore(thread_handler, attr->name, attr->stack_size,
                thread, attr->priority, &thread->handle, affinity);
    }

    return thread;
}

void cwhttpd_thread_delete(cwhttpd_thread_t *thread)
{
    if (thread == NULL) {
        vTaskDelete(NULL);
    } else {
        vTaskDelete(thread->handle);
        free(thread);
    }
}

struct cwhttpd_timer_t {
    TimerHandle_t handle;
    void (*cb)(void *arg);
    void *arg;
};

static void timer_handler(TimerHandle_t handle)
{
    cwhttpd_timer_t *timer = (cwhttpd_timer_t *) pvTimerGetTimerID(handle);
    timer->cb(timer->arg);
}

cwhttpd_timer_t *cwhttpd_timer_create(int ms, bool autoreload,
        cwhttpd_timer_handler_t cb, void *arg)
{
    cwhttpd_timer_t *timer = (cwhttpd_timer_t *) malloc(sizeof(cwhttpd_timer_t));
    if (timer == NULL) {
        return NULL;
    }

    timer->handle = xTimerCreate("esphttpd", pdMS_TO_TICKS(ms),
            autoreload ? pdTRUE:pdFALSE, timer, timer_handler);
    if (timer->handle == NULL) {
        free(timer);
        LOGE(__func__, "xTimerCreate failed");
        return NULL;
    }

    timer->cb = cb;
    timer->arg = arg;

    return timer;
}

void cwhttpd_timer_start(cwhttpd_timer_t *timer)
{
    xTimerStart(timer->handle, portMAX_DELAY);
}

void cwhttpd_timer_stop(cwhttpd_timer_t *timer)
{
    xTimerStop(timer->handle, portMAX_DELAY);
}

void cwhttpd_timer_delete(cwhttpd_timer_t *timer)
{
    xTimerDelete(timer->handle, portMAX_DELAY);
    free(timer);
}
