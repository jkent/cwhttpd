/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "log.h"
#include "cwhttpd/httpd.h"
#include "cwhttpd/port.h"

#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>


void cwhttpd_delay_ms(uint32_t ms)
{
    usleep(ms * 1000);
}

long long cwhttpd_log_timestamp(void)
{
    struct timeval te;
    gettimeofday(&te, NULL);
    long long ms = te.tv_sec * 1000LL + te.tv_usec / 1000;
    return ms;
}

struct cwhttpd_mutex_t {
    pthread_mutex_t handle;
};

cwhttpd_mutex_t *cwhttpd_mutex_create(bool recursive)
{
    cwhttpd_mutex_t *mutex = (cwhttpd_mutex_t *) malloc(sizeof(cwhttpd_mutex_t));
    if (mutex == NULL) {
        LOGE(__func__, "malloc failed");
        return NULL;
    }

    pthread_mutexattr_t mutexattr;
    pthread_mutexattr_init(&mutexattr);
    if (recursive) {
        pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_RECURSIVE);
    }
    pthread_mutex_init(&mutex->handle, &mutexattr);

    return mutex;
}

void cwhttpd_mutex_lock(cwhttpd_mutex_t *mutex)
{
    pthread_mutex_lock(&mutex->handle);
}

void cwhttpd_mutex_unlock(cwhttpd_mutex_t *mutex)
{
    pthread_mutex_unlock(&mutex->handle);
}

void cwhttpd_mutex_delete(cwhttpd_mutex_t *mutex)
{
    pthread_mutex_destroy(&mutex->handle);
    free(mutex);
}

cwhttpd_semaphore_t *cwhttpd_semaphore_create(uint32_t max, uint32_t initial)
{
    sem_t *semaphore = malloc(sizeof(sem_t));
    if (semaphore == NULL) {
        return NULL;
    }

    if (sem_init(semaphore, 0, initial)) {
        free(semaphore);
        return NULL;
    }

    return (cwhttpd_semaphore_t *) semaphore;
}

bool cwhttpd_semaphore_take(cwhttpd_semaphore_t *semaphore, uint32_t timeout_ms)
{
    if (timeout_ms == 0) {
        return sem_trywait((sem_t *) semaphore) == 0;
    } else if (timeout_ms == UINT32_MAX) {
        return sem_wait((sem_t *) semaphore) == 0;
    } else {
        struct timespec ts;
        if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
            return false;
        }
        ts.tv_sec += timeout_ms / 1000;
        ts.tv_nsec += (timeout_ms % 1000) * 1000000;
        ts.tv_sec += ts.tv_nsec / 1000000000;
        ts.tv_nsec %= 1000000000;
        return sem_timedwait((sem_t *) semaphore, &ts) == 0;
    }
}

bool cwhttpd_semaphore_give(cwhttpd_semaphore_t *semaphore)
{
    int num;
    sem_getvalue((sem_t *) semaphore, &num);
    if (num == 1) {
        return false;
    }
    return sem_post((sem_t *) semaphore) == 0;
}

void cwhttpd_semaphore_delete(cwhttpd_semaphore_t *semaphore)
{
    sem_destroy((sem_t *) semaphore);
}

struct cwhttpd_thread_t {
    pthread_t pthread;
    cwhttpd_thread_func_t fn;
    void *arg;
};

static void *thread_handler(void *arg)
{
    cwhttpd_thread_t *thread = (cwhttpd_thread_t *) arg;

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    thread->fn(thread->arg);
    return NULL;
}

cwhttpd_thread_t *cwhttpd_thread_create(cwhttpd_thread_func_t fn,
        void *arg, const cwhttpd_thread_attr_t *attr)
{
    cwhttpd_thread_t *thread = (cwhttpd_thread_t *) malloc(sizeof(cwhttpd_thread_t));
    if (thread == NULL) {
        LOGE(__func__, "malloc failed");
        return NULL;
    }

    thread->fn = fn;
    thread->arg = arg;

    if (pthread_create(&thread->pthread, NULL, thread_handler, thread) != 0) {
        LOGE(__func__, "pthread_create error");
        return NULL;
    }

    return thread;
}

void cwhttpd_thread_delete(cwhttpd_thread_t *thread)
{
    if (pthread_self() == thread->pthread) {
        sigset_t set;
        struct timespec timeout = {};
        sigemptyset(&set);
        sigaddset(&set, SIGPIPE);
        sigtimedwait(&set, NULL, &timeout);
    }

    if (thread == NULL) {
        pthread_exit(NULL);
    } else {
        pthread_exit(&thread->pthread);
        free(thread);
    }
}

struct cwhttpd_timer_t {
    timer_t handle;
    struct itimerspec ts;
    void (*cb)(void *arg);
    void *arg;
};

static void timer_handler(union sigval val)
{
    struct cwhttpd_timer_t *timer = (struct cwhttpd_timer_t *) val.sival_ptr;
    timer->cb(timer->arg);
}

cwhttpd_timer_t *cwhttpd_timer_create(int ms, bool autoreload,
        cwhttpd_timer_handler_t cb, void *arg)
{
    struct cwhttpd_timer_t *timer =
            (struct cwhttpd_timer_t *) calloc(1, sizeof(struct cwhttpd_timer_t));
    if (timer == NULL) {
        LOGE(__func__, "calloc failed");
        return NULL;
    }

    timer->ts.it_value.tv_sec = ms / 1000;
    timer->ts.it_value.tv_nsec = (ms % 1000) * 1000000;
    if (autoreload) {
        timer->ts.it_interval.tv_sec = ms / 1000;
        timer->ts.it_interval.tv_nsec = (ms % 1000) * 1000000;
    }
    timer->cb = cb;
    timer->arg = arg;

    struct sigevent event;
    event.sigev_notify = SIGEV_THREAD;
    event.sigev_notify_function = timer_handler;
    event.sigev_value.sival_ptr = timer;

    if(timer_create(CLOCK_MONOTONIC, &event, &timer->handle) < 0) {
        LOGE(__func__, "timer_create failed");
        free(timer);
        return NULL;
    }

    return timer;
}

void cwhttpd_timer_start(cwhttpd_timer_t *timer)
{
    if (timer_settime(timer->handle, 0, &timer->ts, NULL) < 0) {
        LOGE(__func__, "timer_settime failed");
    }
}

void cwhttpd_timer_stop(cwhttpd_timer_t *timer)
{
    struct itimerspec ts = {};
    if (timer_settime(timer->handle, 0, &ts, NULL) < 0) {
        LOGE(__func__, "timer_settime failed");
    }
}

void cwhttpd_timer_delete(cwhttpd_timer_t *timer)
{
    timer_delete(timer->handle);
    free(timer);
}
