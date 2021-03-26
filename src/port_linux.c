/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "log.h"
#include "libesphttpd/httpd.h"
#include "libesphttpd/port.h"

#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>


void ehttpd_delay_ms(uint32_t ms)
{
    usleep(ms * 1000);
}

long long ehttpd_log_timestamp(void)
{
    struct timeval te;
    gettimeofday(&te, NULL);
    long long ms = te.tv_sec * 1000LL + te.tv_usec / 1000;
    return ms;
}

struct ehttpd_mutex_t {
    pthread_mutex_t handle;
};

ehttpd_mutex_t *ehttpd_mutex_create(bool recursive)
{
    ehttpd_mutex_t *mutex = (ehttpd_mutex_t *) malloc(sizeof(ehttpd_mutex_t));
    if (mutex == NULL) {
        EHTTPD_LOGE(__func__, "malloc failed");
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

void ehttpd_mutex_lock(ehttpd_mutex_t *mutex)
{
    pthread_mutex_lock(&mutex->handle);
}

void ehttpd_mutex_unlock(ehttpd_mutex_t *mutex)
{
    pthread_mutex_unlock(&mutex->handle);
}

void ehttpd_mutex_delete(ehttpd_mutex_t *mutex)
{
    pthread_mutex_destroy(&mutex->handle);
    free(mutex);
}

struct ehttpd_thread_t {
    pthread_t pthread;
    ehttpd_thread_func_t fn;
    void *arg;
};

static void *thread_handler(void *arg)
{
    ehttpd_thread_t *thread = (ehttpd_thread_t *) arg;

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    thread->fn(thread->arg);
    return NULL;
}

ehttpd_thread_t *ehttpd_thread_create(ehttpd_thread_func_t fn,
        void *arg, const ehttpd_thread_attr_t *attr)
{
    ehttpd_thread_t *thread = (ehttpd_thread_t *) malloc(sizeof(ehttpd_thread_t));
    if (thread == NULL) {
        EHTTPD_LOGE(__func__, "malloc failed");
        return NULL;
    }

    thread->fn = fn;
    thread->arg = arg;

    if (pthread_create(&thread->pthread, NULL, thread_handler, thread) != 0) {
        EHTTPD_LOGE(__func__, "pthread_create error");
        return NULL;
    }

    return thread;
}

void ehttpd_thread_delete(ehttpd_thread_t *thread)
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

struct ehttpd_timer_t {
    timer_t handle;
    struct itimerspec ts;
    void (*cb)(void *arg);
    void *arg;
};

static void timer_handler(union sigval val)
{
    struct ehttpd_timer_t *timer = (struct ehttpd_timer_t *) val.sival_ptr;
    timer->cb(timer->arg);
}

ehttpd_timer_t *ehttpd_timer_create(int ms, bool autoreload,
        ehttpd_timer_handler_t cb, void *arg)
{
    struct ehttpd_timer_t *timer =
            (struct ehttpd_timer_t *) calloc(1, sizeof(struct ehttpd_timer_t));
    if (timer == NULL) {
        EHTTPD_LOGE(__func__, "calloc failed");
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
        EHTTPD_LOGE(__func__, "timer_create failed");
        free(timer);
        return NULL;
    }

    return timer;
}

void ehttpd_timer_start(ehttpd_timer_t *timer)
{
    if (timer_settime(timer->handle, 0, &timer->ts, NULL) < 0) {
        EHTTPD_LOGE(__func__, "timer_settime failed");
    }
}

void ehttpd_timer_stop(ehttpd_timer_t *timer)
{
    struct itimerspec ts = {};
    if (timer_settime(timer->handle, 0, &ts, NULL) < 0) {
        EHTTPD_LOGE(__func__, "timer_settime failed");
    }
}

void ehttpd_timer_delete(ehttpd_timer_t *timer)
{
    timer_delete(timer->handle);
    free(timer);
}
