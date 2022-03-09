/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "httpd.h"

#include <stdint.h>


/*********************
 * \section Typedefs
 *********************/

typedef struct cwhttpd_mutex_t cwhttpd_mutex_t;
typedef struct cwhttpd_semaphore_t cwhttpd_semaphore_t;
typedef struct cwhttpd_thread_t cwhttpd_thread_t;
typedef struct cwhttpd_timer_t cwhttpd_timer_t;
typedef struct cwhttpd_queue_t cwhttpd_queue_t;

/*****************
 * \section Delay
 *****************/

/**
 * \brief Blocking delay for time given in milliseconds
 */
void cwhttpd_delay_ms(
    uint32_t ms /** [in] milliseconds */
);


/******************
 * \section Mutex
 ******************/

/**
 * \brief Create a mutex, in the unlocked state
 *
 * \return mutex handle or NULL on error
 */
cwhttpd_mutex_t *cwhttpd_mutex_create(
    bool recursive /** [in] **true** for recursive */
);

/**
 * \brief Lock a mutex
 */
void cwhttpd_mutex_lock(
    cwhttpd_mutex_t *mutex /** [in] mutex handle */
);

/**
 * \brief Unlock a mutex
 */
void cwhttpd_mutex_unlock(
    cwhttpd_mutex_t *mutex /** [in] mutex handle */
);

/**
 * \brief Delete a mutex
 */
void cwhttpd_mutex_delete(
    cwhttpd_mutex_t *mutex /** [in] mutex handle */
);


/**********************
 * \section Semaphore
 **********************/

/**
 * \brief Create a semaphore
 *
 * \return Semaphore handle or NULL on error
 */
cwhttpd_semaphore_t *cwhttpd_semaphore_create(
    uint32_t max, /** [in] max semaphore value */
    uint32_t initial /** [in] initial semaphore value */
);

/**
 * \brief Take semaphore
 *
 * \return true if taken
 */
bool cwhttpd_semaphore_take(
    cwhttpd_semaphore_t *semaphore, /** [in] semaphore handle */
    uint32_t timeout_ms /** [in] timeout in ms, MAX_UINT32 to wait forever */
);

/**
 * \brief Give semaphore
 *
 * \return true if given
 */
bool cwhttpd_semaphore_give(
    cwhttpd_semaphore_t *semaphore /** [in] semaphore handle */
);

/**
 * \breif Delete semaphore
 */
void cwhttpd_semaphore_delete(
    cwhttpd_semaphore_t *semaphore /** [in] semaphore handle */
);


/*******************
 * \section Thread
 *******************/

#define CWHTTPD_NO_AFFINITY INT_MAX

/**
 * \brief Thread attribute struct
 */
typedef struct cwhttpd_thread_attr_t {
    const char *name; /**< FreeRTOS task name */
    uint16_t stack_size; /**< FreeRTOS stack depth in words */
    uint32_t priority; /**< FreeRTOS priority */
    int32_t  affinity; /**< FreeRTOS processor affinity */
} cwhttpd_thread_attr_t;

/**
 * \brief Create a thread
 *
 * \returns thread handle or NULL on error
 */
cwhttpd_thread_t *cwhttpd_thread_create(
    cwhttpd_thread_func_t fn, /** [in] thread function */
    void *arg, /** [in] thread argument */
    const cwhttpd_thread_attr_t *attr /** [in] thread attributes or NULL for
                                                 defaults */
);

/**
 * \brief Delete thread
 */
void cwhttpd_thread_delete(
    cwhttpd_thread_t *thread /** [in] thread handle or NULL to delete current
                                        thread */
);


/******************
 * \section Timer
 ******************/

/**
 * \brief Create a timer, waiting to be armed
 *
 * \return timer handle or NULL on error
 */
cwhttpd_timer_t *cwhttpd_timer_create(
    int ms, /** [in] timer expiry in milliseconds */
    bool autoreload, /** [in] repeat timer after expiry */
    cwhttpd_timer_handler_t cb, /** [in] timer callback function */
    void *arg /** [in] timer callback argument */
);

/**
 * \brief Arm a timer
 */
void cwhttpd_timer_start(
    cwhttpd_timer_t *timer /** [in] timer handle */
);

/**
 * \brief Disarm a timer
 */
void cwhttpd_timer_stop(
    cwhttpd_timer_t *timer /** [in] timer handle */
);

/**
 * \brief Delete a timer
 */
void cwhttpd_timer_delete(
    cwhttpd_timer_t *timer /** [in] timer handle */
);


#ifdef __cplusplus
}
#endif
