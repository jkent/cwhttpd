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

typedef struct ehttpd_mutex_t ehttpd_mutex_t;
typedef struct ehttpd_semaphore_t ehttpd_semaphore_t;
typedef struct ehttpd_thread_t ehttpd_thread_t;
typedef struct ehttpd_timer_t ehttpd_timer_t;
typedef struct ehttpd_queue_t ehttpd_queue_t;

/*****************
 * \section Delay
 *****************/

/**
 * \brief Blocking delay for time given in milliseconds
 */
void ehttpd_delay_ms(
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
ehttpd_mutex_t *ehttpd_mutex_create(
    bool recursive /** [in] **true** for recursive */
);

/**
 * \brief Lock a mutex
 */
void ehttpd_mutex_lock(
    ehttpd_mutex_t *mutex /** [in] mutex handle */
);

/**
 * \brief Unlock a mutex
 */
void ehttpd_mutex_unlock(
    ehttpd_mutex_t *mutex /** [in] mutex handle */
);

/**
 * \brief Delete a mutex
 */
void ehttpd_mutex_delete(
    ehttpd_mutex_t *mutex /** [in] mutex handle */
);


/**********************
 * \section Semaphore
 **********************/

/**
 * \brief Create a semaphore
 *
 * \return Semaphore handle or NULL on error
 */
ehttpd_semaphore_t *ehttpd_semaphore_create(
    uint32_t max, /** [in] max semaphore value */
    uint32_t initial /** [in] initial semaphore value */
);

/**
 * \brief Take semaphore
 *
 * \return true if taken
 */
bool ehttpd_semaphore_take(
    ehttpd_semaphore_t *semaphore, /** [in] semaphore handle */
    uint32_t timeout_ms /** [in] timeout in ms, MAX_UINT32 to wait forever */
);

/**
 * \brief Give semaphore
 *
 * \return true if given
 */
bool ehttpd_semaphore_give(
    ehttpd_semaphore_t *semaphore /** [in] semaphore handle */
);

/**
 * \breif Delete semaphore
 */
void ehttpd_semaphore_delete(
    ehttpd_semaphore_t *semaphore /** [in] semaphore handle */
);


/*******************
 * \section Thread
 *******************/

#define EHTTPD_NO_AFFINITY INT_MAX

/**
 * \brief Thread attribute struct
 */
typedef struct ehttpd_thread_attr_t {
    const char *name; /**< FreeRTOS task name */
    uint16_t stack_size; /**< FreeRTOS stack depth in words */
    uint32_t priority; /**< FreeRTOS priority */
    int32_t  affinity; /**< FreeRTOS processor affinity */
} ehttpd_thread_attr_t;

/**
 * \brief Create a thread
 *
 * \returns thread handle or NULL on error
 */
ehttpd_thread_t *ehttpd_thread_create(
    ehttpd_thread_func_t fn, /** [in] thread function */
    void *arg, /** [in] thread argument */
    const ehttpd_thread_attr_t *attr /** [in] thread attributes or NULL for
                                                 defaults */
);

/**
 * \brief Delete thread
 */
void ehttpd_thread_delete(
    ehttpd_thread_t *thread /** [in] thread handle or NULL to delete current
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
ehttpd_timer_t *ehttpd_timer_create(
    int ms, /** [in] timer expiry in milliseconds */
    bool autoreload, /** [in] repeat timer after expiry */
    ehttpd_timer_handler_t cb, /** [in] timer callback function */
    void *arg /** [in] timer callback argument */
);

/**
 * \brief Arm a timer
 */
void ehttpd_timer_start(
    ehttpd_timer_t *timer /** [in] timer handle */
);

/**
 * \brief Disarm a timer
 */
void ehttpd_timer_stop(
    ehttpd_timer_t *timer /** [in] timer handle */
);

/**
 * \brief Delete a timer
 */
void ehttpd_timer_delete(
    ehttpd_timer_t *timer /** [in] timer handle */
);


#ifdef __cplusplus
}
#endif
