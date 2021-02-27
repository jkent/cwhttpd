#pragma once

#include <stdatomic.h>
#include <stddef.h>

#if defined(CONFIG_IDF_TARGET_ESP8266) || defined(ESP_PLATFORM)
# include <freertos/FreeRTOS.h>
#else
# define configAssert()
#endif


#if !defined(koffsetof)
#define koffsetof(type, member) ((size_t) &((type *) 0)->member)
#endif

#if !defined(kcontainer_of)
#define kcontainer_of(ptr, type, member) ({                  \
    const typeof( ((type *) 0)->member ) *__mptr = (ptr);    \
    (type *) ( (char *) __mptr - koffsetof(type, member) );})
#endif


struct kref {
    atomic_int count;
};


static inline void kref_init(struct kref *kref)
{
    atomic_init(&(kref->count), 1);
}


static inline void kref_get(struct kref *kref)
{
    int old;

    old = atomic_fetch_add(&(kref->count), 1);
    configASSERT(old >= 1);

    (void) old;
}


static inline int kref_put(struct kref *kref, void (*release)(struct kref *kref))
{
    int result;
    int old;

    configASSERT(release != NULL);

    result = 0;

    old = atomic_fetch_sub(&(kref->count), 1);
    configASSERT(old >= 1);

    if(old == 1){
        release(kref);
        result = 1;
    }

    return result;
}
