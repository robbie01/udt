#pragma once

#if defined(WINDOWS)
#include <windows.h>
#include <limits>
#elif defined(MACOSX)
#include <dispatch/dispatch.h>
#else
#include <semaphore.h>
#include <time.h>
#endif

#include <mutex>
#include <condition_variable>
#include <cstdint>
#include <chrono>
#include <atomic>

namespace rsynch {

class Semaphore {
private:
#if defined(WINDOWS)
    HANDLE inner;
#elif defined(MACOSX)
    dispatch_semaphore_t inner;
#else
    sem_t inner;
#endif

public:
    Semaphore(const Semaphore&) = delete;
    Semaphore& operator=(const Semaphore&) = delete;

    inline Semaphore() {
#if defined(WINDOWS)
        inner = CreateSemaphore(nullptr, 0, LONG_MAX, nullptr);
#elif defined(MACOSX)
        inner = dispatch_semaphore_create(0);
#else
        sem_init(&inner, 0, 0);
#endif
    }

    inline ~Semaphore() {
#if defined(WINDOWS)
        CloseHandle(inner);
#elif defined(MACOSX)
        dispatch_release(inner);
#else
        sem_destroy(&inner);
#endif
    }

    inline void post() {
#if defined(WINDOWS)
        ReleaseSemaphore(inner, 1, nullptr);
#elif defined(MACOSX)
        dispatch_semaphore_signal(inner);
#else
        sem_post(&inner);
#endif
    }

    inline void wait() {
#if defined(WINDOWS)
        WaitForSingleObject(inner, INFINITE);
#elif defined(MACOSX)
        dispatch_semaphore_wait(inner, DISPATCH_TIME_FOREVER);
#else
        int res;
        do {
                res = sem_wait(&inner);
        } while (res == -1 && errno == EINTR);
#endif
    }

    template<class Rep, class Period>
    inline bool wait_for(const std::chrono::duration<Rep, Period>& timeout) {
#if defined(WINDOWS)
        auto delta = std::chrono::duration_cast<std::chrono::duration<DWORD, std::milli>>(timeout);
        return WaitForSingleObject(inner, delta.count()) == WAIT_OBJECT_0;
#elif defined(MACOSX)
        auto delta = std::chrono::duration_cast<std::chrono::duration<std::int64_t, std::nano>>(timeout);
        return dispatch_semaphore_wait(inner, dispatch_time(DISPATCH_TIME_NOW, delta.count())) == 0;
#else
        auto delta = std::chrono::duration_cast<std::chrono::duration<std::uint64_t, std::nano>>(timeout).count();
        timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        delta += ts.tv_nsec;
        ts.tv_sec += delta / 1000000000;
        ts.tv_nsec = delta % 1000000000;
        int res;
        do {
                res = sem_timedwait(&inner, &ts);
        } while (res == -1 && errno == EINTR);
        return res == 0;
#endif
    }

    inline bool try_wait() {
#if defined(WINDOWS)
        return WaitForSingleObject(inner, 0) == WAIT_OBJECT_0;
#elif defined(MACOSX)
        return dispatch_semaphore_wait(inner, DISPATCH_TIME_NOW) == 0;
#else
        return sem_trywait(&inner) == 0;
#endif
    }
};

class AutoResetEvent {
private:
    // status: 0 = unset, no waiters
    //         1 = set
    //        -N = unset, N waiters
    std::atomic<int> status{0};
    Semaphore sem;

public:
    AutoResetEvent() = default;
    AutoResetEvent(const AutoResetEvent&) = delete;
    AutoResetEvent& operator=(const AutoResetEvent&) = delete;

    inline void set() {
        int old = status.load(std::memory_order_relaxed);
        for (;;) {
                int new_ = old < 1 ? old + 1 : 1;
                if (status.compare_exchange_weak(old, new_, std::memory_order_release, std::memory_order_relaxed))
                        break;
        }
        if (old < 0) sem.post();
    }

    inline void wait() {
        if (status.fetch_sub(1, std::memory_order_acquire) < 1) sem.wait();
    }

    // There's a bug in this implementation that can cause another waiter to wake up
    // spuriously from a single set() call. Luckily this is only ever used just to
    // have an interruptible timer.
    template<class Rep, class Period>
    inline bool wait_for(const std::chrono::duration<Rep, Period>& timeout) {
        if (status.fetch_sub(1, std::memory_order_acquire) == 1) return true;
        if (sem.wait_for(timeout)) return true;

        int old = status.load(std::memory_order_relaxed);
        for (;;) {
                // Adding is a dangerous game because we don't want to accidentally signal.
                int new_ = old < 0 ? old + 1 : 0;
                if (status.compare_exchange_weak(old, new_, std::memory_order_acquire, std::memory_order_relaxed))
                        break;
        }
        return old == 1;
    }

    inline bool try_wait() {
        int v = 1;
        return status.compare_exchange_strong(v, 0, std::memory_order_acquire, std::memory_order_relaxed);
    }
};

}