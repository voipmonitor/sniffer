#ifndef BOUNDED_MOODYCAMEL_HPP_
#define BOUNDED_MOODYCAMEL_HPP_

#include "concurrentqueue.h"
#include <atomic>
#include <cstddef>
#include <vector>

/**
 * Bounded wrapper pro moodycamel::ConcurrentQueue
 *
 * Poskytuje:
 * - push() - vrací false když je fronta plná
 * - pop()  - vrací false když je fronta prázdná
 * - Striktní dodržení max_size
 */
template<typename T>
class BoundedMoodycamel {
public:
    /**
     * @param max_size Maximální počet prvků ve frontě
     * @param num_producers Počet producer threadů (pro optimalizaci)
     * @param num_consumers Počet consumer threadů (pro optimalizaci)
     */
    BoundedMoodycamel(size_t max_size,
                      size_t num_producers = 1,
                      size_t num_consumers = 1)
        : queue_(max_size, num_producers, num_consumers),
          max_size_(max_size),
          size_(0)
    {}

    /**
     * Push prvek do fronty
     * @return true při úspěchu, false když je fronta plná
     */
    bool push(const T& item) {
        // Atomicky zkontroluj a inkrementuj
        size_t current = size_.load(std::memory_order_relaxed);

        while(current < max_size_) {
            if(size_.compare_exchange_weak(current, current + 1,
                                          std::memory_order_acquire,
                                          std::memory_order_relaxed)) {
                // Podařilo se rezervovat místo
                queue_.enqueue(item);
                return true;
            }
            // CAS selhal - current se updatoval, zkus znovu
        }

        // Fronta plná
        return false;
    }

    /**
     * Pop prvek z fronty
     * @param out Ukazatel kam uložit výsledek
     * @return true při úspěchu, false když je fronta prázdná
     */
    bool pop(T* out) {
        if(queue_.try_dequeue(*out)) {
            size_.fetch_sub(1, std::memory_order_release);
            return true;
        }
        // Fronta prázdná
        return false;
    }

    /**
     * Přibližný počet prvků ve frontě
     * Nepřesné kvůli souběžnosti!
     */
    size_t size_approx() const {
        return size_.load(std::memory_order_relaxed);
    }

    /**
     * Maximální kapacita
     */
    size_t capacity() const {
        return max_size_;
    }

private:
    moodycamel::ConcurrentQueue<T> queue_;
    const size_t max_size_;
    std::atomic<size_t> size_;
};

/**
 * Varianta s per-thread tokens pro vyšší výkon
 *
 * DŮLEŽITÉ: Musíš explicitně předat thread_id při push/pop!
 */
template<typename T>
class BoundedMoodycamelTokenized {
public:
    BoundedMoodycamelTokenized(size_t max_size,
                               size_t num_producers,
                               size_t num_consumers)
        : queue_(max_size, num_producers, num_consumers),
          max_size_(max_size),
          size_(0)
    {
        // Předalokuj tokeny
        for(size_t i = 0; i < num_producers; ++i) {
            prod_tokens_.emplace_back(queue_);
        }
        for(size_t i = 0; i < num_consumers; ++i) {
            cons_tokens_.emplace_back(queue_);
        }
    }

    /**
     * Push s explicitním producer ID
     * @param item Co vložit
     * @param producer_id ID producera (0 až num_producers-1)
     */
    bool push(const T& item, size_t producer_id) {
        size_t current = size_.load(std::memory_order_relaxed);

        while(current < max_size_) {
            if(size_.compare_exchange_weak(current, current + 1,
                                          std::memory_order_acquire,
                                          std::memory_order_relaxed)) {
                queue_.enqueue(prod_tokens_[producer_id], item);
                return true;
            }
        }
        return false;
    }

    /**
     * Pop s explicitním consumer ID
     * @param out Kam uložit výsledek
     * @param consumer_id ID consumera (0 až num_consumers-1)
     */
    bool pop(T* out, size_t consumer_id) {
        if(queue_.try_dequeue(cons_tokens_[consumer_id], *out)) {
            size_.fetch_sub(1, std::memory_order_release);
            return true;
        }
        return false;
    }

    size_t size_approx() const {
        return size_.load(std::memory_order_relaxed);
    }

    size_t capacity() const {
        return max_size_;
    }

private:
    moodycamel::ConcurrentQueue<T> queue_;
    const size_t max_size_;
    std::atomic<size_t> size_;

    std::vector<moodycamel::ProducerToken> prod_tokens_;
    std::vector<moodycamel::ConsumerToken> cons_tokens_;
};

#endif // BOUNDED_MOODYCAMEL_HPP_
