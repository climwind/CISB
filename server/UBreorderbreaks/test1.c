/*
 * 模拟 Linux 内核 md/md.c 中的漏洞：
 *   md_submit_flush_data() 无锁更新 prev_flush_start 和 flush_bio，
 *   由于写入重排序（或中断延迟），其他 CPU 可能看到 flush_bio 先于
 *   prev_flush_start 被修改，导致 WARN_ON 触发。
 *
 * 编译：gcc -Wall -pthread -o md_flush_race md_flush_race.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>

/* 全局变量，模拟 mddev->prev_flush_start 和 mddev->flush_bio */
static unsigned long prev_flush_start = 0;
static int flush_bio = 0;          /* 0: idle, 1: bio in progress */

/* 保护 md_flush_request 的锁，但 md_submit_flush_data 不使用 */
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

/* 逻辑时钟，模拟请求到达的时间戳 */
static volatile unsigned long time_counter = 0;

/*
 * 线程1：模拟 md_submit_flush_data（完成一个 flush）
 * 无锁，先写 flush_bio = 0，再写 prev_flush_start，
 * 并在两者之间插入长时间延迟模拟中断/VM stall.
 */
static void *completer_thread(void *arg)
{
    /* 等待第一个请求提交并完成 */
    sleep(1);

    /* Step 1: 清零 flush_bio（因重排序可能先于 prev_flush_start 可见） */
    flush_bio = 0;
    printf("[Completer] flush_bio <- 0  (prev_flush_start still %lu)\n",
           prev_flush_start);

    /* 模拟长时间中断，让其他请求在此间隙执行 */
    sleep(2);

    /* Step 2: 更新 prev_flush_start（仍然无锁） */
    prev_flush_start = time_counter;  /* 记录完成时刻 */
    printf("[Completer] prev_flush_start <- %lu\n", prev_flush_start);

    return NULL;
}

/*
 * 线程2：模拟 md_flush_request（提交新的 flush 请求）
 * 在锁内检查条件：若 req_start > prev_flush_start 且 flush_bio != 0，
 * 则触发 WARN_ON；否则设置 flush_bio = 1 并开始处理。
 */
static void *requester_thread(void *arg)
{
    /* 请求 1：初始状态提交 */
    pthread_mutex_lock(&lock);
    time_counter = 1;
    unsigned long req = time_counter;
    printf("[Requester] Request 1 at time %lu\n", req);
    if (req > prev_flush_start) {
        if (flush_bio != 0) {
            printf("WARN_ON! flush_bio=%d, expected 0\n", flush_bio);
            exit(1);
        }
        flush_bio = 1;
        printf("[Requester] Request 1 accepted, flush_bio=1\n");
    }
    pthread_mutex_unlock(&lock);

    /* 等待 completer 清零 flush_bio */
    sleep(1);

    /* 请求 2：此时 flush_bio 已为 0，但 prev_flush_start 尚未更新 */
    pthread_mutex_lock(&lock);
    time_counter++;
    req = time_counter;          /* req = 2 */
    printf("[Requester] Request 2 at time %lu\n", req);
    if (req > prev_flush_start) {
        if (flush_bio != 0) {
            printf("WARN_ON! flush_bio=%d, expected 0\n", flush_bio);
            exit(1);
        }
        flush_bio = 1;          /* 接受请求 2 */
        printf("[Requester] Request 2 accepted, flush_bio=1\n");
    }
    pthread_mutex_unlock(&lock);

    /* 等待 completer 更新 prev_flush_start */
    sleep(3);

    /* 请求 3：此时 prev_flush_start 已更新，但 flush_bio 仍为 1 */
    pthread_mutex_lock(&lock);
    time_counter++;
    req = time_counter;          /* req = 3 */
    printf("[Requester] Request 3 at time %lu\n", req);
    if (req > prev_flush_start) {
        if (flush_bio != 0) {
            /* 漏洞触发！ */
            printf("WARN_ON triggered! flush_bio=%d, prev_flush_start=%lu\n",
                   flush_bio, prev_flush_start);
            printf("This would call INIT_WORK again, corrupting the work list.\n");
            exit(1);
        }
        flush_bio = 1;
    }
    pthread_mutex_unlock(&lock);

    return NULL;
}

int main(void)
{
    pthread_t comp, req;

    printf("=== md_flush race simulation ===\n");
    pthread_create(&req, NULL, requester_thread, NULL);
    pthread_create(&comp, NULL, completer_thread, NULL);

    pthread_join(comp, NULL);
    pthread_join(req, NULL);

    /* 正常情况下不应该运行到这里 */
    printf("Test finished without WARN_ON (unexpected)\n");
    return 0;
}