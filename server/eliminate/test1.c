/*
 * 漏洞用例：缺少 READ_ONCE() 保护位字段读导致 TOCTOU
 *
 * 对应 commit 20b50d79974e ("net: ipv4: emulate READ_ONCE() on ->hdrincl
 * bit-field in raw_sendmsg()")。
 * 原始代码：
 *   hdrincl = inet->hdrincl;
 *   ... 使用 hdrincl ...
 * 编译器可能将后续对 hdrincl 的引用直接替换为 inet->hdrincl，
 * 若此时其他 CPU 修改了该位字段，则前后判断不一致。
 *
 * 编译：gcc -O2 -pthread -o hdrincl_race hdrincl_race.c
 * 运行：./hdrincl_race
 */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

struct inet_sock {
    unsigned int hdrincl : 1;
    int dummy;               /* 模拟其他成员，增加寄存器压力 */
};

static struct inet_sock inet = {0, 0};
static volatile int keep_running = 1;

/* 写线程：不断翻转位字段 */
static void *writer(void *arg)
{
    while (keep_running) {
        inet.hdrincl = !inet.hdrincl;
        usleep(1);           /* 给读线程留出窗口 */
    }
    return NULL;
}

/* 读线程：模拟漏洞代码 */
static void *reader(void *arg)
{
    while (keep_running) {
        /* 将位字段读入局部变量，期望后续稳定使用 */
        unsigned int hdrincl = inet.hdrincl;

        int first = hdrincl ? 1 : 0;

        /* 中间代码可能触发编译器重新从内存加载全局变量 */
        usleep(1);           /* 调用外部函数，编译器可能保守重读 */

        /*
         * 第二次使用局部变量 hdrincl，
         * 但编译器可能优化为直接读取 inet.hdrincl。
         */
        int second = hdrincl ? 1 : 0;

        if (first != second) {
            printf("BUG: TOCTOU detected! first=%d second=%d\n"
                   "Compiler likely reloaded inet.hdrincl instead of "
                   "using the local copy.\n",
                   first, second);
            keep_running = 0;
            return NULL;
        }
    }
    return NULL;
}

int main(void)
{
    pthread_t wrt, rdt;
    pthread_create(&wrt, NULL, writer, NULL);
    pthread_create(&rdt, NULL, reader, NULL);

    sleep(2);               /* 运行 2 秒 */
    keep_running = 0;
    pthread_join(wrt, NULL);
    pthread_join(rdt, NULL);

    printf("Test finished.\n");
    return 0;
}