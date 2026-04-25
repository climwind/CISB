/*
 * 漏洞用例：asm-generic/unaligned 旧版 access_ok.h 风格的非对齐访问
 * 
 * 旧实现直接对非对齐指针进行强转解引用，这违反了 C 标准，
 * 属于未定义行为。当存在重叠的非对齐写入时，编译器可能基于
 * “无未定义行为”假设进行错误优化，造成数据损坏。
 *
 * 触发条件：编译时开启优化（如 -O2），非对齐重叠写入。
 * 编译：gcc -O2 -Wall -o unaligned_bug unaligned_bug.c
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ---------- 漏洞版本：模拟 access_ok.h ---------- */
static inline uint32_t get_unaligned_le32_bug(const void *p)
{
    /* 直接强转，未对齐 + 严格别名违规 */
    return *(const uint32_t *)p;
}

static inline void put_unaligned_le32_bug(uint32_t val, void *p)
{
    /* 直接强转写入 */
    *(uint32_t *)p = val;
}

/* ---------- 正确版本：le_struct.h 逐字节方式 ---------- */
static inline uint32_t get_unaligned_le32_ok(const void *p)
{
    const uint8_t *b = (const uint8_t *)p;
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static inline void put_unaligned_le32_ok(uint32_t val, void *p)
{
    uint8_t *b = (uint8_t *)p;
    b[0] = val & 0xff;
    b[1] = (val >> 8) & 0xff;
    b[2] = (val >> 16) & 0xff;
    b[3] = (val >> 24) & 0xff;
}

int main(void)
{
    /* 分配一个 8 字节缓冲区，用于重叠写入 */
    uint8_t buf_bug[8] = {0};
    uint8_t buf_ok[8]  = {0};

    /* 模拟两个重叠的非对齐写入：
     * 1. 在偏移 0 写入值 0x11223344
     * 2. 在偏移 2 写入值 0xAABBCCDD
     * 最终预期结果：偏移 0..1 保留第一次写入的 0x44,0x33，
     * 偏移 2..5 覆盖为第二次的 0xDD,0xCC,0xBB,0xAA
     * 读取偏移 0 处的 uint32_t，期望值为 0xAABB3344（小端解释）。
     */

    /* 漏洞版本操作 */
    put_unaligned_le32_bug(0x11223344, &buf_bug[0]);
    put_unaligned_le32_bug(0xAABBCCDD, &buf_bug[2]);

    /* 正确版本操作 */
    put_unaligned_le32_ok(0x11223344, &buf_ok[0]);
    put_unaligned_le32_ok(0xAABBCCDD, &buf_ok[2]);

    /* 读取结果 */
    uint32_t result_bug = get_unaligned_le32_bug(&buf_bug[0]);
    uint32_t result_ok  = get_unaligned_le32_ok(&buf_ok[0]);

    printf("Expected (byte-wise) : 0x%08X\n", result_ok);
    printf("Buggy   (direct ptr): 0x%08X\n", result_bug);

    if (result_bug != result_ok) {
        printf("\n** Bug triggered: data corruption due to undefined behavior!\n");
    } else {
        printf("\nResults match (may need higher optimization or a different compiler).\n");
    }

    return 0;
}