#include <zygisk.hpp>
#include <dlfcn.h>
#include <cstring>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <vector>

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

// ⚠️ 改成你要伪装的游戏包名
static const char *TARGET_PACKAGES[] = {
 "com.tencent.tmgp.dfm",
"com.tencent.tmgp.sgame",
    "com.pubg.imobile",
};
static constexpr int TARGET_COUNT = 2;

// 麒麟 9000S 的 /proc/cpuinfo
static const char FAKE_CPUINFO[] =
    "Processor\t: AArch64 Processor rev 0 (aarch64)\n"
    "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp\n"
    "CPU implementer\t: 0x48\n"
    "CPU architecture: 8\n"
    "CPU variant\t: 0x1\n"
    "CPU part\t: 0xd0c\n"
    "CPU revision\t: 0\n\n"
    "processor\t: 0\n"
    "BogoMIPS\t: 26.00\n"
    "CPU implementer\t: 0x48\n"
    "CPU architecture: 8\n"
    "CPU variant\t: 0x1\n"
    "CPU part\t: 0xd0c\n"
    "CPU revision\t: 0\n\n"
    "processor\t: 1\n"
    "BogoMIPS\t: 26.00\n"
    "CPU implementer\t: 0x48\n"
    "CPU architecture: 8\n"
    "CPU variant\t: 0x2\n"
    "CPU part\t: 0xd0a\n"
    "CPU revision\t: 0\n\n"
    "processor\t: 2\n"
    "BogoMIPS\t: 26.00\n"
    "CPU implementer\t: 0x48\n"
    "CPU architecture: 8\n"
    "CPU variant\t: 0x2\n"
    "CPU part\t: 0xd0a\n"
    "CPU revision\t: 0\n\n"
    "processor\t: 3\n"
    "BogoMIPS\t: 26.00\n"
    "CPU implementer\t: 0x48\n"
    "CPU architecture: 8\n"
    "CPU variant\t: 0x2\n"
    "CPU part\t: 0xd0a\n"
    "CPU revision\t: 0\n\n"
    "processor\t: 4\n"
    "BogoMIPS\t: 26.00\n"
    "CPU implementer\t: 0x48\n"
    "CPU architecture: 8\n"
    "CPU variant\t: 0x3\n"
    "CPU part\t: 0xd0b\n"
    "CPU revision\t: 0\n\n"
    "processor\t: 5\n"
    "BogoMIPS\t: 26.00\n"
    "CPU implementer\t: 0x48\n"
    "CPU architecture: 8\n"
    "CPU variant\t: 0x3\n"
    "CPU part\t: 0xd0b\n"
    "CPU revision\t: 0\n\n"
    "processor\t: 6\n"
    "BogoMIPS\t: 26.00\n"
    "CPU implementer\t: 0x48\n"
    "CPU architecture: 8\n"
    "CPU variant\t: 0x3\n"
    "CPU part\t: 0xd0b\n"
    "CPU revision\t: 0\n\n"
    "processor\t: 7\n"
    "BogoMIPS\t: 26.00\n"
    "CPU implementer\t: 0x48\n"
    "CPU architecture: 8\n"
    "CPU variant\t: 0x3\n"
    "CPU part\t: 0xd0b\n"
    "CPU revision\t: 0\n\n"
    "Hardware\t: HiSilicon Kirin 9000S\n";

// 需要替换为麒麟 9000S 真实值
static constexpr unsigned long FAKE_HWCAP  = 0x7efefeff;
static constexpr unsigned long FAKE_HWCAP2 = 0x0000001f;

static constexpr int FAKE_CPUINFO_FD = 1000;
static constexpr int FAKE_MIDR_FD = 2000;

static decltype(open)  *orig_open  = nullptr;
static decltype(read)  *orig_read  = nullptr;
static decltype(close) *orig_close = nullptr;
static decltype(getauxval) *orig_getauxval = nullptr;

int fake_open(const char *path, int flags, ...) {
    if (path) {
        if (strcmp(path, "/proc/cpuinfo") == 0) return FAKE_CPUINFO_FD;
        if (strstr(path, "midr_el1")) return FAKE_MIDR_FD;
    }
    return orig_open(path, flags);
}

ssize_t fake_read(int fd, void *buf, size_t count) {
    if (fd == FAKE_CPUINFO_FD) {
        static size_t offset = 0;
        size_t len = sizeof(FAKE_CPUINFO) - 1;
        if (offset >= len) { offset = 0; return 0; }
        size_t copy = (count > (len - offset)) ? (len - offset) : count;
        memcpy(buf, FAKE_CPUINFO + offset, copy);
        offset += copy;
        return copy;
    }
    if (fd == FAKE_MIDR_FD) {
        const char *midr_str = "0x4800d0c0\n";
        static size_t m_off = 0;
        size_t len = strlen(midr_str);
        if (m_off >= len) { m_off = 0; return 0; }
        size_t copy = (count > (len - m_off)) ? (len - m_off) : count;
        memcpy(buf, midr_str + m_off, copy);
        m_off += copy;
        return copy;
    }
    return orig_read(fd, buf, count);
}

int fake_close(int fd) {
    if (fd == FAKE_CPUINFO_FD || fd == FAKE_MIDR_FD) return 0;
    return orig_close(fd);
}

unsigned long fake_getauxval(unsigned long type) {
    if (type == 16) return FAKE_HWCAP;
    if (type == 26) return FAKE_HWCAP2;
    return orig_getauxval(type);
}

class CpuSpoofModule : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override { this->api = api; }
    void preAppSpecialize(AppSpecializeArgs *args) override {
        const char *proc = api->getProcessName();
        bool enable = false;
        for (int i = 0; i < TARGET_COUNT; ++i) {
            if (strcmp(proc, TARGET_PACKAGES[i]) == 0) { enable = true; break; }
        }
        if (!enable) return;
        api->pltHookRegister(".*libc\\.so$", "open",  (void*)fake_open,  (void**)&orig_open);
        api->pltHookRegister(".*libc\\.so$", "read",  (void*)fake_read,  (void**)&orig_read);
        api->pltHookRegister(".*libc\\.so$", "close", (void*)fake_close, (void**)&orig_close);
        api->pltHookRegister(".*libc\\.so$", "getauxval", (void*)fake_getauxval, (void**)&orig_getauxval);
    }
private:
    Api *api;
};

REGISTER_ZYGISK_MODULE(CpuSpoofModule)
