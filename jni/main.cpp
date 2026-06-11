#include <zygisk.hpp>
#include <dlfcn.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <map>
#include <string>
#include <atomic>
#include <android/log.h>

#define LOG_TAG "cpu_spoof"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

using zygisk::Api;
using zygisk::AppSpecializeArgs;

// 目标包名
static const char *TARGET_PACKAGES[] = {
    "com.tencent.tmgp.dfm",
    "com.liuzh.deviceinfo",
    "com.lingqing.trustattestor"
};
static constexpr int TARGET_COUNT = sizeof(TARGET_PACKAGES) / sizeof(TARGET_PACKAGES[0]);

// 麒麟 9000S /proc/cpuinfo
static const char FAKE_CPUINFO[] =
    "processor\t: 0\n"
    "BogoMIPS\t: 26.00\n"
    "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp\n"
    "CPU implementer\t: 0x48\n"
    "CPU architecture: 8\n"
    "CPU variant\t: 0x1\n"
    "CPU part\t: 0xd0c\n"
    "CPU revision\t: 0\n\n"
    "processor\t: 1\n"
    "BogoMIPS\t: 26.00\n"
    "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp\n"
    "CPU implementer\t: 0x48\n"
    "CPU architecture: 8\n"
    "CPU variant\t: 0x2\n"
    "CPU part\t: 0xd0a\n"
    "CPU revision\t: 0\n\n"
    "processor\t: 2\n"
    "BogoMIPS\t: 26.00\n"
    "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp\n"
    "CPU implementer\t: 0x48\n"
    "CPU architecture: 8\n"
    "CPU variant\t: 0x2\n"
    "CPU part\t: 0xd0a\n"
    "CPU revision\t: 0\n\n"
    "processor\t: 3\n"
    "BogoMIPS\t: 26.00\n"
    "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp\n"
    "CPU implementer\t: 0x48\n"
    "CPU architecture: 8\n"
    "CPU variant\t: 0x2\n"
    "CPU part\t: 0xd0a\n"
    "CPU revision\t: 0\n\n"
    "processor\t: 4\n"
    "BogoMIPS\t: 26.00\n"
    "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp\n"
    "CPU implementer\t: 0x48\n"
    "CPU architecture: 8\n"
    "CPU variant\t: 0x3\n"
    "CPU part\t: 0xd0b\n"
    "CPU revision\t: 0\n\n"
    "processor\t: 5\n"
    "BogoMIPS\t: 26.00\n"
    "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp\n"
    "CPU implementer\t: 0x48\n"
    "CPU architecture: 8\n"
    "CPU variant\t: 0x3\n"
    "CPU part\t: 0xd0b\n"
    "CPU revision\t: 0\n\n"
    "processor\t: 6\n"
    "BogoMIPS\t: 26.00\n"
    "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp\n"
    "CPU implementer\t: 0x48\n"
    "CPU architecture: 8\n"
    "CPU variant\t: 0x3\n"
    "CPU part\t: 0xd0b\n"
    "CPU revision\t: 0\n\n"
    "processor\t: 7\n"
    "BogoMIPS\t: 26.00\n"
    "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp\n"
    "CPU implementer\t: 0x48\n"
    "CPU architecture: 8\n"
    "CPU variant\t: 0x3\n"
    "CPU part\t: 0xd0b\n"
    "CPU revision\t: 0\n\n"
    "Hardware\t: HiSilicon Kirin 9000S\n";

static const char FAKE_MIDR[] = "0x480fd0c0\n";
static constexpr unsigned long FAKE_HWCAP  = 0x7efefeff;
static constexpr unsigned long FAKE_HWCAP2 = 0x0000001f;

// 伪文件描述符池
static std::atomic<int> g_next_fd{9000};
static std::map<int, struct FakeFile*> g_files;
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

struct FakeFile {
    const char *data;
    size_t size;
    size_t off;
};

static int new_fd() { return g_next_fd.fetch_add(1); }

static void add_file(int fd, const char *d, size_t s) {
    pthread_mutex_lock(&g_mutex);
    g_files[fd] = new FakeFile{d, s, 0};
    pthread_mutex_unlock(&g_mutex);
}

static FakeFile* get_file(int fd) {
    pthread_mutex_lock(&g_mutex);
    auto it = g_files.find(fd);
    auto *r = (it != g_files.end()) ? it->second : nullptr;
    pthread_mutex_unlock(&g_mutex);
    return r;
}

static void del_file(int fd) {
    pthread_mutex_lock(&g_mutex);
    auto it = g_files.find(fd);
    if (it != g_files.end()) { delete it->second; g_files.erase(it); }
    pthread_mutex_unlock(&g_mutex);
}

// 路径判断
static bool is_cpuinfo(const char *p) { return p && strstr(p, "/proc/cpuinfo"); }
static bool is_midr(const char *p)   { return p && strstr(p, "midr_el1"); }

// 原函数指针
static int  (*real_open)(const char*, int, ...) = nullptr;
static int  (*real_openat)(int, const char*, int, ...) = nullptr;
static ssize_t (*real_read)(int, void*, size_t) = nullptr;
static int  (*real_close)(int) = nullptr;
static unsigned long (*real_getauxval)(unsigned long) = nullptr;
static int  (*real_prop_get)(const char*, char*) = nullptr;
static FILE* (*real_fopen)(const char*, const char*) = nullptr;
static char* (*real_fgets)(char*, int, FILE*) = nullptr;
static int  (*real_fclose)(FILE*) = nullptr;

// ============================================================
// Hook 实现
// ============================================================
static int fake_open(const char *path, int flags, ...) {
    if (is_cpuinfo(path)) {
        int fd = new_fd();
        add_file(fd, FAKE_CPUINFO, sizeof(FAKE_CPUINFO)-1);
        LOGD("open -> cpuinfo fd=%d", fd);
        return fd;
    }
    if (is_midr(path)) {
        int fd = new_fd();
        add_file(fd, FAKE_MIDR, sizeof(FAKE_MIDR)-1);
        return fd;
    }
    // 设备型号 sysfs
    if (strstr(path, "product_name") || strstr(path, "product_model")) {
        int fd = new_fd();
        static const char model[] = "ALN-AL80\n";
        add_file(fd, model, sizeof(model)-1);
        return fd;
    }
    if (strstr(path, "product_manufacturer")) {
        int fd = new_fd();
        static const char mfr[] = "HUAWEI\n";
        add_file(fd, mfr, sizeof(mfr)-1);
        return fd;
    }
    // 覆盖 soc0 和 firmware
    if (strstr(path, "/sys/devices/soc0") || strstr(path, "/sys/firmware/devicetree")) {
        int fd = new_fd();
        static const char e[] = "\n";
        add_file(fd, e, 1);
        return fd;
    }
    return real_open ? real_open(path, flags) : -1;
}

static int fake_openat(int dirfd, const char *path, int flags, ...) {
    return fake_open(path, flags);
}

static ssize_t fake_read(int fd, void *buf, size_t count) {
    FakeFile *f = get_file(fd);
    if (f) {
        size_t r = f->size - f->off;
        if (r == 0) return 0;
        size_t c = (count > r) ? r : count;
        memcpy(buf, f->data + f->off, c);
        f->off += c;
        return c;
    }
    return real_read ? real_read(fd, buf, count) : -1;
}

static int fake_close(int fd) {
    del_file(fd);
    return real_close ? real_close(fd) : -1;
}

static FILE* fake_fopen(const char *filename, const char *mode) {
    if (is_cpuinfo(filename) || is_midr(filename) ||
        strstr(filename, "product_name") || strstr(filename, "product_model") ||
        strstr(filename, "product_manufacturer")) {
        int fd = fake_open(filename, O_RDONLY);
        if (fd > 0) return fdopen(fd, mode);
    }
    return real_fopen ? real_fopen(filename, mode) : nullptr;
}

static char* fake_fgets(char *buf, int n, FILE *fp) {
    if (!fp) return nullptr;
    FakeFile *f = get_file(fileno(fp));
    if (f) {
        if (f->off >= f->size) return nullptr;
        int i = 0;
        while (i < n-1 && f->off < f->size) {
            buf[i] = f->data[f->off++];
            if (buf[i++] == '\n') break;
        }
        buf[i] = 0;
        return buf;
    }
    return real_fgets ? real_fgets(buf, n, fp) : nullptr;
}

static unsigned long fake_getauxval(unsigned long type) {
    if (type == 16) return FAKE_HWCAP;
    if (type == 26) return FAKE_HWCAP2;
    return real_getauxval ? real_getauxval(type) : 0;
}

static int fake_prop_get(const char *name, char *value) {
    LOGD("prop_get: %s", name);
    if (strstr(name, "ro.board.platform") || strstr(name, "ro.hardware") ||
        strstr(name, "ro.soc.model") || strstr(name, "ro.chipname")) {
        strcpy(value, "kirin9000s");
        return strlen(value);
    }
    if (strstr(name, "ro.mediatek.platform")) {
        value[0] = 0;
        return 0;
    }
    if (strstr(name, "ro.product.model")) {
        strcpy(value, "ALN-AL80");
        return strlen(value);
    }
    if (strstr(name, "ro.product.manufacturer") || strstr(name, "ro.product.brand")) {
        strcpy(value, "HUAWEI");
        return strlen(value);
    }
    if (strstr(name, "ro.product.device")) {
        strcpy(value, "HWALN");
        return strlen(value);
    }
    if (strstr(name, "ro.build.fingerprint")) {
        strcpy(value, "HUAWEI/ALN-AL80/HWALN:12/HUAWEIALN-AL80/103.0.0.165:user/release-keys");
        return strlen(value);
    }
    if (strstr(name, "ro.build.display.id") || strstr(name, "ro.build.version.incremental")) {
        strcpy(value, "ALN-AL80 4.0.0.165(C00E165R8P4)");
        return strlen(value);
    }
    if (strstr(name, "ro.build.description")) {
        strcpy(value, "ALN-AL80-user 12 HUAWEIALN-AL80 103.0.0.165 release-keys");
        return strlen(value);
    }
    return real_prop_get ? real_prop_get(name, value) : 0;
}

// ============================================================
// Zygisk 模块
// ============================================================
class CpuSpoofModule : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api = api;
        void *libc = dlopen("libc.so", RTLD_NOW);
        if (libc) {
            real_open      = (decltype(real_open))dlsym(libc, "open");
            real_openat    = (decltype(real_openat))dlsym(libc, "openat");
            real_read      = (decltype(real_read))dlsym(libc, "read");
            real_close     = (decltype(real_close))dlsym(libc, "close");
            real_getauxval = (decltype(real_getauxval))dlsym(libc, "getauxval");
            real_prop_get  = (decltype(real_prop_get))dlsym(libc, "__system_property_get");
            real_fopen     = (decltype(real_fopen))dlsym(libc, "fopen");
            real_fgets     = (decltype(real_fgets))dlsym(libc, "fgets");
            real_fclose    = (decltype(real_fclose))dlsym(libc, "fclose");
            dlclose(libc);
        }
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        const char *proc = api->getProcessName();
        bool ok = false;
        for (int i = 0; i < TARGET_COUNT; ++i) {
            if (strstr(proc, TARGET_PACKAGES[i]) == proc) {
                ok = true;
                break;
            }
        }
        if (!ok) return;

        LOGD("Injected into process: %s", proc);

        const char *r = ".*libc\\.so$";
        api->pltHookRegister(r, "open",     (void*)fake_open,     (void**)&real_open);
        api->pltHookRegister(r, "openat",   (void*)fake_openat,   (void**)&real_openat);
        api->pltHookRegister(r, "read",     (void*)fake_read,     (void**)&real_read);
        api->pltHookRegister(r, "close",    (void*)fake_close,    (void**)&real_close);
        api->pltHookRegister(r, "fopen",    (void*)fake_fopen,    (void**)&real_fopen);
        api->pltHookRegister(r, "fgets",    (void*)fake_fgets,    (void**)&real_fgets);
        api->pltHookRegister(r, "getauxval",(void*)fake_getauxval,(void**)&real_getauxval);
        api->pltHookRegister(r, "__system_property_get", (void*)fake_prop_get, (void**)&real_prop_get);

        LOGD("All hooks installed for %s", proc);
    }

private:
    Api *api;
};

REGISTER_ZYGISK_MODULE(CpuSpoofModule)
