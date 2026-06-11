#include <zygisk.hpp>
#include <dlfcn.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <map>
#include <string>
#include <atomic>
#include <ctime>
#include <csignal>

using zygisk::Api;
using zygisk::AppSpecializeArgs;

// ============================================================
// 目标游戏包名（改这里！）
// ============================================================
static const char *TARGET_PACKAGES[] = {
    "com.tencent.tmgp.sgame",
    "com.pubg.imobile",
    "com.tencent.tmgp.dfm",
};
static constexpr int TARGET_COUNT = 3;

// ============================================================
// 麒麟 9000S 数据
// ============================================================
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

static const char FAKE_MIDR[] = "0x480fd0c0\n";
static constexpr unsigned long FAKE_HWCAP  = 0x7efefeff;
static constexpr unsigned long FAKE_HWCAP2 = 0x0000001f;

// ============================================================
// 伪文件系统
// ============================================================
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

// ============================================================
// 原函数
// ============================================================
static int  (*real_open)(const char*, int, ...) = nullptr;
static int  (*real_openat)(int, const char*, int, ...) = nullptr;
static ssize_t (*real_read)(int, void*, size_t) = nullptr;
static int  (*real_close)(int) = nullptr;
static unsigned long (*real_getauxval)(unsigned long) = nullptr;
static int  (*real_prop_get)(const char*, char*) = nullptr;
static FILE* (*real_fopen)(const char*, const char*) = nullptr;
static char* (*real_fgets)(char*, int, FILE*) = nullptr;

// ============================================================
// 路径判断
// ============================================================
static bool is_cpuinfo(const char *p) { return p && strstr(p, "/proc/cpuinfo"); }
static bool is_midr(const char *p)   { return p && strstr(p, "midr_el1"); }
static bool is_cpu_sysfs(const char *p) { return p && (strstr(p, "/sys/devices/system/cpu") || strstr(p, "/sys/devices/soc0")); }

// ============================================================
// seccomp 拦截结果
// ============================================================
static long do_openat(int dirfd, const char *path, int flags, mode_t mode) {
    if (is_cpuinfo(path)) { int fd = new_fd(); add_file(fd, FAKE_CPUINFO, sizeof(FAKE_CPUINFO)-1); return fd; }
    if (is_midr(path))   { int fd = new_fd(); add_file(fd, FAKE_MIDR, sizeof(FAKE_MIDR)-1); return fd; }
    if (is_cpu_sysfs(path)) { int fd = new_fd(); static const char e[] = "\n"; add_file(fd, e, 1); return fd; }
    return syscall(__NR_openat, dirfd, path, flags, mode);
}

static ssize_t do_read(int fd, void *buf, size_t count) {
    FakeFile *f = get_file(fd);
    if (f) {
        struct timespec ts = {0, (long)(rand() % 30) * 1000};
        nanosleep(&ts, nullptr);
        size_t r = f->size - f->off;
        if (r == 0) return 0;
        size_t c = (count > r) ? r : count;
        memcpy(buf, f->data + f->off, c);
        f->off += c;
        return c;
    }
    return syscall(__NR_read, fd, buf, count);
}

static int do_close(int fd) {
    del_file(fd);
    return syscall(__NR_close, fd);
}

// ============================================================
// seccomp-bpf 过滤器
// ============================================================
static void install_seccomp() {
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_read, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_close, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog p = {sizeof(f)/sizeof(f[0]), f};
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &p);
}

// ARM64 寄存器访问宏
#define ARM64_REG(uc, idx) ((unsigned long*)(&(uc)->uc_mcontext))[idx]

static void sigsys_hdl(int, siginfo_t*, void *ctx) {
    ucontext_t *u = (ucontext_t*)ctx;
    unsigned long *regs = (unsigned long*)&u->uc_mcontext;
    long nr = regs[8];
    long ret = -1;
    if (nr == __NR_openat) {
        ret = do_openat(regs[0], (const char*)regs[1], (int)regs[2], (mode_t)regs[3]);
    } else if (nr == __NR_read) {
        ret = do_read(regs[0], (void*)regs[1], regs[2]);
    } else if (nr == __NR_close) {
        ret = do_close(regs[0]);
    }
    regs[0] = ret;
}

// ============================================================
// libc 层 Hook（备用）
// ============================================================
static int fake_open(const char *p, int f, ...) { return do_openat(AT_FDCWD, p, f, 0); }
static int fake_openat(int d, const char *p, int f, ...) { return do_openat(d, p, f, 0); }
static ssize_t fake_read(int fd, void *b, size_t c) { return do_read(fd, b, c); }
static int fake_close(int fd) { del_file(fd); return real_close ? real_close(fd) : -1; }

static unsigned long fake_getauxval(unsigned long t) {
    if (t == 16) return FAKE_HWCAP;
    if (t == 26) return FAKE_HWCAP2;
    return real_getauxval ? real_getauxval(t) : 0;
}

static int fake_prop_get(const char *n, char *v) {
    if (strstr(n, "ro.board.platform") || strstr(n, "ro.hardware") ||
        strstr(n, "ro.soc.model") || strstr(n, "ro.chipname")) {
        strcpy(v, "kirin9000s"); return strlen(v);
    }
    if (strstr(n, "ro.mediatek.platform")) { v[0]=0; return 0; }
    return real_prop_get ? real_prop_get(n, v) : 0;
}

static FILE* fake_fopen(const char *fn, const char *m) {
    if (is_cpuinfo(fn) || is_midr(fn)) {
        int fd = do_openat(AT_FDCWD, fn, O_RDONLY, 0);
        if (fd > 0) return fdopen(fd, m);
    }
    return real_fopen ? real_fopen(fn, m) : nullptr;
}

static char* fake_fgets(char *b, int n, FILE *fp) {
    if (!fp) return nullptr;
    FakeFile *f = get_file(fileno(fp));
    if (f) {
        if (f->off >= f->size) return nullptr;
        int i = 0;
        while (i < n-1 && f->off < f->size) {
            b[i] = f->data[f->off++];
            if (b[i++] == '\n') break;
        }
        b[i] = 0;
        return b;
    }
    return real_fgets ? real_fgets(b, n, fp) : nullptr;
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
            real_open   = (decltype(real_open))dlsym(libc, "open");
            real_openat = (decltype(real_openat))dlsym(libc, "openat");
            real_read   = (decltype(real_read))dlsym(libc, "read");
            real_close  = (decltype(real_close))dlsym(libc, "close");
            real_getauxval = (decltype(real_getauxval))dlsym(libc, "getauxval");
            real_prop_get  = (decltype(real_prop_get))dlsym(libc, "__system_property_get");
            real_fopen  = (decltype(real_fopen))dlsym(libc, "fopen");
            real_fgets  = (decltype(real_fgets))dlsym(libc, "fgets");
            dlclose(libc);
        }
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        const char *proc = api->getProcessName();
        bool ok = false;
        for (int i = 0; i < TARGET_COUNT; ++i)
            if (strcmp(proc, TARGET_PACKAGES[i]) == 0) { ok = true; break; }
        if (!ok) return;

        install_seccomp();
        struct sigaction sa{};
        sa.sa_sigaction = sigsys_hdl;
        sa.sa_flags = SA_SIGINFO | SA_NODEFER;
        sigaction(SIGSYS, &sa, nullptr);

        const char *r = ".*libc\\.so$";
        api->pltHookRegister(r, "open",  (void*)fake_open,  (void**)&real_open);
        api->pltHookRegister(r, "openat", (void*)fake_openat, (void**)&real_openat);
        api->pltHookRegister(r, "read",  (void*)fake_read,  (void**)&real_read);
        api->pltHookRegister(r, "close", (void*)fake_close, (void**)&real_close);
        api->pltHookRegister(r, "getauxval", (void*)fake_getauxval, (void**)&real_getauxval);
        api->pltHookRegister(r, "__system_property_get", (void*)fake_prop_get, (void**)&real_prop_get);
        api->pltHookRegister(r, "fopen", (void*)fake_fopen, (void**)&real_fopen);
        api->pltHookRegister(r, "fgets", (void*)fake_fgets, (void**)&real_fgets);
    }

private:
    Api *api;
};

REGISTER_ZYGISK_MODULE(CpuSpoofModule)
