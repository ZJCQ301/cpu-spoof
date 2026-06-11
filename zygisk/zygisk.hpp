#pragma once
#include <jni.h>
#include <functional>
#include <string>
#include <vector>

namespace zygisk {

struct AppSpecializeArgs {
    jint &uid;
    jint &gid;
    jintArray &gids;
    jint &runtime_flags;
    jobjectArray &rlimits;
    jint &mount_external;
    jstring &se_info;
    jstring &nice_name;
    jstring &app_data_dir;
    jstring &instruction_set;
};

struct ServerSpecializeArgs {
    jint &uid;
    jint &gid;
    jintArray &gids;
};

class Api;

class ModuleBase {
public:
    virtual void onLoad(Api *api, JNIEnv *env) {}
    virtual void preAppSpecialize(AppSpecializeArgs *args) {}
    virtual void postAppSpecialize(AppSpecializeArgs *args) {}
    virtual void preServerSpecialize(ServerSpecializeArgs *args) {}
    virtual void postServerSpecialize(ServerSpecializeArgs *args) {}
    virtual ~ModuleBase() {}
};

class Api {
public:
    virtual void pltHookRegister(const char *soname, const char *symbol,
                                 void *new_func, void **old_func) = 0;
    virtual const char *getProcessName() = 0;
    virtual ~Api() {}
};

} // namespace zygisk

#define REGISTER_ZYGISK_MODULE(className) \
    extern "C" __attribute__((visibility("default"))) zygisk::ModuleBase* zygisk_module_entry() { \
        return new className(); \
}
