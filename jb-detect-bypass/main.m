#import <Foundation/Foundation.h>
#import <spawn.h>
#import <dlfcn.h>
#import <rootless.h>
#import "logging.h"

// Executable name of the app to enable tweak injection for
#define TARGET_APP_EXECUTABLE_NAME ""

// This can be any tweak loader that provides MSHookFunction
#define HOOKING_LIBRARY_DYLIB_PATH ROOT_PATH("/usr/lib/libellekit.dylib")

static void *orig_posix_spawn;
static void *orig_posix_spawnp;

static void reverse_string(char *str) {
    if (str == NULL) {
        return;
    }

    unsigned long i = 0;
    unsigned long j = strlen(str) - 1;
    while (i < j) {
        char temp = str[i];
        str[i] = str[j];
        str[j] = temp;
        i++;
        j--;
    }
}

static int posix_spawn_launchd(pid_t * __restrict pid, const char * __restrict path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t * __restrict attrp, char *const __argv[__restrict], char *const __envp[__restrict], void *original_function) {

    char **new_envp = NULL;
    if (path && __envp && strstr(path, "/sbin/launchd") == NULL && strstr(path, TARGET_APP_EXECUTABLE_NAME) != NULL) {

        size_t envp_size = 0;
        while (__envp[envp_size] != NULL) {
            envp_size++;
        }

        new_envp = calloc(envp_size + 2, sizeof(char *));
        if (new_envp == NULL) {
            serial_println("Failed to allocate new environment variables");
            return -1;
        }

        // Names of tweakloaders to exclude from the process' environment variables (case-insensitive).
        // The intent is to cover all of them. Expand as needed
        const char *tweakloaders_to_exclude[] = {
            "ellekit",
            "hook",
            "inject",
            "substitute"
            "substrate",
            "loader",
        };
        uint32_t num_tweakloaders = sizeof(tweakloaders_to_exclude) / sizeof(tweakloaders_to_exclude[0]);

        char *dyld_insert_libraries = NULL;
        char *reversed_libraries = NULL;
        size_t j = 0;

        for (size_t i = 0; i < envp_size; i++) {
            const char *current_env = __envp[i];
            if (current_env == NULL || strlen(current_env) == 0) {
                continue;
            }

            if (strncmp(current_env, "DYLD_INSERT_LIBRARIES=", 22) == 0) {
                char *libraries = strdup(current_env + 22);
                char *token = strtok(libraries, ":");
                char *allowed_libraries = NULL;
                char *excluded_libraries = NULL;

                while (token != NULL) {
                    int should_exclude = 0;
                    for (uint32_t k = 0; k < num_tweakloaders; k++) {
                        if (strcasestr(token, tweakloaders_to_exclude[k]) != NULL) {
                            should_exclude = 1;
                            break;
                        }
                    }

                    if (should_exclude) {
                        serial_println("Excluding library: %s", token);
                        if (excluded_libraries) {
                            asprintf(&excluded_libraries, "%s:%s", excluded_libraries, token);
                        }
                        else {
                            excluded_libraries = strdup(token);
                        }
                    }
                    else {
                        if (allowed_libraries) {
                            asprintf(&allowed_libraries, "%s:%s", allowed_libraries, token);
                        }
                        else {
                            allowed_libraries = strdup(token);
                        }
                    }

                    token = strtok(NULL, ":");
                }

                if (allowed_libraries) {
                    asprintf(&dyld_insert_libraries, "DYLD_INSERT_LIBRARIES=%s", allowed_libraries);
                    new_envp[j++] = dyld_insert_libraries;
                }

                if (excluded_libraries) {
                    reverse_string(excluded_libraries);
                    asprintf(&reversed_libraries, "SEIRARBIL_TRESNI_DLYD=%s", excluded_libraries);
                    new_envp[j++] = reversed_libraries;
                }

                free(libraries);
                free(allowed_libraries);
                free(excluded_libraries);
            }
            else {
                new_envp[j++] = strdup(current_env);
            }
        }

        new_envp[j] = NULL;
    }

    int result = ((int (*)(pid_t * __restrict, const char * __restrict, const posix_spawn_file_actions_t *, const posix_spawnattr_t * __restrict, char *const __argv[__restrict], char *const __envp[__restrict]))original_function)(pid, path, file_actions, attrp, __argv, new_envp ? new_envp : __envp);

    if (new_envp) {
        for (size_t i = 0; new_envp[i] != NULL; i++) {
            free(new_envp[i]);
        }
        free(new_envp);
    }

    return result;
}

static int posix_spawn_hook(pid_t * __restrict pid, const char * __restrict path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t * __restrict attrp, char *const __argv[__restrict], char *const __envp[__restrict]) {
    return posix_spawn_launchd(pid, path, file_actions, attrp, __argv, __envp, orig_posix_spawn);
}

static int posix_spawnp_hook(pid_t * __restrict pid, const char * __restrict path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t * __restrict attrp, char *const __argv[__restrict], char *const __envp[__restrict]) {
    return posix_spawn_launchd(pid, path, file_actions, attrp, __argv, __envp, orig_posix_spawnp);
}


static void init_launchd_hooks(void) {
    serial_println("Injected into launchd");

    // A tweakloader should already be in the process. If not, try to load a hooking library
    void *global_handle = dlopen(NULL, RTLD_LAZY);
    void *_MSHookFunction = dlsym(global_handle, "MSHookFunction");
    if (_MSHookFunction == NULL) {
        serial_println("dlopening hooking library: %s", HOOKING_LIBRARY_DYLIB_PATH);
        void *handle = dlopen(HOOKING_LIBRARY_DYLIB_PATH, 0);
        if (handle == NULL) {
            serial_println("Failed to load hooking library: %s. %s", HOOKING_LIBRARY_DYLIB_PATH, dlerror());
            return;
        }

        _MSHookFunction = dlsym(handle, "MSHookFunction");
    }

    if (_MSHookFunction == NULL) {
        serial_println("Failed to find MSHookFunction. Cannot proceed");
        return;
    }
    serial_println("Using MSHookFunction at %p", _MSHookFunction);

    ((void (*)(void *, void *, void **))_MSHookFunction)((void *)posix_spawn, (void *)posix_spawn_hook, (void **)&orig_posix_spawn);
    ((void (*)(void *, void *, void **))_MSHookFunction)((void *)posix_spawnp, (void *)posix_spawnp_hook, (void **)&orig_posix_spawnp);
    serial_println("Succesfully hooked posix_spawn functions");
}

static void load_dyld_insert_libraries(void) {
    const char *reversed_libraries = getenv("SEIRARBIL_TRESNI_DLYD");
    if (reversed_libraries == NULL) {
        return;
    }
    serial_println("Found reversed libraries: %s", reversed_libraries);

    char *libraries = strdup(reversed_libraries);
    if (libraries == NULL) {
        return;
    }

    reverse_string(libraries);

    char *library_path = strtok(libraries, ":");
    while (library_path != NULL) {

        if (dlopen(library_path, RTLD_LAZY) == NULL) {
            serial_println("Failed to load library: %s. %s", library_path, dlerror());
        }

        library_path = strtok(NULL, ":");
    }

    free(libraries);
}

static void __attribute__((constructor)) init(void) {

    if (getpid() == 1) {
        init_launchd_hooks();
        return;
    }
    else {
        load_dyld_insert_libraries();
    }
}
