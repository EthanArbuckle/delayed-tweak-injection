#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <sys/sysctl.h>
#import <rootless.h>
#import <mach/mach.h>
#import <dlfcn.h>

// Bundle ID of the app to enable tweak injection for
#define TARGET_BUNDLE_ID @""

#define HELPER_DYLIB_PATH ROOT_PATH("/Library/MobileSubstrate/DynamicLibraries/jb-detect-bypass.dylib")

extern kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);
extern kern_return_t mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
extern kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);

NSString * const SBApplicationStateKey = @"SBApplicationStateKey";
NSString * const SBApplicationStateProcessIDKey = @"SBApplicationStateProcessIDKey";
NSString * const SBApplicationStateDisplayIDKey = @"SBApplicationStateDisplayIDKey";

enum {
    ApplicationStateUnknown = 0,
    ApplicationStateTerminated = (1 << 0),
    ApplicationStateBackgroundRunning = (1 << 2),
    ApplicationStateForegroundRunning = (1 << 3),
};

static kern_return_t launch_app(NSString *bundleID) {

    Class _FBSSystemService = objc_getClass("FBSSystemService");
    if (_FBSSystemService == NULL) {
        NSLog(@"Failed to find FBSSystemService class");
        return KERN_FAILURE;
    }

    __block int launchStatus = 0;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    void (^completionHandler)(NSError *) = ^(NSError *error) {

        launchStatus = error ? KERN_FAILURE : KERN_SUCCESS;
        if (error) {
            NSLog(@"App launch error: %@", error);
        }

        dispatch_semaphore_signal(sem);
    };

    mach_port_t clientPort = ((mach_port_t (*)(void))dlsym(RTLD_DEFAULT, "SBSCreateClientEntitlementEnforcementPort"))();
    if (clientPort == MACH_PORT_NULL) {
        NSLog(@"Failed to get client port: %s", dlerror());
        return KERN_FAILURE;
    }

    id systemService = ((id (*)(id, SEL))objc_msgSend)(_FBSSystemService, sel_registerName("sharedService"));
    NSDictionary *options = @{@"__ActivateSuspended" : @(NO), @"__UnlockDevice": @(YES), @"__DebugOptions": @{@"__Environment": @{@"DYLD_INSERT_LIBRARIES": @""}}};
    ((void (*)(id, SEL, NSString *, NSDictionary *, mach_port_t, void (^)(NSError *)))objc_msgSend)(systemService, sel_registerName("openApplication:options:clientPort:withResult:"), bundleID, options, clientPort, completionHandler);

    if (dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)) != 0) {
        NSLog(@"Timed out waiting for app to launch");
        return KERN_FAILURE;
    }

    return launchStatus;
}

static kern_return_t terminate_application_process(NSString *bundleID) {

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    void (^completionHandler)(void *) = ^void(void *_something) {
        dispatch_semaphore_signal(sem);
    };

    Class _FBSSystemService = objc_getClass("FBSSystemService");
    if (_FBSSystemService == NULL) {
        NSLog(@"Failed to find FBSSystemService class");
        return KERN_FAILURE;
    }

    id systemService = ((id (*)(id, SEL))objc_msgSend)(_FBSSystemService, sel_registerName("sharedService"));
    ((void (*)(id, SEL, id, long long, BOOL, id, void (^)(void *)))objc_msgSend)(systemService, sel_registerName("terminateApplication:forReason:andReport:withDescription:completion:"), bundleID, 1, 0, nil, completionHandler);

    if (dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)) != 0) {
        NSLog(@"Timed out waiting for app to terminate");
        return KERN_FAILURE;
    }

    return KERN_SUCCESS;
}

static kern_return_t suspend_all_threads(task_t task) {

    thread_act_array_t threads;
    mach_msg_type_number_t thread_count;
    kern_return_t kr = task_threads(task, &threads, &thread_count);
    if (kr != KERN_SUCCESS) {
        return kr;
    }

    for (mach_msg_type_number_t i = 0; i < thread_count; i++) {
        thread_suspend(threads[i]);
    }

    vm_deallocate(mach_task_self(), (vm_address_t)threads, thread_count * sizeof(thread_act_t));
    return KERN_SUCCESS;
}

static kern_return_t resume_all_threads(task_t task) {

    thread_act_array_t threads;
    mach_msg_type_number_t thread_count;
    kern_return_t kr = task_threads(task, &threads, &thread_count);
    if (kr != KERN_SUCCESS) {
        return kr;
    }

    for (mach_msg_type_number_t i = 0; i < thread_count; i++) {
        thread_resume(threads[i]);
    }

    vm_deallocate(mach_task_self(), (vm_address_t)threads, thread_count * sizeof(thread_act_t));
    return KERN_SUCCESS;
}

static kern_return_t inject_dylib_into_task(task_t task, const char *dylib_path) {

    mach_vm_size_t stack_size = 0x4000;
    mach_vm_address_t remote_stack;
    mach_port_insert_right(mach_task_self(), task, task, MACH_MSG_TYPE_COPY_SEND);
    kern_return_t kr = mach_vm_allocate(task, &remote_stack, stack_size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        NSLog(@"failed to allocate remote stack: %s", mach_error_string(kr));
        return kr;
    }

    mach_vm_protect(task, remote_stack, stack_size, 1, VM_PROT_READ | VM_PROT_WRITE);

    mach_vm_address_t remote_dylib_path_str;
    kr = mach_vm_allocate(task, &remote_dylib_path_str, 0x100 + strlen(dylib_path) + 1, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        NSLog(@"failed to allocate remote dylib path string: %s", mach_error_string(kr));
        return kr;
    }

    kr = mach_vm_write(task, 0x100 + remote_dylib_path_str, (vm_offset_t)dylib_path, (mach_msg_type_number_t)strlen(dylib_path) + 1);
    if (kr != KERN_SUCCESS) {
        NSLog(@"failed to write remote dylib path string: %s", mach_error_string(kr));
        return kr;
    }

    uint64_t *stack = malloc(stack_size);
    size_t sp = (stack_size / 8) - 2;
    kr = mach_vm_write(task, remote_stack, (vm_offset_t)stack, (mach_msg_type_number_t)stack_size);
    if (kr != KERN_SUCCESS) {
        free(stack);
        NSLog(@"failed to write remote stack: %s", mach_error_string(kr));
        return kr;
    }

    arm_thread_state64_t state = {};
    bzero(&state, sizeof(arm_thread_state64_t));
    state.__x[0] = (uint64_t)remote_stack;
    state.__x[2] = (uint64_t)dlsym(RTLD_NEXT, "dlopen");
    state.__x[3] = (uint64_t)(remote_dylib_path_str + 0x100);
    __darwin_arm_thread_state64_set_lr_fptr(state, (void *)0x7171717171717171);
    __darwin_arm_thread_state64_set_pc_fptr(state, dlsym(RTLD_NEXT, "pthread_create_from_mach_thread"));
    __darwin_arm_thread_state64_set_sp(state, (void *)(remote_stack + (sp * sizeof(uint64_t))));

    mach_port_t exc_handler;
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exc_handler);
    if (kr != KERN_SUCCESS) {
        free(stack);
        NSLog(@"failed to allocate exception handler port: %s", mach_error_string(kr));
        return kr;
    }

    kr = mach_port_insert_right(mach_task_self(), exc_handler, exc_handler, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        free(stack);
        NSLog(@"failed to insert right to exception handler port: %s", mach_error_string(kr));
        return kr;
    }

    mach_port_t remote_thread;
    kern_return_t (*_thread_create_running)(task_t, thread_state_flavor_t, thread_state_t, mach_msg_type_number_t, thread_act_t *) = dlsym(RTLD_DEFAULT, "thread_create_running");
    if (_thread_create_running == NULL) {
        free(stack);
        NSLog(@"failed to resolve thread_create_running");
        return KERN_FAILURE;
    }
    if (_thread_create_running(task, ARM_THREAD_STATE64, (thread_state_t)&state, ARM_THREAD_STATE64_COUNT, &remote_thread) != KERN_SUCCESS) {
        free(stack);
        NSLog(@"failed to create remote thread");
        return KERN_FAILURE;
    }

    kern_return_t (*_thread_set_exception_ports)(thread_act_t, exception_mask_t, mach_port_t, exception_behavior_t, thread_state_flavor_t) = dlsym(RTLD_DEFAULT, "thread_set_exception_ports");
    if (_thread_set_exception_ports == NULL) {
        free(stack);
        NSLog(@"failed to resolve thread_set_exception_ports");
        return KERN_FAILURE;
    }
    if (_thread_set_exception_ports(remote_thread, EXC_MASK_BAD_ACCESS, exc_handler, EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, ARM_THREAD_STATE64) != KERN_SUCCESS) {
        free(stack);
        NSLog(@"failed to set remote exception port");
        return KERN_FAILURE;
    }

    thread_resume(remote_thread);

    void (*_mach_msg)(mach_msg_header_t *, mach_msg_option_t, mach_msg_size_t, mach_msg_size_t, mach_port_t, mach_msg_timeout_t, mach_port_t) = dlsym(RTLD_DEFAULT, "mach_msg");
    if (_mach_msg == NULL) {
        free(stack);
        NSLog(@"failed to resolve mach_msg");
        return KERN_FAILURE;
    }

    mach_msg_header_t *msg = malloc(0x4000);
    _mach_msg(msg, MACH_RCV_MSG | MACH_RCV_LARGE, 0, 0x4000, exc_handler, 0, MACH_PORT_NULL);
    free(msg);

    kern_return_t (*_thread_terminate)(thread_act_t) = dlsym(RTLD_DEFAULT, "thread_terminate");
    if (_thread_terminate == NULL) {
        free(stack);
        NSLog(@"failed to resolve thread_terminate");
        return -1;
    }

    _thread_terminate(remote_thread);
    free(stack);
    return KERN_SUCCESS;
}

static kern_return_t inject_dylib_into_pid(pid_t pid, const char *dylib_path, bool suspend_threads) {

    task_t task;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        NSLog(@"Failed to get task for PID %d: %s", pid, mach_error_string(kr));
        return kr;
    }

    if (suspend_threads && (kr = suspend_all_threads(task)) != KERN_SUCCESS) {
        NSLog(@"Failed to suspend threads for PID %d: %s", pid, mach_error_string(kr));
        return kr;
    }

    if ((kr = inject_dylib_into_task(task, dylib_path)) != KERN_SUCCESS) {
        NSLog(@"Failed to inject dylib into PID %d: %s", pid, mach_error_string(kr));
        // Kill the app if it's still running
        terminate_application_process(TARGET_BUNDLE_ID);
        return kr;
    }

    if (suspend_threads && (kr = resume_all_threads(task)) != KERN_SUCCESS) {
        NSLog(@"Failed to resume threads for PID %d: %s", pid, mach_error_string(kr));
    }

    return kr;
}

static void (^handler)(NSDictionary *info);

int main(int argc, char *argv[]) {
    @autoreleasepool {

        if (argc == 2 && strcmp(argv[1], "--launchd") == 0) {

            bool suspend_threads = false;
            kern_return_t kr = inject_dylib_into_pid(1, HELPER_DYLIB_PATH, suspend_threads);
            if (kr != KERN_SUCCESS) {
                NSLog(@"Failed to inject helper into launchd: %s", mach_error_string(kr));
                return kr;
            }
        }

        id monitor = [[objc_getClass("BKSApplicationStateMonitor") alloc] init];
        if (!monitor) {
            NSLog(@"Failed to create application process monitor");
            return 1;
        }

        __block int lastKnownPid = -1;
        handler = ^(NSDictionary *info) {
            if (![info objectForKey:SBApplicationStateProcessIDKey]) {
                return;
            }

            // Skip processes that are not the target app
            NSString *launchedAppBundleId = [info objectForKey:SBApplicationStateDisplayIDKey];
            if ([launchedAppBundleId isEqualToString:TARGET_BUNDLE_ID] == NO) {
                return;
            }

            int currentPid = [info[SBApplicationStateProcessIDKey] intValue];
            if (currentPid < 1) {
                return;
            }

            BOOL isEnteringForeground = [info[SBApplicationStateKey] unsignedIntValue] == ApplicationStateForegroundRunning;
            if (lastKnownPid != currentPid && isEnteringForeground) {
                lastKnownPid = currentPid;
                NSLog(@"Detected %@ launching with PID %d", launchedAppBundleId, currentPid);

                // Inject the helper dylib
                bool suspend_threads = true;
                kern_return_t kr = inject_dylib_into_pid(currentPid, HELPER_DYLIB_PATH, suspend_threads);
                if (kr != KERN_SUCCESS) {
                    NSLog(@"Failed to inject helper dylib into PID %d: %s", currentPid, mach_error_string(kr));

                    // Try launching it again
                    terminate_application_process(TARGET_BUNDLE_ID);
                    launch_app(TARGET_BUNDLE_ID);

                    // The handler will be called again with the new PID
                    return;
                }

                NSLog(@"Successfully injected dylib into PID %d", currentPid);
            }
        };
        ((void (*)(id, SEL, void (^)(NSDictionary *)))objc_msgSend)(monitor, sel_registerName("setHandler:"), handler);

        dispatch_main();
    }

    return 0;
}
