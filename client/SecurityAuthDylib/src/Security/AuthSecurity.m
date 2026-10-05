#import "../../include/AuthSecurity.h"
#import <sys/types.h>
#import <sys/sysctl.h>
#import <dlfcn.h>
#import <unistd.h>
#import <netinet/in.h>
#import <sys/socket.h>
#import <arpa/inet.h>

#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif

typedef int (*ptrace_ptr_t)(int _request, pid_t _pid, caddr_t _addr, int _data);

@implementation AuthSecurity

+ (void)enableAntiDebug {
#ifndef DEBUG
    // 动态查找 ptrace 符号，防止静态导入表特征暴露
    void *handle = dlopen(NULL, RTLD_GLOBAL | RTLD_NOW);
    if (handle) {
        ptrace_ptr_t ptrace_func = (ptrace_ptr_t)dlsym(handle, "ptrace");
        if (ptrace_func) {
            ptrace_func(PT_DENY_ATTACH, 0, 0, 0);
        }
        dlclose(handle);
    }
#endif
}

+ (BOOL)isBeingDebugged {
    int name[4];
    struct kinfo_proc info;
    size_t info_size = sizeof(info);

    info.kp_proc.p_flag = 0;
    name[0] = CTL_KERN;
    name[1] = KERN_PROC;
    name[2] = KERN_PROC_PID;
    name[3] = getpid();

    if (sysctl(name, 4, &info, &info_size, NULL, 0) == -1) {
        return NO;
    }

    // 检查 P_TRACED 标志位 (0x00000800)
    return ((info.kp_proc.p_flag & P_TRACED) != 0);
}

+ (BOOL)isDeviceJailbroken {
    // 常见越狱路径探针
    NSArray *jailbreakPaths = @[
        @"/Applications/Cydia.app",
        @"/Library/MobileSubstrate/MobileSubstrate.dylib",
        @"/bin/bash",
        @"/usr/sbin/sshd",
        @"/etc/apt",
        @"/private/var/lib/apt/",
        @"/var/lib/cydia"
    ];

    for (NSString *path in jailbreakPaths) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
            return YES;
        }
    }

    // 尝试在沙盒外写文件探针
    NSError *error = nil;
    NSString *testString = @"JailbreakTest";
    NSString *testPath = @"/private/jailbreak_test.txt";
    [testString writeToFile:testPath atomically:YES encoding:NSUTF8StringEncoding error:&error];
    if (!error) {
        [[NSFileManager defaultManager] removeItemAtPath:testPath error:nil];
        return YES;
    }

    return NO;
}

+ (BOOL)isFridaDetected {
    // 探测 Frida 默认控制端口 27042
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(27042);
    inet_aton("127.0.0.1", &sa.sin_addr);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock >= 0) {
        int result = connect(sock, (struct sockaddr *)&sa, sizeof(sa));
        close(sock);
        if (result == 0) {
            return YES; // 端口开放，极可能存在 Frida-server
        }
    }
    return NO;
}

+ (NSString *)decryptObfuscatedString:(const char *)cipherText key:(char)key length:(size_t)len {
    char *buffer = (char *)malloc(len + 1);
    for (size_t i = 0; i < len; i++) {
        buffer[i] = cipherText[i] ^ key;
    }
    buffer[len] = '\0';
    NSString *result = [NSString stringWithUTF8String:buffer];
    free(buffer);
    return result;
}

@end
