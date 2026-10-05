#ifndef AuthSecurity_h
#define AuthSecurity_h

#import <Foundation/Foundation.h>

@interface AuthSecurity : NSObject

/**
 * 启用反附加与反调试防护 (ptrace PT_DENY_ATTACH)
 */
+ (void)enableAntiDebug;

/**
 * 检测当前进程是否处于被调试状态 (sysctl P_TRACED)
 */
+ (BOOL)isBeingDebugged;

/**
 * 检测当前运行环境是否为越狱设备
 */
+ (BOOL)isDeviceJailbroken;

/**
 * 检测是否存在 Frida 注入或逆向 Hook 工具痕迹
 */
+ (BOOL)isFridaDetected;

/**
 * 动态字符串解密 (编译期异或混淆还原)
 */
+ (NSString *)decryptObfuscatedString:(const char *)cipherText key:(char)key length:(size_t)len;

@end

#endif /* AuthSecurity_h */
