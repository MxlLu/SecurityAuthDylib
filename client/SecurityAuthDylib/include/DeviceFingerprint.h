#ifndef DeviceFingerprint_h
#define DeviceFingerprint_h

#import <Foundation/Foundation.h>
#import "AuthTypes.h"

@interface DeviceFingerprint : NSObject

/**
 * 获取完整设备指纹模型
 */
+ (DeviceFingerprintModel *)collectFingerprint;

/**
 * 获取或持久化生成 Keychain 唯一设备 UUID
 */
+ (NSString *)getOrCreateKeychainUUID;

/**
 * 读写 Keychain 辅助函数
 */
+ (BOOL)saveToKeychain:(NSString *)key value:(NSString *)value;
+ (NSString *)loadFromKeychain:(NSString *)key;
+ (void)deleteFromKeychain:(NSString *)key;

@end

#endif /* DeviceFingerprint_h */
