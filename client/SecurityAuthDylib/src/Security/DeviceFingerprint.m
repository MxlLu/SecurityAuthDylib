#import "../../include/DeviceFingerprint.h"
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <sys/sysctl.h>
#import <CommonCrypto/CommonDigest.h>

@implementation DeviceFingerprintModel

- (NSDictionary *)toDictionary {
    return @{
        @"keychain_uuid": self.keychainUUID ?: @"",
        @"idfv": self.idfv ?: @"",
        @"device_model": self.deviceModel ?: @"",
        @"system_version": self.systemVersion ?: @"",
        @"bundle_id": self.bundleId ?: @"",
        @"hardware_hash": self.hardwareHash ?: @""
    };
}

@end

@implementation CardInfoModel

+ (instancetype)fromDictionary:(NSDictionary *)dict {
    CardInfoModel *model = [[CardInfoModel alloc] init];
    model.cardKey = dict[@"card_key"];
    model.cardType = dict[@"card_type"];
    
    NSString *statusStr = dict[@"status"];
    if ([statusStr isEqualToString:@"ACTIVE"]) model.status = AuthCardStatusActive;
    else if ([statusStr isEqualToString:@"EXPIRED"]) model.status = AuthCardStatusExpired;
    else if ([statusStr isEqualToString:@"FROZEN"]) model.status = AuthCardStatusFrozen;
    else if ([statusStr isEqualToString:@"UNBOUND"]) model.status = AuthCardStatusUnbound;
    else model.status = AuthCardStatusUnactivated;

    model.activatedAt = [dict[@"activated_at"] longLongValue];
    model.expireAt = [dict[@"expire_at"] longLongValue];
    model.remainingSeconds = [dict[@"remaining_seconds"] longLongValue];
    model.sessionToken = dict[@"session_token"];
    model.challengeToken = dict[@"challenge_token"];
    return model;
}

@end

@implementation DeviceFingerprint

+ (NSString *)getDeviceModel {
    size_t size;
    sysctlbyname("hw.machine", NULL, &size, NULL, 0);
    char *machine = malloc(size);
    sysctlbyname("hw.machine", machine, &size, NULL, 0);
    NSString *platform = [NSString stringWithCString:machine encoding:NSUTF8StringEncoding];
    free(machine);
    return platform ?: @"iPhone_Unknown";
}

+ (NSString *)computeHardwareHashWithUUID:(NSString *)uuid model:(NSString *)model {
    CGRect screenBounds = [UIScreen mainScreen].bounds;
    CGFloat scale = [UIScreen mainScreen].scale;
    NSInteger cores = [[NSProcessInfo processInfo] activeProcessorCount];
    unsigned long long memory = [[NSProcessInfo processInfo] physicalMemory];

    NSString *raw = [NSString stringWithFormat:@"%@|%@|%.0fx%.0f|%ld|%llu",
                     uuid, model, screenBounds.size.width * scale, screenBounds.size.height * scale, (long)cores, memory];

    const char *cStr = [raw UTF8String];
    unsigned char result[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(cStr, (CC_LONG)strlen(cStr), result);

    NSMutableString *hash = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hash appendFormat:@"%02x", result[i]];
    }
    return hash;
}

+ (DeviceFingerprintModel *)collectFingerprint {
    DeviceFingerprintModel *fp = [[DeviceFingerprintModel alloc] init];
    fp.keychainUUID = [self getOrCreateKeychainUUID];
    fp.idfv = [[[UIDevice currentDevice] identifierForVendor] UUIDString] ?: @"";
    fp.deviceModel = [self getDeviceModel];
    fp.systemVersion = [[UIDevice currentDevice] systemVersion] ?: @"";
    fp.bundleId = [[NSBundle mainBundle] bundleIdentifier] ?: @"";
    fp.hardwareHash = [self computeHardwareHashWithUUID:fp.keychainUUID model:fp.deviceModel];
    return fp;
}

#pragma mark - Keychain 持久化

+ (NSString *)getOrCreateKeychainUUID {
    NSString *cachedUUID = [self loadFromKeychain:AUTH_KEYCHAIN_KEY_UUID];
    if (cachedUUID && cachedUUID.length > 0) {
        return cachedUUID;
    }
    NSString *newUUID = [[NSUUID UUID] UUIDString];
    [self saveToKeychain:AUTH_KEYCHAIN_KEY_UUID value:newUUID];
    return newUUID;
}

+ (BOOL)saveToKeychain:(NSString *)key value:(NSString *)value {
    if (!key || !value) return NO;
    NSData *valueData = [value dataUsingEncoding:NSUTF8StringEncoding];

    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: AUTH_KEYCHAIN_SERVICE,
        (__bridge id)kSecAttrAccount: key
    };

    SecItemDelete((__bridge CFDictionaryRef)query);

    NSMutableDictionary *attributes = [query mutableCopy];
    attributes[(__bridge id)kSecValueData] = valueData;
    attributes[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlock;

    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)attributes, NULL);
    return (status == errSecSuccess);
}

+ (NSString *)loadFromKeychain:(NSString *)key {
    if (!key) return nil;
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: AUTH_KEYCHAIN_SERVICE,
        (__bridge id)kSecAttrAccount: key,
        (__bridge id)kSecReturnData: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne
    };

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status == errSecSuccess && result != NULL) {
        NSData *data = (__bridge_transfer NSData *)result;
        return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    }
    return nil;
}

+ (void)deleteFromKeychain:(NSString *)key {
    if (!key) return;
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: AUTH_KEYCHAIN_SERVICE,
        (__bridge id)kSecAttrAccount: key
    };
    SecItemDelete((__bridge CFDictionaryRef)query);
}

@end
