#ifndef AuthTypes_h
#define AuthTypes_h

#import <Foundation/Foundation.h>

/**
 * 客户端全局配置宏
 */
#define AUTH_SDK_VERSION @"1.0.0"
#define AUTH_DEFAULT_SERVER_URL @"http://127.0.0.1:8080"
#define AUTH_KEYCHAIN_SERVICE @"com.security.auth.license"
#define AUTH_KEYCHAIN_KEY_CARD @"saved_card_key"
#define AUTH_KEYCHAIN_KEY_TOKEN @"saved_session_token"
#define AUTH_KEYCHAIN_KEY_UUID @"device_persistent_uuid"

/**
 * 卡密生命周期状态
 */
typedef NS_ENUM(NSInteger, AuthCardStatus) {
    AuthCardStatusUnknown = 0,
    AuthCardStatusUnactivated,
    AuthCardStatusActive,
    AuthCardStatusExpired,
    AuthCardStatusFrozen,
    AuthCardStatusUnbound
};

/**
 * 业务响应状态码
 */
typedef NS_ENUM(NSInteger, AuthResultCode) {
    AuthResultCodeSuccess = 0,
    AuthResultCodeInvalidParams = 4000,
    AuthResultCodeReplayAttack = 4001,
    AuthResultCodeSignatureFailed = 4002,
    AuthResultCodeDecryptFailed = 4003,
    AuthResultCodeSessionExpired = 4004,
    AuthResultCodeCardNotFound = 4010,
    AuthResultCodeCardExpired = 4011,
    AuthResultCodeCardFrozen = 4012,
    AuthResultCodeDeviceLimitExceeded = 4013,
    AuthResultCodeDeviceMismatch = 4014,
    AuthResultCodeUnbindLimitExceeded = 4015,
    AuthResultCodeChallengeMismatch = 4016,
    AuthResultCodeAppBlocked = 4020,
    AuthResultCodeTamperAlert = 4030,
    AuthResultCodeServerError = 5000,
    AuthResultCodeNetworkError = -1001
};

/**
 * 设备指纹数据载体
 */
@interface DeviceFingerprintModel : NSObject
@property (nonatomic, copy) NSString *keychainUUID;
@property (nonatomic, copy) NSString *idfv;
@property (nonatomic, copy) NSString *deviceModel;
@property (nonatomic, copy) NSString *systemVersion;
@property (nonatomic, copy) NSString *bundleId;
@property (nonatomic, copy) NSString *hardwareHash;

- (NSDictionary *)toDictionary;
@end

/**
 * 卡密信息载体
 */
@interface CardInfoModel : NSObject
@property (nonatomic, copy) NSString *cardKey;
@property (nonatomic, copy) NSString *cardType;
@property (nonatomic, assign) AuthCardStatus status;
@property (nonatomic, assign) int64_t activatedAt;
@property (nonatomic, assign) int64_t expireAt;
@property (nonatomic, assign) int64_t remainingSeconds;
@property (nonatomic, copy) NSString *sessionToken;
@property (nonatomic, copy) NSString *challengeToken;

+ (instancetype)fromDictionary:(NSDictionary *)dict;
@end

/**
 * 统一业务回调定义
 */
typedef void(^AuthCompletionHandler)(BOOL success, NSString *message, id _Nullable data);

#endif /* AuthTypes_h */
