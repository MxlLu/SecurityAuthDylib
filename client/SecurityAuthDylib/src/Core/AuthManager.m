#import "../../include/AuthManager.h"
#import "../../include/AuthSecurity.h"
#import "../../include/DeviceFingerprint.h"
#import "../../include/CryptoEngine.h"
#import "../../include/NetworkTransport.h"
#import "../../include/AuthUIOverlay.h"
#import "../../include/AuthConfig.h"

@interface AuthManager ()
@property (nonatomic, assign) BOOL isAuthorized;
@property (nonatomic, strong) CardInfoModel *currentCardInfo;
@property (nonatomic, strong) NSTimer *heartbeatTimer;
@property (nonatomic, copy) NSString *challengeToken;
@property (nonatomic, assign) NSInteger continuousHeartbeatFailures;
@end

@implementation AuthManager

+ (instancetype)sharedInstance {
    static AuthManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[AuthManager alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _isAuthorized = NO;
        _continuousHeartbeatFailures = 0;
    }
    return self;
}

- (void)startAuthFlow {
    // 1. 安全与反调试感知
    [AuthSecurity enableAntiDebug];
    if ([AuthSecurity isBeingDebugged]) {
        NSLog(@"[SecurityAuth] 警告: 检测到进程被调试器附加！");
    }

    // 2. 准备本地 32 字节随机会话密钥
    NSData *localSessionKey = [CryptoEngine generateRandomBytes:32];

    // 3. 执行握手
    NSString *bundleId = [[NSBundle mainBundle] bundleIdentifier];
    [[NetworkTransport sharedInstance] postHandshakeWithBundleId:bundleId
                                                      sessionKey:localSessionKey
                                                      completion:^(BOOL success, NSDictionary *data, NSString *errorMsg) {
        if (!success || !data) {
            NSLog(@"[SecurityAuth] 握手失败: %@", errorMsg);
            [self promptAuthDialogWithCardKey:nil];
            return;
        }

        [NetworkTransport sharedInstance].clientId = data[@"client_id"];
        [NetworkTransport sharedInstance].sessionKey = localSessionKey;
        [NetworkTransport sharedInstance].signSalt = data[@"sign_salt"];

        // 4. 检查 Keychain 本地凭据
        NSString *savedCard = [DeviceFingerprint loadFromKeychain:AUTH_KEYCHAIN_KEY_CARD];
        NSString *savedToken = [DeviceFingerprint loadFromKeychain:AUTH_KEYCHAIN_KEY_TOKEN];

        if (savedCard && savedCard.length > 0) {
            // 发起静默免密登录
            [self silentVerifyWithCardKey:savedCard sessionToken:savedToken];
        } else {
            // 本地无凭据，呼出激活窗口
            [self promptAuthDialogWithCardKey:nil];
        }
    }];
}

- (void)silentVerifyWithCardKey:(NSString *)cardKey sessionToken:(NSString *)token {
    DeviceFingerprintModel *fp = [DeviceFingerprint collectFingerprint];
    NSDictionary *body = @{
        @"card_key": cardKey,
        @"session_token": token ?: @"",
        @"device_fingerprint": [fp toDictionary]
    };

    [[NetworkTransport sharedInstance] postEncryptedPath:@"/api/v1/auth/verify"
                                              bodyParams:body
                                              completion:^(BOOL success, NSDictionary *data, NSString *errorMsg) {
        if (success && data && [data[@"valid"] boolValue]) {
            self.isAuthorized = YES;
            self.challengeToken = data[@"challenge_token"];
            
            CardInfoModel *info = [[CardInfoModel alloc] init];
            info.cardKey = cardKey;
            info.expireAt = [data[@"expire_at"] longLongValue];
            info.remainingSeconds = [data[@"remaining_seconds"] longLongValue];
            info.sessionToken = data[@"session_token"];
            self.currentCardInfo = info;

            // 启动心跳定时器
            [self startHeartbeatTimer];

            // 展示状态胶囊
            NSString *timeDesc = info.expireAt == 0 ? @"永久授权" : [NSString stringWithFormat:@"剩余 %lld 天", info.remainingSeconds / 86400];
            [[AuthUIOverlay sharedInstance] showStatusCapsuleWithText:timeDesc];
        } else {
            NSLog(@"[SecurityAuth] 静默验证失效: %@", errorMsg);
            [self promptAuthDialogWithCardKey:cardKey];
        }
    }];
}

- (void)promptAuthDialogWithCardKey:(NSString *)defaultKey {
    [[AuthUIOverlay sharedInstance] showAuthDialogWithCardKey:defaultKey
                                                     onCommit:^(NSString *cardKey) {
        [self activateWithCardKey:cardKey completion:^(BOOL success, NSString *message, id data) {
            if (success) {
                [[AuthUIOverlay sharedInstance] dismissAuthDialog];
            } else {
                [[AuthUIOverlay sharedInstance] showToast:message ?: @"激活失败"];
            }
        }];
    } onUnbind:^(NSString *cardKey) {
        [self unbindWithCardKey:cardKey completion:^(BOOL success, NSString *message, id data) {
            [[AuthUIOverlay sharedInstance] showToast:message ?: @"解绑已处理"];
        }];
    }];
}

- (void)activateWithCardKey:(NSString *)cardKey completion:(AuthCompletionHandler)completion {
    DeviceFingerprintModel *fp = [DeviceFingerprint collectFingerprint];
    NSDictionary *body = @{
        @"card_key": cardKey,
        @"device_fingerprint": [fp toDictionary]
    };

    [[NetworkTransport sharedInstance] postEncryptedPath:@"/api/v1/auth/activate"
                                              bodyParams:body
                                              completion:^(BOOL success, NSDictionary *data, NSString *errorMsg) {
        if (!success || !data) {
            if (completion) completion(NO, errorMsg, nil);
            return;
        }

        self.isAuthorized = YES;
        self.currentCardInfo = [CardInfoModel fromDictionary:data];
        self.challengeToken = data[@"challenge_token"];

        // 持久化存储到 Keychain
        [DeviceFingerprint saveToKeychain:AUTH_KEYCHAIN_KEY_CARD value:cardKey];
        [DeviceFingerprint saveToKeychain:AUTH_KEYCHAIN_KEY_TOKEN value:self.currentCardInfo.sessionToken];

        // 启动心跳定时器
        [self startHeartbeatTimer];

        NSString *timeDesc = self.currentCardInfo.expireAt == 0 ? @"永久授权" : @"已激活";
        [[AuthUIOverlay sharedInstance] showStatusCapsuleWithText:timeDesc];

        if (completion) completion(YES, @"激活成功", self.currentCardInfo);
    }];
}

- (void)unbindWithCardKey:(NSString *)cardKey completion:(AuthCompletionHandler)completion {
    DeviceFingerprintModel *fp = [DeviceFingerprint collectFingerprint];
    NSDictionary *body = @{
        @"card_key": cardKey,
        @"device_fingerprint": [fp toDictionary],
        @"reason": @"USER_REQUEST"
    };

    [[NetworkTransport sharedInstance] postEncryptedPath:@"/api/v1/auth/unbind"
                                              bodyParams:body
                                              completion:^(BOOL success, NSDictionary *data, NSString *errorMsg) {
        if (success) {
            // 清理本地 Keychain 凭据
            [DeviceFingerprint deleteFromKeychain:AUTH_KEYCHAIN_KEY_CARD];
            [DeviceFingerprint deleteFromKeychain:AUTH_KEYCHAIN_KEY_TOKEN];
            [self stopHeartbeatTimer];
            self.isAuthorized = NO;
            if (completion) completion(YES, [NSString stringWithFormat:@"解绑成功 (扣除 %ld 小时)", [data[@"deducted_hours"] longValue]], data);
        } else {
            if (completion) completion(NO, errorMsg ?: @"解绑失败", nil);
        }
    }];
}

#pragma mark - 心跳定时保活机制

- (void)startHeartbeatTimer {
    dispatch_async(dispatch_get_main_queue(), ^{
        [self stopHeartbeatTimer];
        NSTimeInterval interval = [AuthConfig sharedInstance].heartbeatInterval;
        if (interval <= 0) interval = 60.0;
        self.heartbeatTimer = [NSTimer scheduledTimerWithTimeInterval:interval
                                                               repeats:YES
                                                                 block:^(NSTimer * _Nonnull timer) {
            [self sendHeartbeat];
        }];
    });
}

- (void)stopHeartbeatTimer {
    if (self.heartbeatTimer) {
        [self.heartbeatTimer invalidate];
        self.heartbeatTimer = nil;
    }
}

- (void)sendHeartbeat {
    if (!self.currentCardInfo.sessionToken || !self.challengeToken) return;

    int64_t timestamp = (int64_t)([[NSDate date] timeIntervalSince1970] * 1000);
    NSString *signSalt = [NetworkTransport sharedInstance].signSalt ?: @"";
    NSString *responseHash = [CryptoEngine calculateChallengeResponse:self.challengeToken
                                                             signSalt:signSalt
                                                            timestamp:timestamp];

    NSDictionary *body = @{
        @"session_token": self.currentCardInfo.sessionToken,
        @"challenge_response": responseHash,
        @"uptime_sec": @(60),
        @"tamper_status": @{
            @"is_jailbroken": @([AuthSecurity isDeviceJailbroken]),
            @"is_debugged": @([AuthSecurity isBeingDebugged])
        }
    };

    [[NetworkTransport sharedInstance] postEncryptedPath:@"/api/v1/auth/heartbeat"
                                              bodyParams:body
                                              completion:^(BOOL success, NSDictionary *data, NSString *errorMsg) {
        if (success && data && [data[@"alive"] boolValue]) {
            self.continuousHeartbeatFailures = 0;
            self.challengeToken = data[@"next_challenge_token"];

            NSString *forceAction = data[@"force_action"];
            if ([forceAction isEqualToString:@"TERMINATE"]) {
                [self triggerCircuitBreakerWithMessage:@"授权已终止，程序即将退出"];
            }
        } else {
            self.continuousHeartbeatFailures++;
            NSLog(@"[SecurityAuth] 心跳失败 (%ld 次): %@", (long)self.continuousHeartbeatFailures, errorMsg);
            if (self.continuousHeartbeatFailures >= 3) {
                [self triggerCircuitBreakerWithMessage:@"连续心跳丢失或卡密过期，请重新激活"];
            }
        }
    }];
}

- (void)triggerCircuitBreakerWithMessage:(NSString *)msg {
    self.isAuthorized = NO;
    [self stopHeartbeatTimer];
    [[AuthUIOverlay sharedInstance] showToast:msg];
}

@end
