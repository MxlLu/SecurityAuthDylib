#ifndef AuthConfig_h
#define AuthConfig_h

#import <Foundation/Foundation.h>

@interface AuthConfig : NSObject

/**
 * 鉴权服务端完整通信地址 (例如 http://192.168.1.100:8080 或 https://auth.mydomain.com)
 */
@property (nonatomic, copy) NSString *serverURL;

/**
 * 服务端 2048 位 RSA 公钥 (PEM 格式)
 */
@property (nonatomic, copy) NSString *serverPublicKeyPEM;

/**
 * 原生弹窗主标题
 */
@property (nonatomic, copy) NSString *dialogTitle;

/**
 * 原生弹窗副标题/说明文本
 */
@property (nonatomic, copy) NSString *dialogSubtitle;

/**
 * 默认预填充的卡密 (测试阶段或免输场景可配置)
 */
@property (nonatomic, copy) NSString *defaultPresetCardKey;

/**
 * 动态心跳上报间隔时间 (秒，默认 60)
 */
@property (nonatomic, assign) NSTimeInterval heartbeatInterval;

/**
 * 是否启用底层反调试与 ptrace 防护 (默认 YES)
 */
@property (nonatomic, assign) BOOL enableAntiDebug;

/**
 * 是否开启越狱/逆向环境感知排查 (默认 YES)
 */
@property (nonatomic, assign) BOOL enableEnvironmentCheck;

+ (instancetype)sharedInstance;

@end

#endif /* AuthConfig_h */
