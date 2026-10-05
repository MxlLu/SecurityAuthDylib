#import <UIKit/UIKit.h>
#import "../include/AuthManager.h"
#import "../include/CryptoEngine.h"
#import "../include/AuthSecurity.h"
#import "../include/AuthConfig.h"

// 注入动态库构造函数入口
__attribute__((constructor)) static void SecurityAuthEntry(void) {
    NSLog(@"====================================================");
    NSLog(@"[SecurityAuth] Dylib 成功注入宿主进程！版本: %@", AUTH_SDK_VERSION);
    NSLog(@"====================================================");

    // 1. 初始化客户端业务参数 (可在此按需自定义配置)
    AuthConfig *cfg = [AuthConfig sharedInstance];
    cfg.serverURL = @"https://ios.xltx7.dpdns.org";   // 宝塔线上服务端通信地址
    cfg.dialogTitle = @"专业版授权激活";                // 弹窗主标题
    cfg.dialogSubtitle = @"请输入卡密以解锁完整功能";     // 弹窗说明文案
    cfg.defaultPresetCardKey = @"";                   // 可预设默认卡密 (测试阶段填入如 @"VIP-CUSTOM-8888")
    cfg.heartbeatInterval = 60.0;                     // 心跳保活周期 (秒)

    // 2. 初始化安全防护
    if (cfg.enableAntiDebug) {
        [AuthSecurity enableAntiDebug];
    }

    // 3. 预置服务端 RSA 公钥 (与服务端的 keys/server_public.pem 对应)
    NSString *embeddedServerPubKey =
        @"-----BEGIN PUBLIC KEY-----\n"
        @"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwMPVF23Cm74qgsHM/T9E\n"
        @"vKyI/cB1vR4lCLD4u8w/hm6pPugrqIc4hqQSXdDq9SKg2YtCvx3aiTB55bbeAmKi\n"
        @"QMok0kp9ETOhksZowK3EcULc/kIl6Bmb7V7g1x3a8CCPE2+/zu+1qoFL/9m2O/78\n"
        @"u0OVcqchY1BBGDKN+z1ZkoUhf1JBou4/ku5kqf7P5vAnqSF1hDPw66lLaiRU+lP2\n"
        @"78dbXOaCxK9tuQPyRz9s9VIAbdxrOXmoBoGOAEjXm/cytsBsR9IdMEFB6iLNLMSV\n"
        @"EJe7y9wol5aqNoukZ4+ZR+gmRskPoRgvzgVvJTow+bAcY+9lcweG4QkFVAej0bm7\n"
        @"AwIDAQAB\n"
        @"-----END PUBLIC KEY-----";
    [CryptoEngine setServerRSAPublicKeyPEM:embeddedServerPubKey];

    // 4. 监听应用启动完成通知以无感挂载 UI
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
                                                      object:nil
                                                       queue:[NSOperationQueue mainQueue]
                                                  usingBlock:^(NSNotification * _Nonnull note) {
        NSLog(@"[SecurityAuth] 宿主应用完成启动，拉起网络授权状态机...");
        // 延迟 0.5 秒避开首屏闪屏动画冲突
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [[AuthManager sharedInstance] startAuthFlow];
        });
    }];
}
