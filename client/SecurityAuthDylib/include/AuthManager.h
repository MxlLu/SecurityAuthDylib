#ifndef AuthManager_h
#define AuthManager_h

#import <Foundation/Foundation.h>
#import "AuthTypes.h"

@interface AuthManager : NSObject

@property (nonatomic, assign, readonly) BOOL isAuthorized;
@property (nonatomic, strong, readonly) CardInfoModel *currentCardInfo;

+ (instancetype)sharedInstance;

/**
 * 启动全流程网络验证链路 (构造函数调用)
 */
- (void)startAuthFlow;

/**
 * 主动执行卡密激活
 */
- (void)activateWithCardKey:(NSString *)cardKey completion:(AuthCompletionHandler)completion;

/**
 * 主动执行设备解绑
 */
- (void)unbindWithCardKey:(NSString *)cardKey completion:(AuthCompletionHandler)completion;

@end

#endif /* AuthManager_h */
