#ifndef AuthUIOverlay_h
#define AuthUIOverlay_h

#import <UIKit/UIKit.h>
#import "AuthTypes.h"

@interface AuthUIOverlay : NSObject

+ (instancetype)sharedInstance;

/**
 * 弹出卡密输入与授权激活窗口
 */
- (void)showAuthDialogWithCardKey:(NSString *)defaultKey
                         onCommit:(void(^)(NSString *cardKey))onCommit
                         onUnbind:(void(^)(NSString *cardKey))onUnbind;

/**
 * 隐藏或销毁授权窗口
 */
- (void)dismissAuthDialog;

/**
 * 展示悬浮状态胶囊/到期时间提示
 */
- (void)showStatusCapsuleWithText:(NSString *)text;

/**
 * 展示简单提示
 */
- (void)showToast:(NSString *)message;

@end

#endif /* AuthUIOverlay_h */
