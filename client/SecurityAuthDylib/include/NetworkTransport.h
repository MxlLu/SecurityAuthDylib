#ifndef NetworkTransport_h
#define NetworkTransport_h

#import <Foundation/Foundation.h>
#import "AuthTypes.h"

@interface NetworkTransport : NSObject

@property (nonatomic, copy) NSString *serverBaseURL;
@property (nonatomic, copy) NSString *clientId;
@property (nonatomic, strong) NSData *sessionKey;
@property (nonatomic, copy) NSString *signSalt;

+ (instancetype)sharedInstance;

/**
 * 发起初始握手请求 (RSA 加密协商 SessionKey)
 */
- (void)postHandshakeWithBundleId:(NSString *)bundleId
                       sessionKey:(NSData *)sessionKey
                       completion:(void(^)(BOOL success, NSDictionary *data, NSString *errorMsg))completion;

/**
 * 发送加密业务请求 (AES-GCM 信封封装 + 签名计算)
 */
- (void)postEncryptedPath:(NSString *)path
               bodyParams:(NSDictionary *)bodyParams
               completion:(void(^)(BOOL success, NSDictionary *data, NSString *errorMsg))completion;

@end

#endif /* NetworkTransport_h */
