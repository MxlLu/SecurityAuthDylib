#ifndef CryptoEngine_h
#define CryptoEngine_h

#import <Foundation/Foundation.h>

@interface CryptoEngine : NSObject

/**
 * 设置或获取服务端嵌入式 RSA 公钥 (PEM / DER 格式)
 */
+ (void)setServerRSAPublicKeyPEM:(NSString *)pemString;
+ (NSString *)getServerRSAPublicKeyPEM;

/**
 * 生成指定长度的安全随机字节
 */
+ (NSData *)generateRandomBytes:(size_t)length;

/**
 * 使用服务端 RSA 公钥 (RSA-OAEP-SHA256) 加密本地 32 字节 SessionKey
 */
+ (NSString *)encryptSessionKeyWithRSA:(NSData *)sessionKey error:(NSError **)error;

/**
 * AES-256-GCM 加密数据
 */
+ (BOOL)encryptAESGCM:(NSData *)plainData
                  key:(NSData *)key
            outCipher:(NSData **)outCipher
                outIV:(NSData **)outIV
               outTag:(NSData **)outTag
                error:(NSError **)error;

/**
 * AES-256-GCM 解密数据
 */
+ (NSData *)decryptAESGCM:(NSData *)cipherData
                      key:(NSData *)key
                       iv:(NSData *)iv
                  authTag:(NSData *)authTag
                    error:(NSError **)error;

/**
 * 计算 API 请求签名 HMAC-SHA256
 */
+ (NSString *)calculateHMACSHA256WithKey:(NSString *)signKey
                               timestamp:(int64_t)timestamp
                                   nonce:(NSString *)nonce
                                 payload:(NSString *)payload;

/**
 * 计算心跳滚动挑战应答哈希: SHA256(challenge + salt + timestamp)
 */
+ (NSString *)calculateChallengeResponse:(NSString *)challenge
                                signSalt:(NSString *)salt
                               timestamp:(int64_t)timestamp;

@end

#endif /* CryptoEngine_h */
