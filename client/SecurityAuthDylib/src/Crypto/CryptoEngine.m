#import "../../include/CryptoEngine.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonCryptor.h>

// 声明 CommonCrypto GCM 接口 (iOS 9.0+)
CCCryptorStatus CCCryptorGCM(
    CCOperation op,
    CCAlgorithm alg,
    const void *key,
    size_t keyLength,
    const void *iv,
    size_t ivLen,
    const void *aData,
    size_t aDataLen,
    const void *dataIn,
    size_t dataInLength,
    void *dataOut,
    void *tag,
    size_t *tagLength);

static NSString *gServerPublicKeyPEM = nil;

@implementation CryptoEngine

+ (void)setServerRSAPublicKeyPEM:(NSString *)pemString {
    gServerPublicKeyPEM = [pemString copy];
}

+ (NSString *)getServerRSAPublicKeyPEM {
    if (!gServerPublicKeyPEM) {
        // 默认空占位，可在运行时从 Bundle 资源加载或动态设定
        gServerPublicKeyPEM = @"";
    }
    return gServerPublicKeyPEM;
}

+ (NSData *)generateRandomBytes:(size_t)length {
    NSMutableData *data = [NSMutableData dataWithLength:length];
    int result = SecRandomCopyBytes(kSecRandomDefault, length, data.mutableBytes);
    if (result == errSecSuccess) {
        return data;
    }
    return nil;
}

+ (NSString *)encryptSessionKeyWithRSA:(NSData *)sessionKey error:(NSError **)error {
    NSString *pem = [self getServerRSAPublicKeyPEM];
    if (!pem || pem.length == 0) {
        if (error) *error = [NSError errorWithDomain:@"CryptoEngine" code:-1 userInfo:@{NSLocalizedDescriptionKey: @"未配置服务端 RSA 公钥"}];
        return nil;
    }

    // 剥离 PEM 头部与尾部标头及换行
    NSString *cleanKey = [pem stringByReplacingOccurrencesOfString:@"-----BEGIN PUBLIC KEY-----" withString:@""];
    cleanKey = [cleanKey stringByReplacingOccurrencesOfString:@"-----END PUBLIC KEY-----" withString:@""];
    cleanKey = [cleanKey stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    cleanKey = [cleanKey stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    cleanKey = [cleanKey stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];

    NSData *keyData = [[NSData alloc] initWithBase64EncodedString:cleanKey options:NSDataBase64DecodingIgnoreUnknownCharacters];
    if (!keyData) {
        if (error) *error = [NSError errorWithDomain:@"CryptoEngine" code:-2 userInfo:@{NSLocalizedDescriptionKey: @"Base64 解码公钥失败"}];
        return nil;
    }

    NSDictionary *keyAttributes = @{
        (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
        (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPublic,
        (__bridge id)kSecAttrKeySizeInBits: @2048
    };

    CFErrorRef cfError = NULL;
    SecKeyRef pubKey = SecKeyCreateWithData((__bridge CFDataRef)keyData, (__bridge CFDictionaryRef)keyAttributes, &cfError);
    if (!pubKey || cfError) {
        if (error && cfError) *error = (__bridge_transfer NSError *)cfError;
        return nil;
    }

    CFDataRef cipherData = SecKeyCreateEncryptedData(pubKey, kSecKeyAlgorithmRSAEncryptionOAEPSHA256, (__bridge CFDataRef)sessionKey, &cfError);
    CFRelease(pubKey);

    if (cfError || !cipherData) {
        if (error && cfError) *error = (__bridge_transfer NSError *)cfError;
        return nil;
    }

    NSData *resultData = (__bridge_transfer NSData *)cipherData;
    return [resultData base64EncodedStringWithOptions:0];
}

+ (BOOL)encryptAESGCM:(NSData *)plainData
                  key:(NSData *)key
            outCipher:(NSData **)outCipher
                outIV:(NSData **)outIV
               outTag:(NSData **)outTag
                error:(NSError **)error {
    if (key.length != 32) {
        if (error) *error = [NSError errorWithDomain:@"CryptoEngine" code:-3 userInfo:@{NSLocalizedDescriptionKey: @"AES Key 必须为 32 字节"}];
        return NO;
    }

    NSData *iv = [self generateRandomBytes:12];
    NSMutableData *cipher = [NSMutableData dataWithLength:plainData.length];
    NSMutableData *tag = [NSMutableData dataWithLength:16];
    size_t tagLen = 16;

    CCCryptorStatus status = CCCryptorGCM(
        kCCEncrypt,
        kCCAlgorithmAES,
        key.bytes,
        key.length,
        iv.bytes,
        iv.length,
        NULL,
        0,
        plainData.bytes,
        plainData.length,
        cipher.mutableBytes,
        tag.mutableBytes,
        &tagLen
    );

    if (status != kCCSuccess) {
        if (error) *error = [NSError errorWithDomain:@"CryptoEngine" code:status userInfo:@{NSLocalizedDescriptionKey: @"AES-GCM 加密失败"}];
        return NO;
    }

    if (outCipher) *outCipher = cipher;
    if (outIV) *outIV = iv;
    if (outTag) *outTag = tag;
    return YES;
}

+ (NSData *)decryptAESGCM:(NSData *)cipherData
                      key:(NSData *)key
                       iv:(NSData *)iv
                  authTag:(NSData *)authTag
                    error:(NSError **)error {
    if (key.length != 32 || iv.length != 12 || authTag.length != 16) {
        if (error) *error = [NSError errorWithDomain:@"CryptoEngine" code:-4 userInfo:@{NSLocalizedDescriptionKey: @"解密参数长度不合法"}];
        return nil;
    }

    NSMutableData *plain = [NSMutableData dataWithLength:cipherData.length];
    NSMutableData *tagBuf = [authTag mutableCopy];
    size_t tagLen = 16;

    CCCryptorStatus status = CCCryptorGCM(
        kCCDecrypt,
        kCCAlgorithmAES,
        key.bytes,
        key.length,
        iv.bytes,
        iv.length,
        NULL,
        0,
        cipherData.bytes,
        cipherData.length,
        plain.mutableBytes,
        tagBuf.mutableBytes,
        &tagLen
    );

    if (status != kCCSuccess) {
        if (error) *error = [NSError errorWithDomain:@"CryptoEngine" code:status userInfo:@{NSLocalizedDescriptionKey: @"AES-GCM 解密/Tag 校验失败"}];
        return nil;
    }

    return plain;
}

+ (NSString *)calculateHMACSHA256WithKey:(NSString *)signKey
                               timestamp:(int64_t)timestamp
                                   nonce:(NSString *)nonce
                                 payload:(NSString *)payload {
    NSString *content = [NSString stringWithFormat:@"%lld&%@&%@", timestamp, nonce ?: @"", payload ?: @""];
    const char *keyStr = [signKey UTF8String];
    const char *dataStr = [content UTF8String];

    unsigned char cHMAC[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, keyStr, strlen(keyStr), dataStr, strlen(dataStr), cHMAC);

    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hex appendFormat:@"%02x", cHMAC[i]];
    }
    return hex;
}

+ (NSString *)calculateChallengeResponse:(NSString *)challenge
                                signSalt:(NSString *)salt
                               timestamp:(int64_t)timestamp {
    NSString *raw = [NSString stringWithFormat:@"%@%@%lld", challenge ?: @"", salt ?: @"", timestamp];
    const char *cStr = [raw UTF8String];
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(cStr, (CC_LONG)strlen(cStr), digest);

    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hex appendFormat:@"%02x", digest[i]];
    }
    return hex;
}

@end
