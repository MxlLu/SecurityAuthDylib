#import "../../include/NetworkTransport.h"
#import "../../include/CryptoEngine.h"
#import "../../include/AuthConfig.h"

@interface NetworkTransport ()
@property (nonatomic, strong) NSURLSession *session;
@end

@implementation NetworkTransport

+ (instancetype)sharedInstance {
    static NetworkTransport *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[NetworkTransport alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _serverBaseURL = [AuthConfig sharedInstance].serverURL ?: AUTH_DEFAULT_SERVER_URL;
        NSURLSessionConfiguration *config = [NSURLSessionConfiguration defaultSessionConfiguration];
        config.timeoutIntervalForRequest = 15.0;
        _session = [NSURLSession sessionWithConfiguration:config];
    }
    return self;
}

- (void)postHandshakeWithBundleId:(NSString *)bundleId
                       sessionKey:(NSData *)sessionKey
                       completion:(void(^)(BOOL success, NSDictionary *data, NSString *errorMsg))completion {
    NSError *rsaError = nil;
    NSString *encryptedKey = [CryptoEngine encryptSessionKeyWithRSA:sessionKey error:&rsaError];
    if (rsaError || !encryptedKey) {
        if (completion) completion(NO, nil, rsaError.localizedDescription ?: @"RSA 加密失败");
        return;
    }

    NSString *urlStr = [NSString stringWithFormat:@"%@/api/v1/auth/handshake", self.serverBaseURL];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:urlStr]];
    request.HTTPMethod = @"POST";
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];

    int64_t timestamp = (int64_t)([[NSDate date] timeIntervalSince1970] * 1000);
    NSData *nonceData = [CryptoEngine generateRandomBytes:8];
    NSMutableString *nonce = [NSMutableString string];
    const unsigned char *bytes = nonceData.bytes;
    for (int i = 0; i < 8; i++) [nonce appendFormat:@"%02x", bytes[i]];

    NSString *signature = [CryptoEngine calculateHMACSHA256WithKey:@"salt_ios_auth_v1_secure_2026"
                                                         timestamp:timestamp
                                                             nonce:nonce
                                                           payload:encryptedKey];

    [request setValue:AUTH_SDK_VERSION forHTTPHeaderField:@"X-Auth-Version"];
    [request setValue:[NSString stringWithFormat:@"%lld", timestamp] forHTTPHeaderField:@"X-Auth-Timestamp"];
    [request setValue:nonce forHTTPHeaderField:@"X-Auth-Nonce"];
    [request setValue:signature forHTTPHeaderField:@"X-Auth-Signature"];

    NSDictionary *reqBody = @{
        @"app_bundle_id": bundleId ?: @"",
        @"client_sdk_version": AUTH_SDK_VERSION,
        @"encrypted_session_key": encryptedKey
    };
    request.HTTPBody = [NSJSONSerialization dataWithJSONObject:reqBody options:0 error:nil];

    [[self.session dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (error || !data) {
            if (completion) completion(NO, nil, error.localizedDescription ?: @"网络连接失败");
            return;
        }

        NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        if (!json || [json[@"code"] integerValue] != 0) {
            if (completion) completion(NO, nil, json[@"msg"] ?: @"握手未通过");
            return;
        }

        // 响应解密
        NSString *cipherBase64 = json[@"data"];
        NSString *ivHex = json[@"iv"];
        NSString *tagHex = json[@"auth_tag"];

        NSData *cipherData = [[NSData alloc] initWithBase64EncodedString:cipherBase64 options:0];
        NSMutableData *ivData = [NSMutableData dataWithCapacity:12];
        for (int i = 0; i < ivHex.length; i += 2) {
            unsigned int byte;
            [[NSScanner scannerWithString:[ivHex substringWithRange:NSMakeRange(i, 2)]] scanHexInt:&byte];
            uint8_t b = (uint8_t)byte;
            [ivData appendBytes:&b length:1];
        }
        NSMutableData *tagData = [NSMutableData dataWithCapacity:16];
        for (int i = 0; i < tagHex.length; i += 2) {
            unsigned int byte;
            [[NSScanner scannerWithString:[tagHex substringWithRange:NSMakeRange(i, 2)]] scanHexInt:&byte];
            uint8_t b = (uint8_t)byte;
            [tagData appendBytes:&b length:1];
        }

        NSError *decError = nil;
        NSData *plainData = [CryptoEngine decryptAESGCM:cipherData key:sessionKey iv:ivData authTag:tagData error:&decError];
        if (decError || !plainData) {
            if (completion) completion(NO, nil, @"解密响应数据失败");
            return;
        }

        NSDictionary *resDict = [NSJSONSerialization JSONObjectWithData:plainData options:0 error:nil];
        if (completion) completion(YES, resDict, nil);
    }] resume];
}

- (void)postEncryptedPath:(NSString *)path
               bodyParams:(NSDictionary *)bodyParams
               completion:(void(^)(BOOL success, NSDictionary *data, NSString *errorMsg))completion {
    if (!self.sessionKey || self.sessionKey.length != 32 || !self.clientId) {
        if (completion) completion(NO, nil, @"会话密钥或 ClientID 未就绪，需重新握手");
        return;
    }

    NSData *plainJsonData = [NSJSONSerialization dataWithJSONObject:bodyParams options:0 error:nil];
    NSData *cipherData = nil;
    NSData *ivData = nil;
    NSData *tagData = nil;
    NSError *encError = nil;

    BOOL encOk = [CryptoEngine encryptAESGCM:plainJsonData
                                         key:self.sessionKey
                                   outCipher:&cipherData
                                       outIV:&ivData
                                      outTag:&tagData
                                       error:&encError];
    if (!encOk || encError) {
        if (completion) completion(NO, nil, @"业务载荷加密失败");
        return;
    }

    NSString *cipherBase64 = [cipherData base64EncodedStringWithOptions:0];
    NSMutableString *ivHex = [NSMutableString string];
    const unsigned char *ivBytes = ivData.bytes;
    for (int i = 0; i < ivData.length; i++) [ivHex appendFormat:@"%02x", ivBytes[i]];

    NSMutableString *tagHex = [NSMutableString string];
    const unsigned char *tagBytes = tagData.bytes;
    for (int i = 0; i < tagData.length; i++) [tagHex appendFormat:@"%02x", tagBytes[i]];

    int64_t timestamp = (int64_t)([[NSDate date] timeIntervalSince1970] * 1000);
    NSData *nonceData = [CryptoEngine generateRandomBytes:8];
    NSMutableString *nonce = [NSMutableString string];
    const unsigned char *nBytes = nonceData.bytes;
    for (int i = 0; i < 8; i++) [nonce appendFormat:@"%02x", nBytes[i]];

    NSString *signature = [CryptoEngine calculateHMACSHA256WithKey:self.signSalt ?: @""
                                                         timestamp:timestamp
                                                             nonce:nonce
                                                           payload:cipherBase64];

    NSString *urlStr = [NSString stringWithFormat:@"%@%@", self.serverBaseURL, path];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:urlStr]];
    request.HTTPMethod = @"POST";
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    [request setValue:AUTH_SDK_VERSION forHTTPHeaderField:@"X-Auth-Version"];
    [request setValue:[NSString stringWithFormat:@"%lld", timestamp] forHTTPHeaderField:@"X-Auth-Timestamp"];
    [request setValue:nonce forHTTPHeaderField:@"X-Auth-Nonce"];
    [request setValue:self.clientId forHTTPHeaderField:@"X-Auth-Client-ID"];
    [request setValue:signature forHTTPHeaderField:@"X-Auth-Signature"];

    NSDictionary *envelope = @{
        @"client_id": self.clientId,
        @"iv": ivHex,
        @"auth_tag": tagHex,
        @"cipher_data": cipherBase64
    };
    request.HTTPBody = [NSJSONSerialization dataWithJSONObject:envelope options:0 error:nil];

    [[self.session dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (error || !data) {
            if (completion) completion(NO, nil, error.localizedDescription ?: @"网络通信失败");
            return;
        }

        NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        if (!json) {
            if (completion) completion(NO, nil, @"解析响应 JSON 失败");
            return;
        }

        if ([json[@"code"] integerValue] != 0) {
            if (completion) completion(NO, json, json[@"msg"] ?: @"业务请求失败");
            return;
        }

        NSString *resCipherBase64 = json[@"data"];
        NSString *resIvHex = json[@"iv"];
        NSString *resTagHex = json[@"auth_tag"];

        NSData *resCipher = [[NSData alloc] initWithBase64EncodedString:resCipherBase64 options:0];
        NSMutableData *rIv = [NSMutableData dataWithCapacity:12];
        for (int i = 0; i < resIvHex.length; i += 2) {
            unsigned int byte;
            [[NSScanner scannerWithString:[resIvHex substringWithRange:NSMakeRange(i, 2)]] scanHexInt:&byte];
            uint8_t b = (uint8_t)byte;
            [rIv appendBytes:&b length:1];
        }
        NSMutableData *rTag = [NSMutableData dataWithCapacity:16];
        for (int i = 0; i < resTagHex.length; i += 2) {
            unsigned int byte;
            [[NSScanner scannerWithString:[resTagHex substringWithRange:NSMakeRange(i, 2)]] scanHexInt:&byte];
            uint8_t b = (uint8_t)byte;
            [rTag appendBytes:&b length:1];
        }

        NSError *decErr = nil;
        NSData *plainData = [CryptoEngine decryptAESGCM:resCipher key:self.sessionKey iv:rIv authTag:rTag error:&decErr];
        if (decErr || !plainData) {
            if (completion) completion(NO, nil, @"解密服务端业务响应失败");
            return;
        }

        NSDictionary *decDict = [NSJSONSerialization JSONObjectWithData:plainData options:0 error:nil];
        if (completion) completion(YES, decDict, nil);
    }] resume];
}

@end
