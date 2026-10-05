#import "../../include/AuthConfig.h"
#import "../../include/AuthTypes.h"

@implementation AuthConfig

+ (instancetype)sharedInstance {
    static AuthConfig *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[AuthConfig alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _serverURL = AUTH_DEFAULT_SERVER_URL;
        _dialogTitle = @"软件授权激活";
        _dialogSubtitle = @"请输入授权卡密以解锁完整功能";
        _defaultPresetCardKey = @"";
        _heartbeatInterval = 60.0;
        _enableAntiDebug = YES;
        _enableEnvironmentCheck = YES;
    }
    return self;
}

@end
