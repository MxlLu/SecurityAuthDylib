#import "../../include/AuthUIOverlay.h"
#import "../../include/AuthConfig.h"

@interface AuthUIOverlay ()
@property (nonatomic, strong) UIWindow *overlayWindow;
@property (nonatomic, strong) UIView *cardView;
@property (nonatomic, strong) UITextField *keyTextField;
@property (nonatomic, strong) UIActivityIndicatorView *spinner;
@property (nonatomic, strong) UIButton *commitBtn;
@property (nonatomic, copy) void(^commitHandler)(NSString *cardKey);
@property (nonatomic, copy) void(^unbindHandler)(NSString *cardKey);
@end

@implementation AuthUIOverlay

+ (instancetype)sharedInstance {
    static AuthUIOverlay *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[AuthUIOverlay alloc] init];
    });
    return instance;
}

- (void)showAuthDialogWithCardKey:(NSString *)defaultKey
                         onCommit:(void(^)(NSString *cardKey))onCommit
                         onUnbind:(void(^)(NSString *cardKey))onUnbind {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.commitHandler = onCommit;
        self.unbindHandler = onUnbind;

        if (!self.overlayWindow) {
            if (@available(iOS 13.0, *)) {
                UIWindowScene *scene = nil;
                for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
                    if ([s isKindOfClass:[UIWindowScene class]] && s.activationState == UISceneActivationStateForegroundActive) {
                        scene = (UIWindowScene *)s;
                        break;
                    }
                }
                if (scene) {
                    self.overlayWindow = [[UIWindow alloc] initWithWindowScene:scene];
                } else {
                    self.overlayWindow = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
                }
            } else {
                self.overlayWindow = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
            }
            self.overlayWindow.windowLevel = UIWindowLevelAlert + 100;
            self.overlayWindow.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.55];
            self.overlayWindow.rootViewController = [[UIViewController alloc] init];
        }

        [self.cardView removeFromSuperview];
        [self setupCardViewWithKey:defaultKey];
        [self.overlayWindow makeKeyAndVisible];
    });
}

- (void)setupCardViewWithKey:(NSString *)defaultKey {
    CGFloat screenW = [UIScreen mainScreen].bounds.size.width;
    CGFloat cardW = MIN(screenW - 48, 340);
    CGFloat cardH = 290;

    self.cardView = [[UIView alloc] initWithFrame:CGRectMake(0, 0, cardW, cardH)];
    self.cardView.center = self.overlayWindow.center;
    self.cardView.layer.cornerRadius = 16;
    self.cardView.layer.masksToBounds = YES;

    // 毛玻璃背景
    UIBlurEffect *blur = [UIBlurEffect effectWithStyle:UIBlurEffectStyleSystemMaterialDark];
    UIVisualEffectView *blurView = [[UIVisualEffectView alloc] initWithEffect:blur];
    blurView.frame = self.cardView.bounds;
    [self.cardView addSubview:blurView];

    // 标题
    UILabel *titleLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, 24, cardW - 40, 26)];
    titleLabel.text = [AuthConfig sharedInstance].dialogTitle ?: @"软件授权激活";
    titleLabel.textColor = [UIColor whiteColor];
    titleLabel.font = [UIFont boldSystemFontOfSize:19];
    titleLabel.textAlignment = NSTextAlignmentCenter;
    [self.cardView addSubview:titleLabel];

    // 副标题
    UILabel *subLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, 52, cardW - 40, 18)];
    subLabel.text = [AuthConfig sharedInstance].dialogSubtitle ?: @"请输入授权卡密以解锁完整功能";
    subLabel.textColor = [[UIColor whiteColor] colorWithAlphaComponent:0.7];
    subLabel.font = [UIFont systemFontOfSize:13];
    subLabel.textAlignment = NSTextAlignmentCenter;
    [self.cardView addSubview:subLabel];

    // 卡密输入框 (优先使用传入的 defaultKey，其次读取全局配置的预设卡密)
    NSString *presetKey = (defaultKey && defaultKey.length > 0) ? defaultKey : [AuthConfig sharedInstance].defaultPresetCardKey;
    self.keyTextField = [[UITextField alloc] initWithFrame:CGRectMake(24, 88, cardW - 48, 44)];
    self.keyTextField.placeholder = @"粘贴或输入卡密 (如 VIP-XXXX)";
    self.keyTextField.text = presetKey ?: @"";
    self.keyTextField.layer.cornerRadius = 10;
    self.keyTextField.layer.borderWidth = 1.0;
    self.keyTextField.layer.borderColor = [[UIColor whiteColor] colorWithAlphaComponent:0.2].CGColor;
    self.keyTextField.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.35];
    self.keyTextField.textColor = [UIColor whiteColor];
    self.keyTextField.font = [UIFont systemFontOfSize:14];
    self.keyTextField.textAlignment = NSTextAlignmentCenter;
    self.keyTextField.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
    [self.cardView addSubview:self.keyTextField];

    // 激活确认按钮
    self.commitBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    self.commitBtn.frame = CGRectMake(24, 150, cardW - 48, 44);
    self.commitBtn.layer.cornerRadius = 10;
    self.commitBtn.backgroundColor = [UIColor colorWithRed:0.0 green:0.48 blue:1.0 alpha:1.0];
    [self.commitBtn setTitle:@"立即激活" forState:UIControlStateNormal];
    [self.commitBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.commitBtn.titleLabel.font = [UIFont boldSystemFontOfSize:15];
    [self.commitBtn addTarget:self action:@selector(handleCommit) forControlEvents:UIControlEventTouchUpInside];
    [self.cardView addSubview:self.commitBtn];

    // 设备解绑小按钮
    UIButton *unbindBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    unbindBtn.frame = CGRectMake(24, 204, cardW - 48, 30);
    [unbindBtn setTitle:@"申请设备解绑 / 换绑" forState:UIControlStateNormal];
    [unbindBtn setTitleColor:[[UIColor whiteColor] colorWithAlphaComponent:0.6] forState:UIControlStateNormal];
    unbindBtn.titleLabel.font = [UIFont systemFontOfSize:12];
    [unbindBtn addTarget:self action:@selector(handleUnbind) forControlEvents:UIControlEventTouchUpInside];
    [self.cardView addSubview:unbindBtn];

    // 状态指示器
    self.spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
    self.spinner.color = [UIColor whiteColor];
    self.spinner.center = CGPointMake(cardW - 44, 172);
    self.spinner.hidesWhenStopped = YES;
    [self.cardView addSubview:self.spinner];

    [self.overlayWindow.rootViewController.view addSubview:self.cardView];
}

- (void)handleCommit {
    NSString *key = [self.keyTextField.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (key.length == 0) {
        [self showToast:@"请输入有效卡密"];
        return;
    }
    [self.spinner startAnimating];
    self.commitBtn.enabled = NO;

    if (self.commitHandler) {
        self.commitHandler(key);
    }
}

- (void)handleUnbind {
    NSString *key = [self.keyTextField.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (key.length == 0) {
        [self showToast:@"请输入要解绑的卡密"];
        return;
    }
    if (self.unbindHandler) {
        self.unbindHandler(key);
    }
}

- (void)dismissAuthDialog {
    dispatch_async(dispatch_get_main_queue(), ^{
        [UIView animateWithDuration:0.25 animations:^{
            self.overlayWindow.alpha = 0.0;
        } completion:^(BOOL finished) {
            self.overlayWindow.hidden = YES;
            self.overlayWindow = nil;
        }];
    });
}

- (void)showStatusCapsuleWithText:(NSString *)text {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *keyWindow = [UIApplication sharedApplication].keyWindow;
        if (!keyWindow) return;

        UIView *capsule = [[UIView alloc] initWithFrame:CGRectMake(20, 50, 180, 32)];
        capsule.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.8];
        capsule.layer.cornerRadius = 16;
        capsule.layer.borderWidth = 0.5;
        capsule.layer.borderColor = [[UIColor greenColor] colorWithAlphaComponent:0.5].CGColor;

        UILabel *lbl = [[UILabel alloc] initWithFrame:capsule.bounds];
        lbl.text = [NSString stringWithFormat:@"🟢 %@", text];
        lbl.textColor = [UIColor whiteColor];
        lbl.font = [UIFont systemFontOfSize:11 weight:UIFontWeightMedium];
        lbl.textAlignment = NSTextAlignmentCenter;
        [capsule addSubview:lbl];

        [keyWindow addSubview:capsule];
    });
}

- (void)showToast:(NSString *)message {
    dispatch_async(dispatch_get_main_queue(), ^{
        [self.spinner stopAnimating];
        self.commitBtn.enabled = YES;

        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"授权提示"
                                                                       message:message
                                                                preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
        UIViewController *vc = self.overlayWindow.rootViewController ?: [UIApplication sharedApplication].keyWindow.rootViewController;
        [vc presentViewController:alert animated:YES completion:nil];
    });
}

@end
