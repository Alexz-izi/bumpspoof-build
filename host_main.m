// File: host_main.m
// Purpose: Standalone iOS Host Application for BumpSpoof
// Provides a clean UIKit environment when an external decrypted IPA is not supplied.

#import <UIKit/UIKit.h>
#import <CoreLocation/CoreLocation.h>

@interface HostViewController : UIViewController <CLLocationManagerDelegate>
@property (nonatomic, strong) UILabel *titleLabel;
@property (nonatomic, strong) UILabel *coordLabel;
@property (nonatomic, strong) CLLocationManager *locationManager;
@end

@implementation HostViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor colorWithRed:0.06 green:0.06 blue:0.08 alpha:1.0];

    // Background header card
    UIView *card = [[UIView alloc] initWithFrame:CGRectMake(20, 90, self.view.bounds.size.width - 40, 220)];
    card.backgroundColor = [UIColor colorWithRed:0.10 green:0.10 blue:0.13 alpha:0.95];
    card.layer.cornerRadius = 16;
    card.layer.borderWidth = 1.0;
    card.layer.borderColor = [UIColor colorWithWhite:1.0 alpha:0.12].CGColor;
    card.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    [self.view addSubview:card];

    self.titleLabel = [[UILabel alloc] initWithFrame:CGRectMake(16, 18, card.bounds.size.width - 32, 28)];
    self.titleLabel.text = @"Bump GPX Controller";
    self.titleLabel.font = [UIFont boldSystemFontOfSize:20];
    self.titleLabel.textColor = [UIColor colorWithRed:0.25 green:0.85 blue:0.45 alpha:1.0];
    self.titleLabel.textAlignment = NSTextAlignmentCenter;
    self.titleLabel.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    [card addSubview:self.titleLabel];

    UILabel *descLabel = [[UILabel alloc] initWithFrame:CGRectMake(16, 52, card.bounds.size.width - 32, 40)];
    descLabel.text = @"Standalone Simulation Host\nJoystick and GPX Engine Active";
    descLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
    descLabel.textColor = [UIColor colorWithWhite:0.7 alpha:1.0];
    descLabel.textAlignment = NSTextAlignmentCenter;
    descLabel.numberOfLines = 2;
    descLabel.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    [card addSubview:descLabel];

    self.coordLabel = [[UILabel alloc] initWithFrame:CGRectMake(16, 105, card.bounds.size.width - 32, 85)];
    self.coordLabel.numberOfLines = 0;
    self.coordLabel.textAlignment = NSTextAlignmentCenter;
    self.coordLabel.textColor = [UIColor whiteColor];
    self.coordLabel.font = [UIFont monospacedDigitSystemFontOfSize:13 weight:UIFontWeightRegular];
    self.coordLabel.backgroundColor = [UIColor colorWithWhite:0.04 alpha:0.6];
    self.coordLabel.layer.cornerRadius = 8;
    self.coordLabel.clipsToBounds = YES;
    self.coordLabel.text = @"Listening for CoreLocation updates...";
    self.coordLabel.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    [card addSubview:self.coordLabel];

    // Start listening to CoreLocation updates to display live spoofed readings on the screen
    self.locationManager = [[CLLocationManager alloc] init];
    self.locationManager.delegate = self;
    self.locationManager.desiredAccuracy = kCLLocationAccuracyBestForNavigation;
    [self.locationManager requestWhenInUseAuthorization];
    [self.locationManager startUpdatingLocation];
}

- (void)locationManager:(CLLocationManager *)manager didUpdateLocations:(NSArray<CLLocation *> *)locations {
    CLLocation *loc = locations.lastObject;
    if (!loc) return;
    self.coordLabel.text = [NSString stringWithFormat:
        @"Latitude:  %.6f°\n"
        @"Longitude: %.6f°\n"
        @"Altitude:  %.1f m\n"
        @"Speed:     %.2f m/s\n"
        @"Course:    %.1f°",
        loc.coordinate.latitude,
        loc.coordinate.longitude,
        loc.altitude,
        loc.speed,
        loc.course
    ];
}

@end

@interface HostAppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation HostAppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.rootViewController = [[HostViewController alloc] init];
    [self.window makeKeyAndVisible];
    return YES;
}
@end

int main(int argc, char * argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([HostAppDelegate class]));
    }
}
