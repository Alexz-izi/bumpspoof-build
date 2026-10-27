// File: host_main.m
// Purpose: Full-Screen Interactive Map Host Application for BumpSpoof
// Frameworks: UIKit, CoreLocation, MapKit

#import <UIKit/UIKit.h>
#import <CoreLocation/CoreLocation.h>
#import <MapKit/MapKit.h>

@interface HostViewController : UIViewController <CLLocationManagerDelegate, MKMapViewDelegate>
@property (nonatomic, strong) MKMapView *mapView;
@property (nonatomic, strong) MKPointAnnotation *userPin;
@property (nonatomic, strong) MKPolyline *routePolyline;
@property (nonatomic, strong) CLLocationManager *locationManager;

// Top HUD
@property (nonatomic, strong) UIVisualEffectView *topBar;
@property (nonatomic, strong) UILabel *telemetryLabel;
@property (nonatomic, strong) UIButton *centerButton;
@property (nonatomic, strong) UIButton *mapTypeButton;
@property (nonatomic, strong) UIButton *teleportHintButton;
@property (nonatomic, assign) BOOL followUser;
@end

@implementation HostViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor blackColor];
    self.followUser = YES;

    // 1. Full-Screen Apple Maps View
    self.mapView = [[MKMapView alloc] initWithFrame:self.view.bounds];
    self.mapView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.mapView.delegate = self;
    self.mapView.showsCompass = YES;
    self.mapView.showsScale = YES;
    self.mapView.showsTraffic = NO;
    self.mapView.mapType = MKMapTypeStandard;
    self.mapView.showsUserLocation = YES;
    [self.view addSubview:self.mapView];

    // Initial default coordinate: Paris Eiffel Tower (48.8584, 2.2945)
    double initLat = 48.8584;
    double initLon = 2.2945;
    NSUserDefaults *defs = [NSUserDefaults standardUserDefaults];
    if ([defs objectForKey:@"BumpSpoof_Lat"] != nil) {
        initLat = [defs doubleForKey:@"BumpSpoof_Lat"];
        initLon = [defs doubleForKey:@"BumpSpoof_Lon"];
    }

    CLLocationCoordinate2D initialCoord = CLLocationCoordinate2DMake(initLat, initLon);
    MKCoordinateRegion region = MKCoordinateRegionMakeWithDistance(initialCoord, 1200, 1200);
    [self.mapView setRegion:region animated:NO];

    // 2. Animated User Position Pin
    self.userPin = [[MKPointAnnotation alloc] init];
    self.userPin.coordinate = initialCoord;
    self.userPin.title = @"Simulated Position";
    self.userPin.subtitle = [NSString stringWithFormat:@"%.6f, %.6f", initLat, initLon];
    [self.mapView addAnnotation:self.userPin];

    // 3. Long-Press to Teleport Gesture
    UILongPressGestureRecognizer *lp = [[UILongPressGestureRecognizer alloc] initWithTarget:self action:@selector(handleMapLongPress:)];
    lp.minimumPressDuration = 0.40;
    [self.mapView addGestureRecognizer:lp];

    // 4. Translucent Top Telemetry Bar
    UIBlurEffect *blur = [UIBlurEffect effectWithStyle:UIBlurEffectStyleSystemMaterialDark];
    self.topBar = [[UIVisualEffectView alloc] initWithEffect:blur];
    self.topBar.frame = CGRectMake(16, 54, self.view.bounds.size.width - 32, 64);
    self.topBar.layer.cornerRadius = 16;
    self.topBar.clipsToBounds = YES;
    self.topBar.layer.borderWidth = 1.0;
    self.topBar.layer.borderColor = [UIColor colorWithWhite:1.0 alpha:0.18].CGColor;
    self.topBar.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    [self.view addSubview:self.topBar];

    self.telemetryLabel = [[UILabel alloc] initWithFrame:CGRectMake(14, 8, self.topBar.contentView.bounds.size.width - 120, 48)];
    self.telemetryLabel.numberOfLines = 2;
    self.telemetryLabel.textColor = [UIColor whiteColor];
    self.telemetryLabel.font = [UIFont monospacedDigitSystemFontOfSize:12 weight:UIFontWeightMedium];
    self.telemetryLabel.text = [NSString stringWithFormat:@"Lat: %.6f  Lon: %.6f\nSpeed: 0.0 km/h  Heading: 0°", initLat, initLon];
    self.telemetryLabel.autoresizingMask = UIViewAutoresizingFlexibleWidth;
    [self.topBar.contentView addSubview:self.telemetryLabel];

    // Re-center camera button
    self.centerButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.centerButton.frame = CGRectMake(self.topBar.contentView.bounds.size.width - 100, 14, 42, 36);
    self.centerButton.backgroundColor = [UIColor colorWithRed:0.18 green:0.55 blue:0.95 alpha:0.85];
    self.centerButton.layer.cornerRadius = 10;
    [self.centerButton setTitle:@"Recenter" forState:UIControlStateNormal];
    [self.centerButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.centerButton.titleLabel.font = [UIFont boldSystemFontOfSize:9];
    [self.centerButton addTarget:self action:@selector(recenterCamera) forControlEvents:UIControlEventTouchUpInside];
    self.centerButton.autoresizingMask = UIViewAutoresizingFlexibleLeftMargin;
    [self.topBar.contentView addSubview:self.centerButton];

    // Map style toggle button
    self.mapTypeButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.mapTypeButton.frame = CGRectMake(self.topBar.contentView.bounds.size.width - 52, 14, 42, 36);
    self.mapTypeButton.backgroundColor = [UIColor colorWithWhite:0.25 alpha:0.85];
    self.mapTypeButton.layer.cornerRadius = 10;
    [self.mapTypeButton setTitle:@"Sat" forState:UIControlStateNormal];
    [self.mapTypeButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.mapTypeButton.titleLabel.font = [UIFont boldSystemFontOfSize:10];
    [self.mapTypeButton addTarget:self action:@selector(toggleMapType) forControlEvents:UIControlEventTouchUpInside];
    self.mapTypeButton.autoresizingMask = UIViewAutoresizingFlexibleLeftMargin;
    [self.topBar.contentView addSubview:self.mapTypeButton];

    // Tap-to-teleport guide pill
    UILabel *hintLbl = [[UILabel alloc] initWithFrame:CGRectMake(20, self.view.bounds.size.height - 90, self.view.bounds.size.width - 40, 24)];
    hintLbl.text = @"Hold / long-press anywhere on map to teleport location";
    hintLbl.textColor = [UIColor colorWithWhite:0.85 alpha:0.95];
    hintLbl.font = [UIFont systemFontOfSize:11 weight:UIFontWeightMedium];
    hintLbl.textAlignment = NSTextAlignmentCenter;
    hintLbl.backgroundColor = [UIColor colorWithRed:0.08 green:0.08 blue:0.10 alpha:0.85];
    hintLbl.layer.cornerRadius = 12;
    hintLbl.clipsToBounds = YES;
    hintLbl.layer.borderWidth = 0.8;
    hintLbl.layer.borderColor = [UIColor colorWithWhite:1.0 alpha:0.15].CGColor;
    hintLbl.autoresizingMask = UIViewAutoresizingFlexibleTopMargin | UIViewAutoresizingFlexibleWidth;
    [self.view addSubview:hintLbl];

    // 5. Listen to internal location updates from BumpSpoofManager
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(onLocationUpdated:)
                                                 name:@"BumpSpoofLocationUpdatedNotification"
                                               object:nil];

    // Also register standard CoreLocation updates
    self.locationManager = [[CLLocationManager alloc] init];
    self.locationManager.delegate = self;
    self.locationManager.desiredAccuracy = kCLLocationAccuracyBestForNavigation;
    [self.locationManager requestWhenInUseAuthorization];
    [self.locationManager startUpdatingLocation];
}

- (void)handleMapLongPress:(UILongPressGestureRecognizer *)lp {
    if (lp.state == UIGestureRecognizerStateBegan) {
        CGPoint touchPt = [lp locationInView:self.mapView];
        CLLocationCoordinate2D tappedCoord = [self.mapView convertPoint:touchPt toCoordinateFromView:self.mapView];

        // Teleport spoofed coordinates
        NSUserDefaults *defs = [NSUserDefaults standardUserDefaults];
        [defs setDouble:tappedCoord.latitude forKey:@"BumpSpoof_Lat"];
        [defs setDouble:tappedCoord.longitude forKey:@"BumpSpoof_Lon"];
        [defs synchronize];

        // Notify engine
        [[NSNotificationCenter defaultCenter] postNotificationName:@"BumpSpoofTeleportNotification"
                                                            object:nil
                                                          userInfo:@{
                                                              @"latitude": @(tappedCoord.latitude),
                                                              @"longitude": @(tappedCoord.longitude)
                                                          }];

        self.userPin.coordinate = tappedCoord;
        self.userPin.subtitle = [NSString stringWithFormat:@"%.6f, %.6f", tappedCoord.latitude, tappedCoord.longitude];
        double kmh = 0.0;
        self.telemetryLabel.text = [NSString stringWithFormat:@"Lat: %.6f  Lon: %.6f\nTeleported  Speed: %.1f km/h",
                                    tappedCoord.latitude, tappedCoord.longitude, kmh];

        if (self.followUser) {
            [self.mapView setCenterCoordinate:tappedCoord animated:YES];
        }
    }
}

- (void)recenterCamera {
    self.followUser = YES;
    [self.mapView setCenterCoordinate:self.userPin.coordinate animated:YES];
}

- (void)toggleMapType {
    if (self.mapView.mapType == MKMapTypeStandard) {
        self.mapView.mapType = MKMapTypeHybrid;
        [self.mapTypeButton setTitle:@"Map" forState:UIControlStateNormal];
    } else {
        self.mapView.mapType = MKMapTypeStandard;
        [self.mapTypeButton setTitle:@"Sat" forState:UIControlStateNormal];
    }
}

- (void)onLocationUpdated:(NSNotification *)note {
    NSDictionary *userInfo = note.userInfo;
    if (!userInfo) return;

    double lat = [userInfo[@"latitude"] doubleValue];
    double lon = [userInfo[@"longitude"] doubleValue];
    double speedMPS = [userInfo[@"speed"] doubleValue];
    double course = [userInfo[@"course"] doubleValue];
    double speedKMH = speedMPS * 3.6;

    CLLocationCoordinate2D coord = CLLocationCoordinate2DMake(lat, lon);

    dispatch_async(dispatch_get_main_queue(), ^{
        self.userPin.coordinate = coord;
        self.userPin.subtitle = [NSString stringWithFormat:@"%.6f, %.6f", lat, lon];
        self.telemetryLabel.text = [NSString stringWithFormat:@"Lat: %.6f  Lon: %.6f\nSpeed: %.1f km/h  Course: %.0f°",
                                    lat, lon, speedKMH, course];

        if (self.followUser && (speedMPS > 0.05)) {
            [self.mapView setCenterCoordinate:coord animated:YES];
        }
    });
}

#pragma mark - MapView Delegate

- (MKAnnotationView *)mapView:(MKMapView *)mapView viewForAnnotation:(id<MKAnnotation>)annotation {
    if ([annotation isKindOfClass:[MKPointAnnotation class]]) {
        static NSString *const pinID = @"UserSimPin";
        MKMarkerAnnotationView *view = (MKMarkerAnnotationView *)[mapView dequeueReusableAnnotationViewWithIdentifier:pinID];
        if (!view) {
            view = [[MKMarkerAnnotationView alloc] initWithAnnotation:annotation reuseIdentifier:pinID];
            view.canShowCallout = YES;
            view.animatesWhenAdded = YES;
            view.markerTintColor = [UIColor colorWithRed:0.18 green:0.82 blue:0.42 alpha:1.0];
            view.glyphTintColor = [UIColor blackColor];
            view.glyphText = @"📍";
        } else {
            view.annotation = annotation;
        }
        return view;
    }
    return nil;
}

- (MKOverlayRenderer *)mapView:(MKMapView *)mapView rendererForOverlay:(id<MKOverlay>)overlay {
    if ([overlay isKindOfClass:[MKPolyline class]]) {
        MKPolylineRenderer *renderer = [[MKPolylineRenderer alloc] initWithPolyline:(MKPolyline *)overlay];
        renderer.strokeColor = [UIColor colorWithRed:0.25 green:0.75 blue:1.0 alpha:0.85];
        renderer.lineWidth = 4.0;
        return renderer;
    }
    return nil;
}

- (void)locationManager:(CLLocationManager *)manager didUpdateLocations:(NSArray<CLLocation *> *)locations {
    CLLocation *loc = locations.lastObject;
    if (!loc) return;
    self.userPin.coordinate = loc.coordinate;
    double kmh = loc.speed >= 0 ? loc.speed * 3.6 : 0.0;
    self.telemetryLabel.text = [NSString stringWithFormat:@"Lat: %.6f  Lon: %.6f\nSpeed: %.1f km/h  Course: %.0f°",
                                loc.coordinate.latitude, loc.coordinate.longitude, kmh, loc.course];
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
