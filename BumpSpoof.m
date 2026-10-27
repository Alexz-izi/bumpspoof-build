// File: BumpSpoof.m
// Target: arm64-apple-ios15.0 (compatible through iOS 26.5)
// Features: Touch-Drag Analog Joystick + GPX Route Engine + BSSID/Carrier Spoof + Anti-Simulation Hooks + Fishhook Dynamic Rebinding
// Frameworks: Foundation, UIKit, CoreLocation, QuartzCore, CoreTelephony, SystemConfiguration, NetworkExtension

#import <Foundation/Foundation.h>
#import <CoreLocation/CoreLocation.h>
#import <UIKit/UIKit.h>
#import <CoreGraphics/CoreGraphics.h>
#import <QuartzCore/QuartzCore.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <CoreTelephony/CTCarrier.h>
#import <SystemConfiguration/CaptiveNetwork.h>
#import <NetworkExtension/NetworkExtension.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <dlfcn.h>
#import <stdlib.h>
#import <string.h>
#import <stdbool.h>
#import <math.h>

typedef struct mach_header_64 mach_header_64_t;
typedef struct segment_command_64 segment_command_64_t;
typedef struct section_64 section_64_t;
typedef struct nlist_64 nlist_64_t;

#pragma mark - Embedded Dynamic Symbol Rebinding (Fishhook Engine)

struct rebinding {
    const char *name;
    void *replacement;
    void **replaced;
};

struct rebindings_entry {
    struct rebinding *rebindings;
    size_t rebindings_nel;
    struct rebindings_entry *next;
};

static struct rebindings_entry *_rebindings_head;

static int bs_prepend_rebindings(struct rebindings_entry **head_ptr,
                                 struct rebinding rebindings[],
                                 size_t nel) {
    struct rebindings_entry *new_entry = (struct rebindings_entry *)malloc(sizeof(struct rebindings_entry));
    if (!new_entry) return -1;
    new_entry->rebindings = (struct rebinding *)malloc(sizeof(struct rebinding) * nel);
    if (!new_entry->rebindings) {
        free(new_entry);
        return -1;
    }
    memcpy(new_entry->rebindings, rebindings, sizeof(struct rebinding) * nel);
    new_entry->rebindings_nel = nel;
    new_entry->next = *head_ptr;
    *head_ptr = new_entry;
    return 0;
}

static void bs_perform_rebinding_with_section(struct rebindings_entry *rebindings,
                                              section_64_t *sect,
                                              intptr_t slide,
                                              nlist_64_t *symtab,
                                              char *strtab,
                                              uint32_t *indirect_symtab) {
    uint32_t *indirect_symbol_indices = indirect_symtab + sect->reserved1;
    void **indirect_symbol_bindings = (void **)((uintptr_t)slide + sect->addr);
    for (uint32_t i = 0; i < sect->size / sizeof(void *); i++) {
        uint32_t symtab_index = indirect_symbol_indices[i];
        if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL ||
            symtab_index == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) {
            continue;
        }
        uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
        char *symbol_name = strtab + strtab_offset;
        bool symbol_name_longer_than_one = symbol_name[0] && symbol_name[1];
        struct rebindings_entry *cur = rebindings;
        while (cur) {
            for (uint32_t j = 0; j < cur->rebindings_nel; j++) {
                if (symbol_name_longer_than_one && strcmp(&symbol_name[1], cur->rebindings[j].name) == 0) {
                    if (cur->rebindings[j].replaced != NULL &&
                        indirect_symbol_bindings[i] != cur->rebindings[j].replacement) {
                        *(cur->rebindings[j].replaced) = indirect_symbol_bindings[i];
                    }
                    indirect_symbol_bindings[i] = cur->rebindings[j].replacement;
                    goto next_symbol;
                }
            }
            cur = cur->next;
        }
    next_symbol:;
    }
}

static void bs_rebind_symbols_for_image(struct rebindings_entry *rebindings,
                                        const struct mach_header *header,
                                        intptr_t slide) {
    Dl_info info;
    if (dladdr(header, &info) == 0) return;

    if (header->magic != MH_MAGIC_64) return;
    const mach_header_64_t *header64 = (const mach_header_64_t *)header;

    segment_command_64_t *cur_seg_cmd;
    segment_command_64_t *linkedit_segment = NULL;
    struct symtab_command *symtab_cmd = NULL;
    struct dysymtab_command *dysymtab_cmd = NULL;

    uintptr_t cur = (uintptr_t)header + sizeof(mach_header_64_t);
    for (uint32_t i = 0; i < header64->ncmds; i++) {
        struct load_command *lc = (struct load_command *)cur;
        if (lc->cmd == LC_SEGMENT_64) {
            cur_seg_cmd = (segment_command_64_t *)cur;
            if (strcmp(cur_seg_cmd->segname, SEG_LINKEDIT) == 0) {
                linkedit_segment = cur_seg_cmd;
            }
        } else if (lc->cmd == LC_SYMTAB) {
            symtab_cmd = (struct symtab_command *)cur;
        } else if (lc->cmd == LC_DYSYMTAB) {
            dysymtab_cmd = (struct dysymtab_command *)cur;
        }
        cur += lc->cmdsize;
    }

    if (!symtab_cmd || !dysymtab_cmd || !linkedit_segment || dysymtab_cmd->nindirectsyms == 0) return;

    uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
    nlist_64_t *symtab = (nlist_64_t *)(linkedit_base + symtab_cmd->symoff);
    char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);
    uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);

    cur = (uintptr_t)header + sizeof(mach_header_64_t);
    for (uint32_t i = 0; i < header64->ncmds; i++) {
        struct load_command *lc = (struct load_command *)cur;
        if (lc->cmd == LC_SEGMENT_64) {
            cur_seg_cmd = (segment_command_64_t *)cur;
            if (strcmp(cur_seg_cmd->segname, SEG_DATA) != 0 &&
                strcmp(cur_seg_cmd->segname, "__DATA_CONST") != 0) {
                cur += lc->cmdsize;
                continue;
            }
            for (uint32_t j = 0; j < cur_seg_cmd->nsects; j++) {
                section_64_t *sect = (section_64_t *)(cur + sizeof(segment_command_64_t)) + j;
                uint32_t section_type = sect->flags & SECTION_TYPE;
                if (section_type == S_LAZY_SYMBOL_POINTERS ||
                    section_type == S_NON_LAZY_SYMBOL_POINTERS) {
                    bs_perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab);
                }
            }
        }
        cur += lc->cmdsize;
    }
}

static void _bs_rebind_symbols_for_image(const struct mach_header *header, intptr_t slide) {
    bs_rebind_symbols_for_image(_rebindings_head, header, slide);
}

static int bs_rebind_symbols(struct rebinding rebindings[], size_t nel) {
    int prep = bs_prepend_rebindings(&_rebindings_head, rebindings, nel);
    if (prep < 0) return prep;
    if (!_rebindings_head->next) {
        _dyld_register_func_for_add_image(_bs_rebind_symbols_for_image);
    } else {
        uint32_t c = _dyld_image_count();
        for (uint32_t i = 0; i < c; i++) {
            _bs_rebind_symbols_for_image(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
        }
    }
    return 0;
}

#pragma mark - Constants & Geodesic Mathematics

static NSString *const kPrefEnabledKey = @"BumpSpoof_Enabled";
static NSString *const kPrefLatKey     = @"BumpSpoof_Lat";
static NSString *const kPrefLonKey     = @"BumpSpoof_Lon";
static NSString *const kPrefSpeedKey   = @"BumpSpoof_Speed";

static NSString *const kSpoofedSSID        = @"Livebox-4F8A";
static NSString *const kSpoofedCarrierName = @"Orange F";
static NSString *const kSpoofedMCC         = @"208";
static NSString *const kSpoofedMNC         = @"01";
static NSString *const kSpoofedISOCountry  = @"fr";

static double BSDegToRad(double deg) { return deg * (M_PI / 180.0); }
static double BSRadToDeg(double rad) { return rad * (180.0 / M_PI); }

static double BSHaversineDistanceMeters(double lat1, double lon1, double lat2, double lon2) {
    const double R = 6371000.0;
    double dLat = BSDegToRad(lat2 - lat1);
    double dLon = BSDegToRad(lon2 - lon1);
    double a = sin(dLat / 2.0) * sin(dLat / 2.0) +
               cos(BSDegToRad(lat1)) * cos(BSDegToRad(lat2)) *
               sin(dLon / 2.0) * sin(dLon / 2.0);
    double c = 2.0 * atan2(sqrt(a), sqrt(fmax(0.0, 1.0 - a)));
    return R * c;
}

static double BSForwardAzimuthDegrees(double lat1, double lon1, double lat2, double lon2) {
    double phi1 = BSDegToRad(lat1);
    double phi2 = BSDegToRad(lat2);
    double dLon = BSDegToRad(lon2 - lon1);
    double y = sin(dLon) * cos(phi2);
    double x = cos(phi1) * sin(phi2) - sin(phi1) * cos(phi2) * cos(dLon);
    double brng = BSRadToDeg(atan2(y, x));
    return fmod(brng + 360.0, 360.0);
}

static void BSProjectCoordinate(double lat, double lon, double bearingDeg, double distanceMeters, double *outLat, double *outLon) {
    const double R = 6371000.0;
    double angDist = distanceMeters / R;
    double brng = BSDegToRad(bearingDeg);
    double phi1 = BSDegToRad(lat);
    double lam1 = BSDegToRad(lon);

    double sinPhi2 = sin(phi1) * cos(angDist) + cos(phi1) * sin(angDist) * cos(brng);
    if (sinPhi2 > 1.0) sinPhi2 = 1.0;
    if (sinPhi2 < -1.0) sinPhi2 = -1.0;
    double phi2 = asin(sinPhi2);

    double y = sin(brng) * sin(angDist) * cos(phi1);
    double x = cos(angDist) - sin(phi1) * sin(phi2);
    double lam2 = lam1 + atan2(y, x);

    *outLat = BSRadToDeg(phi2);
    *outLon = BSRadToDeg(lam2);
}

#pragma mark - Analog Touch-Drag Joystick View

@interface BSJoystickView : UIView
@property (nonatomic, strong) UIView *knobView;
@property (nonatomic, assign) double magnitude;
@property (nonatomic, assign) double bearingDegrees;
@property (nonatomic, assign) BOOL active;
@property (nonatomic, copy) void (^onVectorChanged)(double bearingDegrees, double magnitude, BOOL active);
@property (nonatomic, strong) UIPanGestureRecognizer *dragPanGesture;
@end

@implementation BSJoystickView

- (instancetype)initWithFrame:(CGRect)frame {
    if (self = [super initWithFrame:frame]) {
        self.backgroundColor = [UIColor colorWithRed:0.06 green:0.06 blue:0.08 alpha:0.92];
        self.layer.cornerRadius = frame.size.width / 2.0;
        self.layer.borderWidth = 1.5;
        self.layer.borderColor = [UIColor colorWithRed:0.20 green:0.85 blue:0.45 alpha:0.75].CGColor;
        self.clipsToBounds = NO;

        // Crosshairs
        CAShapeLayer *crosshair = [CAShapeLayer layer];
        UIBezierPath *path = [UIBezierPath bezierPath];
        CGFloat mid = frame.size.width / 2.0;
        [path moveToPoint:CGPointMake(mid, 10)];
        [path addLineToPoint:CGPointMake(mid, frame.size.height - 10)];
        [path moveToPoint:CGPointMake(10, mid)];
        [path addLineToPoint:CGPointMake(frame.size.width - 10, mid)];
        crosshair.path = path.CGPath;
        crosshair.strokeColor = [UIColor colorWithWhite:1.0 alpha:0.15].CGColor;
        crosshair.lineWidth = 1.0;
        [self.layer addSublayer:crosshair];

        // North mark
        UILabel *nLbl = [[UILabel alloc] initWithFrame:CGRectMake(mid - 10, 2, 20, 12)];
        nLbl.text = @"N";
        nLbl.textAlignment = NSTextAlignmentCenter;
        nLbl.font = [UIFont boldSystemFontOfSize:9];
        nLbl.textColor = [UIColor colorWithRed:0.25 green:0.90 blue:0.50 alpha:0.9];
        [self addSubview:nLbl];

        // Draggable knob
        CGFloat knobSize = frame.size.width * 0.42;
        _knobView = [[UIView alloc] initWithFrame:CGRectMake(0, 0, knobSize, knobSize)];
        _knobView.center = CGPointMake(mid, mid);
        _knobView.backgroundColor = [UIColor colorWithRed:0.20 green:0.82 blue:0.45 alpha:0.95];
        _knobView.layer.cornerRadius = knobSize / 2.0;
        _knobView.layer.shadowColor = [UIColor blackColor].CGColor;
        _knobView.layer.shadowOpacity = 0.5;
        _knobView.layer.shadowRadius = 4.0;
        _knobView.layer.shadowOffset = CGSizeMake(0, 2);
        _knobView.userInteractionEnabled = NO;
        [self addSubview:_knobView];

        // Reposition pan gesture on outer edge
        _dragPanGesture = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(handleRepositionPan:)];
        _dragPanGesture.maximumNumberOfTouches = 1;
        [self addGestureRecognizer:_dragPanGesture];
    }
    return self;
}

- (void)handleRepositionPan:(UIPanGestureRecognizer *)pan {
    CGPoint loc = [pan locationInView:self];
    CGFloat radius = self.bounds.size.width / 2.0;
    CGFloat distFromCenter = hypot(loc.x - radius, loc.y - radius);

    // If touch began in the outer rim (> 75% radius), move the entire joystick view
    if (distFromCenter > (radius * 0.72) || pan.state == UIGestureRecognizerStateChanged) {
        CGPoint translation = [pan translationInView:self.superview];
        self.center = CGPointMake(self.center.x + translation.x, self.center.y + translation.y);
        [pan setTranslation:CGPointZero inView:self.superview];
    }
}

- (void)updateWithTouchPoint:(CGPoint)pt {
    CGFloat radius = self.bounds.size.width / 2.0;
    CGPoint center = CGPointMake(radius, radius);
    CGFloat dx = pt.x - center.x;
    CGFloat dy = pt.y - center.y;
    CGFloat dist = hypot(dx, dy);
    CGFloat maxDist = radius - (self.knobView.bounds.size.width / 2.0) - 4.0;

    if (dist > maxDist && dist > 0.0) {
        dx = (dx / dist) * maxDist;
        dy = (dy / dist) * maxDist;
        dist = maxDist;
    }

    self.knobView.center = CGPointMake(center.x + dx, center.y + dy);
    self.magnitude = (maxDist > 0.0) ? fmin(1.0, dist / maxDist) : 0.0;

    double rad = atan2(dx, -dy);
    double deg = BSRadToDeg(rad);
    self.bearingDegrees = fmod(deg + 360.0, 360.0);
    self.active = (self.magnitude > 0.04);

    if (self.onVectorChanged) {
        self.onVectorChanged(self.bearingDegrees, self.magnitude, self.active);
    }
}

- (void)resetKnob {
    CGFloat radius = self.bounds.size.width / 2.0;
    [UIView animateWithDuration:0.16 delay:0 options:UIViewAnimationOptionCurveEaseOut animations:^{
        self.knobView.center = CGPointMake(radius, radius);
    } completion:nil];
    self.magnitude = 0.0;
    self.active = NO;
    if (self.onVectorChanged) {
        self.onVectorChanged(self.bearingDegrees, 0.0, NO);
    }
}

- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    UITouch *t = [touches anyObject];
    CGPoint pt = [t locationInView:self];
    CGFloat radius = self.bounds.size.width / 2.0;
    CGFloat dist = hypot(pt.x - radius, pt.y - radius);
    if (dist <= radius * 0.72) {
        [self updateWithTouchPoint:pt];
    }
}

- (void)touchesMoved:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    UITouch *t = [touches anyObject];
    CGPoint pt = [t locationInView:self];
    [self updateWithTouchPoint:pt];
}

- (void)touchesEnded:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    [self resetKnob];
}

- (void)touchesCancelled:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    [self resetKnob];
}

@end

#pragma mark - Waypoint Model & GPX XML Parser

@interface BSWaypoint : NSObject
@property (nonatomic, assign) double latitude;
@property (nonatomic, assign) double longitude;
@property (nonatomic, assign) double elevation;
+ (instancetype)waypointWithLat:(double)lat lon:(double)lon ele:(double)ele;
@end

@implementation BSWaypoint
+ (instancetype)waypointWithLat:(double)lat lon:(double)lon ele:(double)ele {
    BSWaypoint *wp = [[BSWaypoint alloc] init];
    wp.latitude = lat;
    wp.longitude = lon;
    wp.elevation = ele;
    return wp;
}
@end

@interface BSGPXParser : NSObject <NSXMLParserDelegate>
@property (nonatomic, strong) NSMutableArray<BSWaypoint *> *waypoints;
@property (nonatomic, strong) BSWaypoint *currentWaypoint;
@property (nonatomic, strong) NSMutableString *currentText;
@property (nonatomic, assign) BOOL insideEle;
- (NSArray<BSWaypoint *> *)parseGPXData:(NSData *)data;
@end

@implementation BSGPXParser

- (NSArray<BSWaypoint *> *)parseGPXData:(NSData *)data {
    if (!data || data.length == 0) return @[];
    self.waypoints = [NSMutableArray array];
    NSXMLParser *parser = [[NSXMLParser alloc] initWithData:data];
    parser.delegate = self;
    [parser parse];
    return [self.waypoints copy];
}

- (void)parser:(NSXMLParser *)parser didStartElement:(NSString *)elementName
  namespaceURI:(NSString *)namespaceURI qualifiedName:(NSString *)qName
    attributes:(NSDictionary<NSString *,NSString *> *)attributeDict {
    if ([elementName isEqualToString:@"trkpt"] ||
        [elementName isEqualToString:@"rtept"] ||
        [elementName isEqualToString:@"wpt"]) {
        double lat = [attributeDict[@"lat"] doubleValue];
        double lon = [attributeDict[@"lon"] doubleValue];
        self.currentWaypoint = [BSWaypoint waypointWithLat:lat lon:lon ele:35.0];
    } else if ([elementName isEqualToString:@"ele"] && self.currentWaypoint) {
        self.insideEle = YES;
        self.currentText = [NSMutableString string];
    }
}

- (void)parser:(NSXMLParser *)parser foundCharacters:(NSString *)string {
    if (self.insideEle && self.currentText) {
        [self.currentText appendString:string];
    }
}

- (void)parser:(NSXMLParser *)parser didEndElement:(NSString *)elementName
  namespaceURI:(NSString *)namespaceURI qualifiedName:(NSString *)qName {
    if ([elementName isEqualToString:@"ele"] && self.currentWaypoint) {
        self.currentWaypoint.elevation = [self.currentText doubleValue];
        self.insideEle = NO;
        self.currentText = nil;
    } else if (([elementName isEqualToString:@"trkpt"] ||
                [elementName isEqualToString:@"rtept"] ||
                [elementName isEqualToString:@"wpt"]) && self.currentWaypoint) {
        [self.waypoints addObject:self.currentWaypoint];
        self.currentWaypoint = nil;
    }
}

@end

#pragma mark - Passthrough Window for Unobtrusive Floating Overlay

@interface BSPassthroughWindow : UIWindow
@end

@implementation BSPassthroughWindow
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *hitView = [super hitTest:point withEvent:event];
    if (hitView == self || hitView == self.rootViewController.view) {
        return nil;
    }
    return hitView;
}
@end

#pragma mark - Spoof Manager, Engine & Delegate Registry

@interface BumpSpoofManager : NSObject <UITextFieldDelegate>
@property (nonatomic, assign) BOOL enabled;
@property (nonatomic, assign) BOOL routePlaying;
@property (nonatomic, assign) BOOL joystickActive;
@property (nonatomic, assign) double joystickBearing;
@property (nonatomic, assign) double joystickMagnitude;

@property (nonatomic, assign) double latitude;
@property (nonatomic, assign) double longitude;
@property (nonatomic, assign) double altitude;
@property (nonatomic, assign) double currentCourse;
@property (nonatomic, assign) double currentSpeed;
@property (nonatomic, assign) double targetSpeedMPS;

// Atomic recursion guard to prevent double-jittering during delegate broadcast
@property (nonatomic, assign) BOOL isBroadcasting;

@property (nonatomic, strong) NSHashTable<CLLocationManager *> *activeManagers;
@property (nonatomic, strong) NSArray<BSWaypoint *> *routeWaypoints;
@property (nonatomic, assign) NSUInteger currentWaypointIndex;
@property (nonatomic, strong) NSTimer *movementTimer;
@property (nonatomic, assign) CFAbsoluteTime lastTickTime;

// Overlay Window & UI Elements
@property (nonatomic, strong) BSPassthroughWindow *overlayWindow;
@property (nonatomic, strong) UIButton *floatingButton;
@property (nonatomic, strong) UIButton *joyToggleButton;
@property (nonatomic, strong) BSJoystickView *floatingJoystick;
@property (nonatomic, strong) UIView *panelView;
@property (nonatomic, strong) UITextField *latField;
@property (nonatomic, strong) UITextField *lonField;
@property (nonatomic, strong) UISwitch *toggleSwitch;
@property (nonatomic, strong) UISegmentedControl *speedSegment;
@property (nonatomic, strong) UIButton *playRouteButton;
@property (nonatomic, strong) UILabel *statusLabel;

+ (instancetype)shared;
- (CLLocation *)spoofedLocationFromReal:(CLLocation *)realLoc;
- (void)registerManager:(CLLocationManager *)mgr;
- (void)setupUI;
@end

@implementation BumpSpoofManager

+ (instancetype)shared {
    static BumpSpoofManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[BumpSpoofManager alloc] init];
    });
    return instance;
}

- (instancetype)init {
    if (self = [super init]) {
        _activeManagers = [NSHashTable weakObjectsHashTable];
        _altitude = 35.0;
        _currentCourse = 0.0;
        _currentSpeed = 0.0;
        _isBroadcasting = NO;

        NSUserDefaults *defs = [NSUserDefaults standardUserDefaults];
        if ([defs objectForKey:kPrefEnabledKey] == nil) {
            _enabled = YES;
            _latitude = 48.8584; // Paris / Eiffel default
            _longitude = 2.2945;
            _targetSpeedMPS = 1.42;
            [self savePrefs];
        } else {
            _enabled = [defs boolForKey:kPrefEnabledKey];
            _latitude = [defs doubleForKey:kPrefLatKey];
            _longitude = [defs doubleForKey:kPrefLonKey];
            _targetSpeedMPS = [defs doubleForKey:kPrefSpeedKey];
            if (_targetSpeedMPS <= 0.1) _targetSpeedMPS = 1.42;
        }
        [self loadDefaultOrSavedGPX];
        [self startEngineTimer];
    }
    return self;
}

- (void)savePrefs {
    NSUserDefaults *defs = [NSUserDefaults standardUserDefaults];
    [defs setBool:self.enabled forKey:kPrefEnabledKey];
    [defs setDouble:self.latitude forKey:kPrefLatKey];
    [defs setDouble:self.longitude forKey:kPrefLonKey];
    [defs setDouble:self.targetSpeedMPS forKey:kPrefSpeedKey];
}

- (void)registerManager:(CLLocationManager *)mgr {
    if (!mgr) return;
    @synchronized (self.activeManagers) {
        [self.activeManagers addObject:mgr];
    }
}

- (void)startEngineTimer {
    if (self.movementTimer) return;
    self.lastTickTime = CFAbsoluteTimeGetCurrent();
    // 5 Hz tick rate
    self.movementTimer = [NSTimer scheduledTimerWithTimeInterval:0.20
                                                          target:self
                                                        selector:@selector(tickMovement:)
                                                        userInfo:nil
                                                         repeats:YES];
    [[NSRunLoop mainRunLoop] addTimer:self.movementTimer forMode:NSRunLoopCommonModes];
}

- (void)loadDefaultOrSavedGPX {
    NSString *docsDir = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    NSString *gpxPath = [docsDir stringByAppendingPathComponent:@"route.gpx"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:gpxPath]) {
        NSData *data = [NSData dataWithContentsOfFile:gpxPath];
        NSArray<BSWaypoint *> *parsed = [[[BSGPXParser alloc] init] parseGPXData:data];
        if (parsed.count >= 2) {
            self.routeWaypoints = parsed;
            self.currentWaypointIndex = 0;
            return;
        }
    }
    [self rebuildFallbackLoopAroundLat:self.latitude lon:self.longitude];
}

- (void)rebuildFallbackLoopAroundLat:(double)baseLat lon:(double)baseLon {
    NSMutableArray<BSWaypoint *> *loop = [NSMutableArray array];
    const double offsets[8][2] = {
        { 0.0000,  0.0000},
        { 0.0012,  0.0000},
        { 0.0012,  0.0016},
        { 0.0024,  0.0016},
        { 0.0024,  0.0000},
        { 0.0012, -0.0014},
        { 0.0000, -0.0014},
        { 0.0000,  0.0000}
    };
    for (int i = 0; i < 8; i++) {
        [loop addObject:[BSWaypoint waypointWithLat:baseLat + offsets[i][0]
                                                lon:baseLon + offsets[i][1]
                                                ele:35.0]];
    }
    self.routeWaypoints = [loop copy];
    self.currentWaypointIndex = 0;
}

- (void)importGPXFromClipboard {
    NSString *clip = [UIPasteboard generalPasteboard].string;
    if (!clip || ![clip containsString:@"<gpx"]) {
        self.statusLabel.text = @"Clipboard has no <gpx> XML";
        return;
    }
    NSData *data = [clip dataUsingEncoding:NSUTF8StringEncoding];
    NSArray<BSWaypoint *> *parsed = [[[BSGPXParser alloc] init] parseGPXData:data];
    if (parsed.count >= 2) {
        self.routeWaypoints = parsed;
        self.currentWaypointIndex = 0;
        self.latitude = parsed.firstObject.latitude;
        self.longitude = parsed.firstObject.longitude;
        self.altitude = parsed.firstObject.elevation;
        self.latField.text = [NSString stringWithFormat:@"%.6f", self.latitude];
        self.lonField.text = [NSString stringWithFormat:@"%.6f", self.longitude];

        NSString *docsDir = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        [data writeToFile:[docsDir stringByAppendingPathComponent:@"route.gpx"] atomically:YES];
        self.statusLabel.text = [NSString stringWithFormat:@"Loaded %lu GPX pts", (unsigned long)parsed.count];
        [self savePrefs];
    } else {
        self.statusLabel.text = @"Invalid GPX (<2 pts)";
    }
}

- (void)toggleRoutePlayback {
    self.routePlaying = !self.routePlaying;
    if (self.routePlaying) {
        if (self.routeWaypoints.count < 2) {
            [self rebuildFallbackLoopAroundLat:self.latitude lon:self.longitude];
        }
        self.lastTickTime = CFAbsoluteTimeGetCurrent();
        [self.playRouteButton setTitle:@"Pause GPX Walk" forState:UIControlStateNormal];
        self.playRouteButton.backgroundColor = [UIColor colorWithRed:0.85 green:0.45 blue:0.15 alpha:1.0];
        self.statusLabel.text = [NSString stringWithFormat:@"GPX Walk (%lu pts)", (unsigned long)self.routeWaypoints.count];
    } else {
        self.currentSpeed = 0.0;
        [self.playRouteButton setTitle:@"Start GPX Walk" forState:UIControlStateNormal];
        self.playRouteButton.backgroundColor = [UIColor colorWithRed:0.20 green:0.52 blue:0.90 alpha:1.0];
        self.statusLabel.text = @"Static Hold";
    }
}

- (void)tickMovement:(NSTimer *)timer {
    CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();
    double dt = now - self.lastTickTime;
    if (dt <= 0.0 || dt > 2.0) dt = 0.20;
    self.lastTickTime = now;

    if (!self.enabled) return;

    BOOL moved = NO;

    // 1. Live Analog Joystick Steering
    if (self.joystickActive && self.joystickMagnitude > 0.04) {
        if (self.routePlaying) {
            [self toggleRoutePlayback];
        }
        double jitterFactor = 0.95 + ((double)arc4random() / UINT32_MAX) * 0.10;
        double effectiveSpeed = self.targetSpeedMPS * self.joystickMagnitude * jitterFactor;
        double stepDist = effectiveSpeed * dt;

        double newLat = self.latitude;
        double newLon = self.longitude;
        BSProjectCoordinate(self.latitude, self.longitude, self.joystickBearing, stepDist, &newLat, &newLon);

        self.latitude = newLat;
        self.longitude = newLon;
        self.currentCourse = self.joystickBearing;
        self.currentSpeed = effectiveSpeed;
        moved = YES;
        self.statusLabel.text = [NSString stringWithFormat:@"Steer %.0f° @ %.1fm/s", self.currentCourse, self.currentSpeed];
    }
    // 2. Automated GPX Route Playback
    else if (self.routePlaying && self.routeWaypoints.count >= 2) {
        double jitterFactor = 0.94 + ((double)arc4random() / UINT32_MAX) * 0.12;
        double stepSpeed = self.targetSpeedMPS * jitterFactor;
        double stepDistance = stepSpeed * dt;

        NSUInteger nextIdx = (self.currentWaypointIndex + 1) % self.routeWaypoints.count;
        BSWaypoint *targetWP = self.routeWaypoints[nextIdx];

        double distToTarget = BSHaversineDistanceMeters(self.latitude, self.longitude, targetWP.latitude, targetWP.longitude);
        self.currentCourse = BSForwardAzimuthDegrees(self.latitude, self.longitude, targetWP.latitude, targetWP.longitude);
        self.currentSpeed = stepSpeed;

        if (distToTarget <= stepDistance) {
            self.latitude = targetWP.latitude;
            self.longitude = targetWP.longitude;
            self.altitude = targetWP.elevation;
            self.currentWaypointIndex = nextIdx;
        } else {
            double fraction = stepDistance / distToTarget;
            self.latitude += (targetWP.latitude - self.latitude) * fraction;
            self.longitude += (targetWP.longitude - self.longitude) * fraction;
            self.altitude += (targetWP.elevation - self.altitude) * fraction;
        }
        moved = YES;
    } else {
        self.currentSpeed = 0.0;
    }

    if (moved) {
        if (self.panelView && !self.panelView.hidden && !self.latField.isFirstResponder && !self.lonField.isFirstResponder) {
            self.latField.text = [NSString stringWithFormat:@"%.6f", self.latitude];
            self.lonField.text = [NSString stringWithFormat:@"%.6f", self.longitude];
        }
        [self broadcastLocationToActiveDelegates];
    }
}

- (void)broadcastLocationToActiveDelegates {
    CLLocation *simulatedLoc = [self spoofedLocationFromReal:nil];
    NSArray<CLLocationManager *> *managers = nil;
    @synchronized (self.activeManagers) {
        managers = [self.activeManagers allObjects];
    }
    
    // Set guard flag to prevent delegate hook re-jittering
    self.isBroadcasting = YES;
    for (CLLocationManager *mgr in managers) {
        id<CLLocationManagerDelegate> del = mgr.delegate;
        if (del) {
            if ([del respondsToSelector:@selector(locationManager:didUpdateLocations:)]) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    [del locationManager:mgr didUpdateLocations:@[simulatedLoc]];
                });
            } else if ([del respondsToSelector:@selector(locationManager:didUpdateToLocation:fromLocation:)]) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    [del locationManager:mgr didUpdateToLocation:simulatedLoc fromLocation:simulatedLoc];
                });
            }
        }
    }
    self.isBroadcasting = NO;
}

- (CLLocation *)spoofedLocationFromReal:(CLLocation *)realLoc {
    // Realistic GPS Gaussian noise
    double jitterLat = ((double)arc4random() / UINT32_MAX - 0.5) * 0.000014;
    double jitterLon = ((double)arc4random() / UINT32_MAX - 0.5) * 0.000014;
    CLLocationCoordinate2D coord = CLLocationCoordinate2DMake(self.latitude + jitterLat, self.longitude + jitterLon);

    CLLocationDistance alt = self.altitude > 0 ? self.altitude : (realLoc ? realLoc.altitude : 35.0);
    CLLocationAccuracy hAcc = 3.8 + (((double)arc4random() / UINT32_MAX) * 1.4);
    CLLocationAccuracy vAcc = 2.5 + (((double)arc4random() / UINT32_MAX) * 1.5);
    BOOL isMoving = (self.routePlaying || self.joystickActive);
    CLLocationDirection course = isMoving ? self.currentCourse : (realLoc ? realLoc.course : 0.0);
    CLLocationSpeed speed = isMoving ? self.currentSpeed : 0.0;

    if (@available(iOS 13.4, *)) {
        return [[CLLocation alloc] initWithCoordinate:coord
                                             altitude:alt
                                   horizontalAccuracy:hAcc
                                     verticalAccuracy:vAcc
                                               course:course
                                       courseAccuracy:3.8
                                                speed:speed
                                         speedAccuracy:0.25
                                             timestamp:[NSDate date]];
    }
    return [[CLLocation alloc] initWithCoordinate:coord
                                         altitude:alt
                               horizontalAccuracy:hAcc
                                 verticalAccuracy:vAcc
                                           course:course
                                            speed:speed
                                        timestamp:[NSDate date]];
}

#pragma mark - Scene-Aware Floating HUD & Pass-Through Overlay Window

- (UIWindowScene *)activeWindowScene {
    for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
        if ([scene isKindOfClass:[UIWindowScene class]] &&
            (scene.activationState == UISceneActivationStateForegroundActive ||
             scene.activationState == UISceneActivationStateForegroundInactive)) {
            return (UIWindowScene *)scene;
        }
    }
    return nil;
}

- (void)setupUI {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindowScene *ws = [self activeWindowScene];
        if (!ws) {
            [self performSelector:@selector(setupUI) withObject:nil afterDelay:1.0];
            return;
        }

        if (!self.overlayWindow) {
            self.overlayWindow = [[BSPassthroughWindow alloc] initWithWindowScene:ws];
            self.overlayWindow.frame = ws.coordinateSpace.bounds;
            self.overlayWindow.backgroundColor = [UIColor clearColor];
            self.overlayWindow.windowLevel = UIWindowLevelAlert + 100.0;
            self.overlayWindow.hidden = NO;

            UIViewController *rootVC = [[UIViewController alloc] init];
            rootVC.view.backgroundColor = [UIColor clearColor];
            rootVC.view.userInteractionEnabled = YES;
            self.overlayWindow.rootViewController = rootVC;
        } else {
            self.overlayWindow.windowScene = ws;
            self.overlayWindow.hidden = NO;
        }

        UIView *container = self.overlayWindow.rootViewController.view;
        if (self.floatingButton && self.floatingButton.superview == container) return;

        [self.floatingButton removeFromSuperview];
        [self.joyToggleButton removeFromSuperview];
        [self.floatingJoystick removeFromSuperview];
        [self.panelView removeFromSuperview];

        // Floating Pill ("GPX")
        self.floatingButton = [UIButton buttonWithType:UIButtonTypeCustom];
        self.floatingButton.frame = CGRectMake(20, 110, 58, 32);
        self.floatingButton.backgroundColor = [UIColor colorWithRed:0.08 green:0.08 blue:0.10 alpha:0.92];
        self.floatingButton.layer.cornerRadius = 16;
        self.floatingButton.layer.borderWidth = 1.4;
        self.floatingButton.layer.borderColor = self.enabled
            ? [UIColor colorWithRed:0.2 green:0.85 blue:0.4 alpha:1.0].CGColor
            : [UIColor colorWithRed:0.9 green:0.25 blue:0.25 alpha:1.0].CGColor;
        [self.floatingButton setTitle:@"GPX" forState:UIControlStateNormal];
        self.floatingButton.titleLabel.font = [UIFont boldSystemFontOfSize:11];
        [self.floatingButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        [self.floatingButton addTarget:self action:@selector(togglePanel) forControlEvents:UIControlEventTouchUpInside];

        UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(handlePan:)];
        [self.floatingButton addGestureRecognizer:pan];
        [container addSubview:self.floatingButton];

        // Quick Joy Toggle
        self.joyToggleButton = [UIButton buttonWithType:UIButtonTypeCustom];
        self.joyToggleButton.frame = CGRectMake(84, 110, 46, 32);
        self.joyToggleButton.backgroundColor = [UIColor colorWithRed:0.12 green:0.12 blue:0.16 alpha:0.92];
        self.joyToggleButton.layer.cornerRadius = 16;
        self.joyToggleButton.layer.borderWidth = 1.2;
        self.joyToggleButton.layer.borderColor = [UIColor colorWithRed:0.25 green:0.75 blue:0.95 alpha:0.9].CGColor;
        [self.joyToggleButton setTitle:@"Joy" forState:UIControlStateNormal];
        self.joyToggleButton.titleLabel.font = [UIFont boldSystemFontOfSize:11];
        [self.joyToggleButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        [self.joyToggleButton addTarget:self action:@selector(toggleJoystickVisibility) forControlEvents:UIControlEventTouchUpInside];
        [container addSubview:self.joyToggleButton];

        // Analog Joystick View
        CGSize screenSize = container.bounds.size;
        self.floatingJoystick = [[BSJoystickView alloc] initWithFrame:CGRectMake(screenSize.width - 136, screenSize.height - 230, 112, 112)];
        __weak typeof(self) weakSelf = self;
        self.floatingJoystick.onVectorChanged = ^(double bearingDegrees, double magnitude, BOOL active) {
            __strong typeof(weakSelf) strongSelf = weakSelf;
            if (!strongSelf) return;
            strongSelf.joystickBearing = bearingDegrees;
            strongSelf.joystickMagnitude = magnitude;
            strongSelf.joystickActive = active;
            if (!active) {
                strongSelf.currentSpeed = 0.0;
                strongSelf.statusLabel.text = @"Stick Idle (Locked)";
                [strongSelf savePrefs];
            }
        };
        [container addSubview:self.floatingJoystick];

        // Control Panel
        self.panelView = [[UIView alloc] initWithFrame:CGRectMake(20, 150, 246, 310)];
        self.panelView.backgroundColor = [UIColor colorWithRed:0.09 green:0.09 blue:0.11 alpha:0.96];
        self.panelView.layer.cornerRadius = 16;
        self.panelView.layer.borderWidth = 1.0;
        self.panelView.layer.borderColor = [UIColor colorWithWhite:1.0 alpha:0.16].CGColor;
        self.panelView.hidden = YES;

        UILabel *titleLbl = [[UILabel alloc] initWithFrame:CGRectMake(14, 12, 160, 20)];
        titleLbl.text = @"Bump GPX + Joystick";
        titleLbl.textColor = [UIColor whiteColor];
        titleLbl.font = [UIFont boldSystemFontOfSize:14];
        [self.panelView addSubview:titleLbl];

        self.statusLabel = [[UILabel alloc] initWithFrame:CGRectMake(14, 30, 165, 14)];
        self.statusLabel.text = [NSString stringWithFormat:@"Ready (%lu pts)", (unsigned long)self.routeWaypoints.count];
        self.statusLabel.textColor = [UIColor colorWithWhite:0.65 alpha:1.0];
        self.statusLabel.font = [UIFont systemFontOfSize:10 weight:UIFontWeightMedium];
        [self.panelView addSubview:self.statusLabel];

        self.toggleSwitch = [[UISwitch alloc] initWithFrame:CGRectMake(182, 10, 0, 0)];
        self.toggleSwitch.transform = CGAffineTransformMakeScale(0.8, 0.8);
        self.toggleSwitch.on = self.enabled;
        [self.toggleSwitch addTarget:self action:@selector(switchChanged:) forControlEvents:UIControlEventValueChanged];
        [self.panelView addSubview:self.toggleSwitch];

        self.latField = [[UITextField alloc] initWithFrame:CGRectMake(14, 52, 218, 32)];
        self.latField.backgroundColor = [UIColor colorWithWhite:0.18 alpha:1.0];
        self.latField.textColor = [UIColor whiteColor];
        self.latField.font = [UIFont monospacedDigitSystemFontOfSize:13 weight:UIFontWeightRegular];
        self.latField.layer.cornerRadius = 6;
        self.latField.text = [NSString stringWithFormat:@"%.6f", self.latitude];
        self.latField.keyboardType = UIKeyboardTypeNumbersAndPunctuation;
        self.latField.delegate = self;
        [self.panelView addSubview:self.latField];

        self.lonField = [[UITextField alloc] initWithFrame:CGRectMake(14, 90, 218, 32)];
        self.lonField.backgroundColor = [UIColor colorWithWhite:0.18 alpha:1.0];
        self.lonField.textColor = [UIColor whiteColor];
        self.lonField.font = [UIFont monospacedDigitSystemFontOfSize:13 weight:UIFontWeightRegular];
        self.lonField.layer.cornerRadius = 6;
        self.lonField.text = [NSString stringWithFormat:@"%.6f", self.longitude];
        self.lonField.keyboardType = UIKeyboardTypeNumbersAndPunctuation;
        self.lonField.delegate = self;
        [self.panelView addSubview:self.lonField];

        self.speedSegment = [[UISegmentedControl alloc] initWithItems:@[@"Walk", @"Bike", @"Drive"]];
        self.speedSegment.frame = CGRectMake(14, 130, 218, 28);
        self.speedSegment.selectedSegmentIndex = (self.targetSpeedMPS > 10.0) ? 2 : ((self.targetSpeedMPS > 3.0) ? 1 : 0);
        [self.speedSegment addTarget:self action:@selector(speedChanged:) forControlEvents:UIControlEventValueChanged];
        [self.panelView addSubview:self.speedSegment];

        UIButton *lockBtn = [UIButton buttonWithType:UIButtonTypeSystem];
        lockBtn.frame = CGRectMake(14, 168, 218, 36);
        lockBtn.backgroundColor = [UIColor colorWithRed:0.15 green:0.68 blue:0.38 alpha:1.0];
        lockBtn.layer.cornerRadius = 8;
        [lockBtn setTitle:@"Lock Coords & Rebuild Loop" forState:UIControlStateNormal];
        [lockBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        lockBtn.titleLabel.font = [UIFont boldSystemFontOfSize:12];
        [lockBtn addTarget:self action:@selector(applyCoords) forControlEvents:UIControlEventTouchUpInside];
        [self.panelView addSubview:lockBtn];

        self.playRouteButton = [UIButton buttonWithType:UIButtonTypeSystem];
        self.playRouteButton.frame = CGRectMake(14, 212, 218, 36);
        self.playRouteButton.backgroundColor = [UIColor colorWithRed:0.20 green:0.52 blue:0.90 alpha:1.0];
        self.playRouteButton.layer.cornerRadius = 8;
        [self.playRouteButton setTitle:@"Start GPX Walk" forState:UIControlStateNormal];
        [self.playRouteButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        self.playRouteButton.titleLabel.font = [UIFont boldSystemFontOfSize:12];
        [self.playRouteButton addTarget:self action:@selector(toggleRoutePlayback) forControlEvents:UIControlEventTouchUpInside];
        [self.panelView addSubview:self.playRouteButton];

        UIButton *pasteGPXBtn = [UIButton buttonWithType:UIButtonTypeSystem];
        pasteGPXBtn.frame = CGRectMake(14, 256, 218, 36);
        pasteGPXBtn.backgroundColor = [UIColor colorWithWhite:0.22 alpha:1.0];
        pasteGPXBtn.layer.cornerRadius = 8;
        [pasteGPXBtn setTitle:@"Paste GPX XML from Clipboard" forState:UIControlStateNormal];
        [pasteGPXBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        pasteGPXBtn.titleLabel.font = [UIFont boldSystemFontOfSize:11];
        [pasteGPXBtn addTarget:self action:@selector(importGPXFromClipboard) forControlEvents:UIControlEventTouchUpInside];
        [self.panelView addSubview:pasteGPXBtn];

        [container addSubview:self.panelView];
    });
}

- (void)togglePanel {
    self.panelView.hidden = !self.panelView.hidden;
    if (!self.panelView.hidden) {
        [self.floatingButton.superview bringSubviewToFront:self.panelView];
        [self.floatingButton.superview bringSubviewToFront:self.floatingJoystick];
        [self.floatingButton.superview bringSubviewToFront:self.floatingButton];
        [self.floatingButton.superview bringSubviewToFront:self.joyToggleButton];
    } else {
        [self.latField resignFirstResponder];
        [self.lonField resignFirstResponder];
    }
}

- (void)toggleJoystickVisibility {
    self.floatingJoystick.hidden = !self.floatingJoystick.hidden;
    self.joyToggleButton.layer.borderColor = self.floatingJoystick.hidden
        ? [UIColor colorWithWhite:0.4 alpha:0.8].CGColor
        : [UIColor colorWithRed:0.25 green:0.75 blue:0.95 alpha:0.9].CGColor;
}

- (void)switchChanged:(UISwitch *)sender {
    self.enabled = sender.isOn;
    self.floatingButton.layer.borderColor = self.enabled
        ? [UIColor colorWithRed:0.2 green:0.85 blue:0.4 alpha:1.0].CGColor
        : [UIColor colorWithRed:0.9 green:0.25 blue:0.25 alpha:1.0].CGColor;
    [self savePrefs];
}

- (void)speedChanged:(UISegmentedControl *)seg {
    if (seg.selectedSegmentIndex == 0) self.targetSpeedMPS = 1.42;      // Walk (~5.1 km/h)
    else if (seg.selectedSegmentIndex == 1) self.targetSpeedMPS = 5.50; // Bike (~19.8 km/h)
    else self.targetSpeedMPS = 13.88;                                   // Drive (~50 km/h)
    [self savePrefs];
}

- (void)applyCoords {
    double lat = [self.latField.text doubleValue];
    double lon = [self.lonField.text doubleValue];
    if (lat >= -90.0 && lat <= 90.0 && lon >= -180.0 && lon <= 180.0) {
        self.latitude = lat;
        self.longitude = lon;
        [self rebuildFallbackLoopAroundLat:lat lon:lon];
        self.statusLabel.text = @"Locked + 8-pt Loop Set";
        [self savePrefs];
        [self broadcastLocationToActiveDelegates];
    }
    [self.latField resignFirstResponder];
    [self.lonField resignFirstResponder];
}

- (BOOL)textFieldShouldReturn:(UITextField *)textField {
    [textField resignFirstResponder];
    return YES;
}

- (void)handlePan:(UIPanGestureRecognizer *)gesture {
    UIView *sup = self.floatingButton.superview;
    if (!sup) return;
    CGPoint trans = [gesture translationInView:sup];
    self.floatingButton.center = CGPointMake(self.floatingButton.center.x + trans.x, self.floatingButton.center.y + trans.y);
    self.joyToggleButton.center = CGPointMake(self.joyToggleButton.center.x + trans.x, self.joyToggleButton.center.y + trans.y);
    self.panelView.center = CGPointMake(self.panelView.center.x + trans.x, self.panelView.center.y + trans.y);
    [gesture setTranslation:CGPointZero inView:sup];
}

@end

#pragma mark - Anti-Detection: CLLocationSourceInformation & iOS 17-26.5 CLLocationUpdate Hooks

@implementation CLLocationSourceInformation (BumpSpoof)

+ (void)load {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        Class cls = [CLLocationSourceInformation class];
        Method m1 = class_getInstanceMethod(cls, @selector(isSimulatedBySoftware));
        Method m2 = class_getInstanceMethod(cls, @selector(bs_isSimulatedBySoftware));
        if (m1 && m2) method_exchangeImplementations(m1, m2);

        Method m3 = class_getInstanceMethod(cls, @selector(isProducedByAccessory));
        Method m4 = class_getInstanceMethod(cls, @selector(bs_isProducedByAccessory));
        if (m3 && m4) method_exchangeImplementations(m3, m4);
    });
}

- (BOOL)bs_isSimulatedBySoftware { return NO; }
- (BOOL)bs_isProducedByAccessory { return NO; }

@end

__attribute__((constructor)) static void BSHookModernLocationUpdate(void) {
    Class updateCls = NSClassFromString(@"CLLocationUpdate");
    if (updateCls) {
        SEL locSel = NSSelectorFromString(@"location");
        Method m = class_getInstanceMethod(updateCls, locSel);
        if (m) {
            IMP origIMP = method_getImplementation(m);
            CLLocation *(*origFunc)(id, SEL) = (void *)origIMP;
            IMP swizIMP = imp_implementationWithBlock(^CLLocation *(id selfRef) {
                CLLocation *real = origFunc(selfRef, locSel);
                if ([BumpSpoofManager shared].enabled) {
                    return [[BumpSpoofManager shared] spoofedLocationFromReal:real];
                }
                return real;
            });
            method_setImplementation(m, swizIMP);
        }
    }
}

#pragma mark - CoreLocation Manager & Delegate Safe Swizzling

static NSMutableSet<Class> *gSwizzledDelegateClasses = nil;

static void BSSwizzleDelegateClass(Class delClass) {
    if (!delClass) return;
    @synchronized (gSwizzledDelegateClasses) {
        if ([gSwizzledDelegateClasses containsObject:delClass]) return;
        [gSwizzledDelegateClasses addObject:delClass];

        // 1. Swizzle locationManager:didUpdateLocations:
        SEL modernSel = @selector(locationManager:didUpdateLocations:);
        if ([delClass instancesRespondToSelector:modernSel]) {
            Method m = class_getInstanceMethod(delClass, modernSel);
            if (m) {
                const char *types = method_getTypeEncoding(m);
                IMP origIMP = method_getImplementation(m);
                // Ensure concrete class receives method implementation without altering superclass
                class_addMethod(delClass, modernSel, origIMP, types);
                m = class_getInstanceMethod(delClass, modernSel);
                origIMP = method_getImplementation(m);

                void (*origFunc)(id, SEL, CLLocationManager *, NSArray<CLLocation *> *) = (void *)origIMP;
                id block = ^(id selfRef, CLLocationManager *manager, NSArray<CLLocation *> *locations) {
                    [[BumpSpoofManager shared] registerManager:manager];
                    if ([BumpSpoofManager shared].enabled) {
                        if ([BumpSpoofManager shared].isBroadcasting) {
                            // Forward already simulated locations without re-jittering
                            origFunc(selfRef, modernSel, manager, locations);
                        } else {
                            CLLocation *sample = locations.lastObject;
                            CLLocation *fake = [[BumpSpoofManager shared] spoofedLocationFromReal:sample];
                            origFunc(selfRef, modernSel, manager, @[fake]);
                        }
                    } else {
                        origFunc(selfRef, modernSel, manager, locations);
                    }
                };
                method_setImplementation(m, imp_implementationWithBlock(block));
            }
        }

        // 2. Swizzle legacy locationManager:didUpdateToLocation:fromLocation:
        SEL legacySel = @selector(locationManager:didUpdateToLocation:fromLocation:);
        if ([delClass instancesRespondToSelector:legacySel]) {
            Method m = class_getInstanceMethod(delClass, legacySel);
            if (m) {
                const char *types = method_getTypeEncoding(m);
                IMP origIMP = method_getImplementation(m);
                class_addMethod(delClass, legacySel, origIMP, types);
                m = class_getInstanceMethod(delClass, legacySel);
                origIMP = method_getImplementation(m);

                void (*origFunc)(id, SEL, CLLocationManager *, CLLocation *, CLLocation *) = (void *)origIMP;
                id block = ^(id selfRef, CLLocationManager *manager, CLLocation *newLoc, CLLocation *oldLoc) {
                    [[BumpSpoofManager shared] registerManager:manager];
                    if ([BumpSpoofManager shared].enabled) {
                        if ([BumpSpoofManager shared].isBroadcasting) {
                            origFunc(selfRef, legacySel, manager, newLoc, oldLoc);
                        } else {
                            CLLocation *fake = [[BumpSpoofManager shared] spoofedLocationFromReal:newLoc];
                            origFunc(selfRef, legacySel, manager, fake, oldLoc);
                        }
                    } else {
                        origFunc(selfRef, legacySel, manager, newLoc, oldLoc);
                    }
                };
                method_setImplementation(m, imp_implementationWithBlock(block));
            }
        }
    }
}

@implementation CLLocationManager (BumpSpoof)

+ (void)load {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        gSwizzledDelegateClasses = [NSMutableSet new];
        Class mgrClass = [CLLocationManager class];

        Method origLoc = class_getInstanceMethod(mgrClass, @selector(location));
        Method swizLoc = class_getInstanceMethod(mgrClass, @selector(bs_location));
        if (origLoc && swizLoc) method_exchangeImplementations(origLoc, swizLoc);

        Method origDel = class_getInstanceMethod(mgrClass, @selector(setDelegate:));
        Method swizDel = class_getInstanceMethod(mgrClass, @selector(bs_setDelegate:));
        if (origDel && swizDel) method_exchangeImplementations(origDel, swizDel);

        Method origStart = class_getInstanceMethod(mgrClass, @selector(startUpdatingLocation));
        Method swizStart = class_getInstanceMethod(mgrClass, @selector(bs_startUpdatingLocation));
        if (origStart && swizStart) method_exchangeImplementations(origStart, swizStart);

        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification
                                                          object:nil
                                                           queue:[NSOperationQueue mainQueue]
                                                      usingBlock:^(NSNotification * _Nonnull note) {
            (void)note;
            [[BumpSpoofManager shared] setupUI];
        }];
    });
}

- (void)bs_startUpdatingLocation {
    [[BumpSpoofManager shared] registerManager:self];
    [self bs_startUpdatingLocation];
}

- (CLLocation *)bs_location {
    [[BumpSpoofManager shared] registerManager:self];
    CLLocation *real = [self bs_location];
    if ([BumpSpoofManager shared].enabled) {
        return [[BumpSpoofManager shared] spoofedLocationFromReal:real];
    }
    return real;
}

- (void)bs_setDelegate:(id<CLLocationManagerDelegate>)delegate {
    [[BumpSpoofManager shared] registerManager:self];
    if (delegate) {
        BSSwizzleDelegateClass([delegate class]);
    }
    [self bs_setDelegate:delegate];
}

@end

#pragma mark - Network & Cellular Region Emulation (BSSID + CTCarrier)

static NSString *BSGenerateSpoofedBSSID(void) {
    double lat = [BumpSpoofManager shared].latitude;
    double lon = [BumpSpoofManager shared].longitude;
    uint32_t latHash = (uint32_t)(fabs(lat * 10000.0));
    uint32_t lonHash = (uint32_t)(fabs(lon * 10000.0));
    return [NSString stringWithFormat:@"02:%02x:%02x:%02x:%02x:%02x",
            (latHash >> 8) & 0xFF, latHash & 0xFF,
            (lonHash >> 16) & 0xFF, (lonHash >> 8) & 0xFF, lonHash & 0xFF];
}

@implementation CTCarrier (BumpSpoof)
+ (void)load {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        Class cls = [CTCarrier class];
        struct { SEL orig; SEL swiz; } pairs[] = {
            { @selector(carrierName),       @selector(bs_carrierName) },
            { @selector(mobileCountryCode), @selector(bs_mobileCountryCode) },
            { @selector(mobileNetworkCode), @selector(bs_mobileNetworkCode) },
            { @selector(isoCountryCode),    @selector(bs_isoCountryCode) }
        };
        for (size_t i = 0; i < sizeof(pairs) / sizeof(pairs[0]); i++) {
            Method m1 = class_getInstanceMethod(cls, pairs[i].orig);
            Method m2 = class_getInstanceMethod(cls, pairs[i].swiz);
            if (m1 && m2) method_exchangeImplementations(m1, m2);
        }
    });
}
- (NSString *)bs_carrierName { return [BumpSpoofManager shared].enabled ? kSpoofedCarrierName : [self bs_carrierName]; }
- (NSString *)bs_mobileCountryCode { return [BumpSpoofManager shared].enabled ? kSpoofedMCC : [self bs_mobileCountryCode]; }
- (NSString *)bs_mobileNetworkCode { return [BumpSpoofManager shared].enabled ? kSpoofedMNC : [self bs_mobileNetworkCode]; }
- (NSString *)bs_isoCountryCode { return [BumpSpoofManager shared].enabled ? kSpoofedISOCountry : [self bs_isoCountryCode]; }
@end

@implementation NEHotspotNetwork (BumpSpoof)
+ (void)load {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        Class cls = [NEHotspotNetwork class];
        Method origBSSID = class_getInstanceMethod(cls, @selector(BSSID));
        Method swizBSSID = class_getInstanceMethod(cls, @selector(bs_BSSID));
        if (origBSSID && swizBSSID) method_exchangeImplementations(origBSSID, swizBSSID);

        Method origSSID = class_getInstanceMethod(cls, @selector(SSID));
        Method swizSSID = class_getInstanceMethod(cls, @selector(bs_SSID));
        if (origSSID && swizSSID) method_exchangeImplementations(origSSID, swizSSID);
    });
}
- (NSString *)bs_BSSID { return [BumpSpoofManager shared].enabled ? BSGenerateSpoofedBSSID() : [self bs_BSSID]; }
- (NSString *)bs_SSID { return [BumpSpoofManager shared].enabled ? kSpoofedSSID : [self bs_SSID]; }
@end

#pragma mark - Dynamic C-Function Interception (Replacing Static Interpose)

static CFDictionaryRef (*orig_CNCopyCurrentNetworkInfo)(CFStringRef interfaceName) = NULL;

static CFDictionaryRef bs_CNCopyCurrentNetworkInfo(CFStringRef interfaceName) {
    if (![BumpSpoofManager shared].enabled) {
        if (orig_CNCopyCurrentNetworkInfo) return orig_CNCopyCurrentNetworkInfo(interfaceName);
        return CNCopyCurrentNetworkInfo(interfaceName);
    }
    NSString *bssid = BSGenerateSpoofedBSSID();
    NSDictionary *spoofedDict = @{
        (__bridge NSString *)kCNNetworkInfoKeySSID: kSpoofedSSID,
        (__bridge NSString *)kCNNetworkInfoKeyBSSID: bssid,
        (__bridge NSString *)kCNNetworkInfoKeySSIDData: [kSpoofedSSID dataUsingEncoding:NSUTF8StringEncoding]
    };
    return CFBridgingRetain(spoofedDict);
}

__attribute__((constructor)) static void BSInitializeDynamicRebindings(void) {
    struct rebinding rebs[] = {
        { "CNCopyCurrentNetworkInfo", (void *)bs_CNCopyCurrentNetworkInfo, (void **)&orig_CNCopyCurrentNetworkInfo }
    };
    bs_rebind_symbols(rebs, sizeof(rebs) / sizeof(rebs[0]));
}
