# BumpSpoof — Comprehensive Build, Packaging & Usage Guide

A modular iOS location and environment simulation suite compatible with iOS 15.0 through 26.5+. This guide provides end-to-end instructions for compiling the dynamic library, injecting it into an IPA, sideloading it onto an iPhone/iPad, and operating the on-screen navigation controls.

---

## 1. Architecture Overview

BumpSpoof consists of four core components:

* **`BumpSpoof.m`**: The runtime dynamic library (`.dylib`). It intercepts Apple's `CoreLocation` APIs (`CLLocationManager`, modern `CLLocationUpdate`, `CLLocationSourceInformation`), hooks cellular network queries (`CTCarrier`, `NEHotspotNetwork`, `CNCopyCurrentNetworkInfo`), and renders an unobtrusive floating HUD with an analog touch-drag joystick.
* **`inject_ipa.py`**: A cross-platform Python script that unpacks a target `.ipa`, embeds `BumpSpoof.dylib` inside `Payload/<App>.app/Frameworks/`, adds an `LC_LOAD_DYLIB` command to the main 64-bit Mach-O executable, and enables iTunes / Files app document sharing.
* **`build_spoof_ipa.yml`**: A GitHub Actions CI/CD workflow that automates the entire compilation, testing, and packaging process in the cloud on Apple Silicon macOS runners.
* **`test_inject_ipa.py`**: A unit test suite verifying Mach-O slice injection, universal FAT binary handling, and archive repacking.

---

## 2. Prerequisites

Depending on whether you choose to build in the cloud or on your local workstation:

### Option A: Cloud Build (Recommended — No Mac Required)
* A free [GitHub](https://github.com) account.
* A decrypted copy of the target IPA (or a direct download link to one).

### Option B: Local Compilation
* macOS running Xcode 14+ with Command Line Tools installed (`xcode-select --install`).
* Python 3.8+ installed.
* An iOS sideloading utility (TrollStore, AltStore, Sideloadly, or Apple Developer Account).

---

## 3. Method 1: Building via GitHub Actions (Zero Local Setup)

This is the easiest and most reliable method because it uses Apple's official Clang compiler on GitHub's hosted macOS runners.

### Step 1: Push Repository to GitHub
1. Create a new **Private** repository on GitHub (e.g., `bumpspoof-build`).
2. Clone or push this project directory into the repository:
   ```bash
   git init
   git add .
   git commit -m "Initialize BumpSpoof build suite"
   git remote add origin https://github.com/<your-username>/bumpspoof-build.git
   git branch -M main
   git push -u origin main
   ```

### Step 2: Trigger Workflow
1. Navigate to the **Actions** tab on your GitHub repository.
2. Under **Workflows** on the left sidebar, click on **Build Bump GPX Spoofer (iOS 26.5 Ready)**.
3. Click the **Run workflow** dropdown on the right:
   * **If you have a direct URL to a decrypted Bump IPA**: Paste it into the `ipa_url` input field.
   * **If you committed `Bump.ipa` to the repo root**: Leave the field empty.
   * **If you only want the compiled `.dylib`**: Leave the field empty.
4. Click **Run workflow**.

### Step 3: Download Artifacts
1. Wait 1–2 minutes for the workflow to complete.
2. Click on the completed run.
3. Scroll down to the **Artifacts** section at the bottom:
   * **`BumpSpoof-iOS26.5-Build`**: Contains `BumpSpoof.dylib` and (if an IPA was provided) `Bump_GPX_Spoofed.ipa`.
4. Download and unzip the artifact archive.

---

## 4. Method 2: Local Compilation & Manual Injection (macOS)

If you prefer building locally on a Mac:

### Step 1: Compile the Dynamic Library
Open Terminal in the project directory and run:

```bash
SDK_PATH=$(xcrun --sdk iphoneos --show-sdk-path)

xcrun -sdk iphoneos clang -arch arm64 \
  -dynamiclib \
  -O2 \
  -isysroot "$SDK_PATH" \
  -miphoneos-version-min=15.0 \
  -fobjc-arc \
  -Wall -Wextra -Wno-deprecated-declarations \
  -framework Foundation \
  -framework UIKit \
  -framework CoreGraphics \
  -framework CoreLocation \
  -framework QuartzCore \
  -framework CoreTelephony \
  -framework SystemConfiguration \
  -framework NetworkExtension \
  -install_name "@executable_path/Frameworks/BumpSpoof.dylib" \
  BumpSpoof.m -o BumpSpoof.dylib

# Ad-hoc sign the library
codesign -f -s - BumpSpoof.dylib
```

### Step 2: Run the Unit Verification Suite
Verify your Python environment and binary parsing:
```bash
python3 test_inject_ipa.py
```
Expected output:
```text
Ran 3 tests in 0.011s
OK
```

### Step 3: Inject into Target IPA
Run the injection utility pointing to your decrypted target app:
```bash
python3 inject_ipa.py Bump.ipa BumpSpoof.dylib Bump_GPX_Spoofed.ipa
```

The script will:
1. Extract the IPA bundle.
2. Modify `Info.plist` to enable `UIFileSharingEnabled` and `LSSupportsOpeningDocumentsInPlace`.
3. Copy `BumpSpoof.dylib` into `Payload/Bump.app/Frameworks/`.
4. Insert `LC_LOAD_DYLIB` pointing to `@executable_path/Frameworks/BumpSpoof.dylib`.
5. Repackage the archive with valid POSIX executable permissions (`0o755`).

---

## 5. Sideloading onto iOS Device

Once you have `Bump_GPX_Spoofed.ipa`:

### Approach A: TrollStore (iOS 14.0 – 17.0 / Permasigned)
* AirDrop or transfer `Bump_GPX_Spoofed.ipa` to your iOS device.
* Open the file in **TrollStore** and tap **Install**.
* No revokes, no 7-day expiration, and rootless sandboxing handles the injected library automatically.

### Approach B: AltStore / SideStore (Standard iOS 15 – 26+)
1. Connect your iPhone to your Mac/PC via USB or Wi-Fi sync.
2. Open **AltServer** or **SideStore**.
3. Hold Option/Shift and select **Sideload .ipa**.
4. Select `Bump_GPX_Spoofed.ipa`.
5. Enter your Apple ID credentials to sign and install the app.
6. On the device, go to **Settings > General > VPN & Device Management** and trust your developer profile.

### Approach C: Sideloadly (Windows & macOS)
1. Launch **Sideloadly**.
2. Connect your device.
3. Drag and drop `Bump_GPX_Spoofed.ipa` into Sideloadly.
4. Click **Start** to sign and install.

---

## 6. In-App Controls & Feature Guide

When you launch the application, you are greeted with a full-screen interactive Apple Map and floating navigation HUD:

### 0. Full-Screen Interactive Map (`MKMapView`)
* **Live GPS Pin**: A prominent green beacon pin displays your current simulated location in real-time.
* **Tap-to-Teleport**: Tap anywhere on the map to immediately teleport your virtual coordinate to that location.
* **Follow Camera**: As you steer with the analog joystick or run a GPX route walk, the map camera automatically follows your movement.
* **Recenter**: Tap the **Recenter** button in the top bar anytime to focus the camera directly on your current position.
* **Map Style**: Tap **Sat / Map** in the top bar to toggle between Standard street view and Satellite / Hybrid imagery.

### 1. Floating Menu Button ("GPX")
* **Position**: Default top-left (`(20, 110)`).
* **Indicator Border**:
  * **Green Border**: Location and environment simulation is active.
  * **Red Border**: Simulation is disabled (app receives true hardware GPS).
* **Interaction**: Tap to open or collapse the main control panel. Drag anywhere on the screen to reposition.

### 2. Quick Joystick Button ("Joy")
* **Position**: Next to the GPX button.
* **Function**: Instantly shows or hides the on-screen analog joystick without opening the full control panel.
* **Border Color**: Cyan when joystick is visible; dimmed when hidden.

### 3. Draggable Analog Joystick (`BSJoystickView`)
* **Inner Green Knob**:
  * Touch and drag the center knob in any direction to move your virtual position.
  * **Bearing Calculation**: The joystick calculates continuous heading (0° North, 90° East, 180° South, 270° West).
  * **Magnitude Scaling**: Pushing the knob further out increases your velocity up to the selected profile maximum.
  * Releasing the knob smoothly returns it to center, immediately halting movement and locking coordinates.
* **Repositioning the Joystick**:
  * Touch the **outer circular rim** of the joystick to drag the entire joystick widget to any corner of the screen so it does not obstruct in-app buttons.

### 4. Speed Profiles
Within the control panel, select your movement velocity:
* **Walk**: `1.42 m/s` (~5.1 km/h) — Standard pedestrian pace.
* **Bike**: `5.50 m/s` (~19.8 km/h) — Urban cycling pace.
* **Drive**: `13.88 m/s` (~50.0 km/h) — City driving speed.

### 5. Manual Coordinate Locking
* Open the panel to view live latitude and longitude.
* Tap the text fields to type custom coordinates (e.g., `48.858400`, `2.294500`).
* Tap **Lock Coords & Rebuild Loop** to instantly jump to the target coordinate and generate an automated local 8-point perimeter route around that point.

### 6. Automated GPX Route Playback
You can simulate automated walking along custom paths:
* **Option A: Files App Route Drop**
  1. Connect your iPhone to a PC or open Apple's native **Files** app on device.
  2. Navigate to **On My iPhone > Bump**.
  3. Place a file named `route.gpx` inside this folder.
  4. The app loads the route on start. Tap **Start GPX Walk**.
* **Option B: Clipboard Paste**
  1. Copy any raw GPX XML string on your device.
  2. Open the control panel and tap **Paste GPX XML from Clipboard**.
  3. Tap **Start GPX Walk** to begin route traversal.
* **Manual Override**: Touching the analog joystick while a GPX walk is active immediately pauses automated playback and transfers steering control to your thumb.

---

## 7. Anti-Detection & System Integration Safeguards

* **Hardware Indicator Suppression**: Automatically intercepts `CLLocationSourceInformation` so `isSimulatedBySoftware` and `isProducedByAccessory` return `NO`.
* **Dynamic Symbol Rebinding**: Hooks low-level network discovery functions dynamically via an embedded Fishhook Mach-O relocation parser, guaranteeing execution in sandboxed environments where traditional static interposing fails.
* **Regional Cellular Matching**: Reports a synchronized French carrier and BSSID network profile (`Orange F`, MCC 208, MNC 01) matching default coordinates.
* **Gaussian Jitter Engine**: Injects realistic micro-variations (3.8–5.2m accuracy, subtle velocity fluctuations) so location streams mimic real satellite reception rather than static coordinates.
