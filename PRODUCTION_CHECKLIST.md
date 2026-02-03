# SignedByMe - Production Checklist

## Branding & Assets
- [ ] App name: "BTC_DID" → "SignedByMe"
- [ ] Custom app icon (launcher icon)
- [ ] Splash screen (optional but nice)

## Build Configuration
- [ ] Version code/name (1.0.0 for initial release)
- [ ] Enable R8/ProGuard minification for release
- [ ] Configure signing config for release builds
- [ ] Target SDK 36 ✓ (already set)
- [ ] Min SDK 26 ✓ (Android 8.0+)

## Native Libraries
- [x] arm64-v8a ✓
- [x] armeabi-v7a ✓
- [x] x86_64 ✓

## Code Quality
- [ ] Remove debug/demo buttons for production
- [ ] Error handling for network failures
- [ ] Error handling for keystore failures
- [ ] Loading states during API calls

## Play Store Requirements
- [ ] Privacy policy URL
- [ ] App description
- [ ] Screenshots (phone)
- [ ] Feature graphic (1024x500)
- [ ] Content rating questionnaire
- [ ] Data safety form

## Testing
- [ ] Full flow test on device
- [ ] Test on different screen sizes
- [ ] Test offline behavior

---
Last updated: 2026-02-03
