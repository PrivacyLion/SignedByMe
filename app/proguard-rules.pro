# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# Keep line numbers for crash reports
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# ===== JNI / Native Bridge =====
# Keep all native methods and the NativeBridge object
-keep class com.privacylion.btcdid.NativeBridge { *; }
-keepclasseswithmembernames class * {
    native <methods>;
}

# ===== Kotlin Serialization / JSON =====
-keep class org.json.** { *; }

# ===== DidWalletManager data classes =====
-keep class com.privacylion.btcdid.DidWalletManager$LoginStart { *; }

# ===== Compose =====
# Compose handles most things, but keep these for safety
-keep class androidx.compose.** { *; }
-dontwarn androidx.compose.**

# ===== Crypto / Keystore =====
-keep class javax.crypto.** { *; }
-keep class java.security.** { *; }
