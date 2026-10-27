// Top-level build file where you can add configuration options common to all sub-projects/modules.
plugins {
    alias(libs.plugins.android.application) apply false
    // Never applied. Pins the Kotlin version that AGP's built-in Kotlin compiles with. Without it,
    // AGP falls back to its bundled one.
    alias(libs.plugins.kotlin.android) apply false
}
