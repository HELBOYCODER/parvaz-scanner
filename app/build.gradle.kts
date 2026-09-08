plugins { id("com.android.application") }
android {
  namespace = "com.parvaz.scanner"
  compileSdk = 34
  defaultConfig {
    applicationId = "com.parvaz.scanner"
    minSdk = 24; targetSdk = 34; versionCode = 2; versionName = "1.2.0"
  }
  buildTypes { release { isMinifyEnabled = false } }
  compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
}
dependencies {
  implementation("androidx.appcompat:appcompat:1.6.1")
  implementation("com.google.android.material:material:1.11.0")
  implementation("org.bouncycastle:bcprov-jdk15on:1.70")
}