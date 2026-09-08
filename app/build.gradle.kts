plugins { id("com.android.application") }
android {
  namespace = "com.parvaz.scanner"
  compileSdk = 34
  defaultConfig {
    applicationId = "com.parvaz.scanner"
    minSdk = 24; targetSdk = 34; versionCode = 5; versionName = "1.5.0"
  }
  buildTypes { release { isMinifyEnabled = false } }
  compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
}
dependencies {
  implementation("androidx.appcompat:appcompat:1.6.1")
  implementation("com.google.android.material:material:1.11.0")
  implementation("androidx.constraintlayout:constraintlayout:2.1.4")
  implementation("androidx.recyclerview:recyclerview:1.3.2")
}
