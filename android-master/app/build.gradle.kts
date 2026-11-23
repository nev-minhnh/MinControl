import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.ksp)
}

// Firebase config is private and NOT committed: drop app/google-services.json in to enable FCM.
// Without it the app builds and runs; push is simply disabled (FirebaseApp never initialises).
if (file("google-services.json").exists()) {
    apply(plugin = "com.google.gms.google-services")
}

android {
    namespace = "io.github.nevminhnh.mincontrol.master"
    compileSdk = 36

    defaultConfig {
        applicationId = "io.github.nevminhnh.mincontrol.master"
        minSdk = 28
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures { compose = true }
    packaging {
        resources.excludes += setOf("META-INF/versions/9/OSGI-INF/MANIFEST.MF", "META-INF/DEPENDENCIES")
    }
    testOptions {
        unitTests.isReturnDefaultValues = true
        unitTests.all {
            // The contract tests read ../protocol relative to the module dir.
            it.systemProperty("mincontrol.protocolDir", rootDir.resolve("../protocol").canonicalPath)
        }
    }
}

/**
 * Copies the protocol catalogs into the app assets: services.json (API.md §17), app-groups.json and
 * search-engines.json (§19). A missing file becomes an empty catalog; the app then uses its built-in fallback.
 */
abstract class CopyProtocolAssets : DefaultTask() {
    @get:Internal abstract val protocolDir: Property<String>
    @get:OutputDirectory abstract val outputDir: DirectoryProperty

    @TaskAction
    fun copy() {
        val fallbacks = mapOf(
            "services.json" to "{\"version\":0,\"services\":[]}",
            "app-groups.json" to "{\"version\":0,\"groups\":[]}",
            "search-engines.json" to "{\"version\":0,\"engines\":[]}",
        )
        val dir = outputDir.get().asFile
        dir.mkdirs()
        for ((name, empty) in fallbacks) {
            val src = File(protocolDir.get(), name)
            val out = File(dir, name)
            if (src.isFile) src.copyTo(out, overwrite = true) else out.writeText(empty)
        }
    }
}

val copyProtocolAssets = tasks.register<CopyProtocolAssets>("copyProtocolAssets") {
    protocolDir.set(rootDir.resolve("../protocol").canonicalPath)
    outputs.upToDateWhen { false }
}

androidComponents {
    onVariants { v -> v.sources.assets?.addGeneratedSourceDirectory(copyProtocolAssets, CopyProtocolAssets::outputDir) }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
        optIn.addAll("androidx.compose.material3.ExperimentalMaterial3Api", "androidx.compose.foundation.layout.ExperimentalLayoutApi")
    }
}

ksp {
    arg("room.generateKotlin", "true")
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.fragment.ktx)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.process)
    implementation(libs.androidx.navigation.compose)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.text.google.fonts)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons.extended)
    implementation(libs.androidx.biometric)
    implementation(libs.play.services.code.scanner)
    implementation(libs.androidx.room.runtime)
    implementation(libs.androidx.room.ktx)
    ksp(libs.androidx.room.compiler)
    implementation(libs.androidx.glance.appwidget)
    implementation(libs.androidx.glance.material3)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.okhttp)
    implementation(libs.bouncycastle)
    implementation(libs.zxing.core)
    implementation(platform(libs.firebase.bom))
    implementation(libs.firebase.messaging)
    debugImplementation(libs.androidx.compose.ui.tooling)

    testImplementation(libs.junit)
    testImplementation(libs.json.schema.validator)
}
