package io.github.nevminhnh.mincontrol.master.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.DeviceFontFamilyName
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.googlefonts.GoogleFont
import androidx.compose.ui.unit.sp
import io.github.nevminhnh.mincontrol.master.R
import androidx.compose.ui.text.googlefonts.Font as GoogleFontEntry

private val provider = GoogleFont.Provider(
    providerAuthority = "com.google.android.gms.fonts",
    providerPackage = "com.google.android.gms",
    certificates = R.array.com_google_android_gms_fonts_certs,
)

private val beVietnamPro = GoogleFont("Be Vietnam Pro")
private val jetBrainsMono = GoogleFont("JetBrains Mono")
private val weights = listOf(FontWeight.Normal, FontWeight.Medium, FontWeight.SemiBold, FontWeight.Bold)

/** Be Vietnam Pro (downloadable Google Font); system sans-serif is the fallback while loading / if GMS is absent. */
val BeVietnamPro: FontFamily = FontFamily(
    weights.flatMap { w ->
        listOf(
            GoogleFontEntry(googleFont = beVietnamPro, fontProvider = provider, weight = w),
            Font(DeviceFontFamilyName("sans-serif"), weight = w),
        )
    },
)

/** JetBrains Mono for pairing codes and key fingerprints (falls back to system monospace). */
val Mono: FontFamily = FontFamily(
    listOf(FontWeight.Normal, FontWeight.SemiBold).flatMap { w ->
        listOf(
            GoogleFontEntry(googleFont = jetBrainsMono, fontProvider = provider, weight = w),
            Font(DeviceFontFamilyName("monospace"), weight = w),
        )
    },
)

private fun s(size: Int, weight: FontWeight = FontWeight.Normal, line: Int = (size * 1.4).toInt()) =
    TextStyle(fontFamily = BeVietnamPro, fontWeight = weight, fontSize = size.sp, lineHeight = line.sp)

/** Mock-up scale: 32 big numbers, 20 titles, 15 body, 13 secondary. */
val AppTypography = Typography(
    displaySmall = s(32, FontWeight.SemiBold, 38),
    headlineSmall = s(20, FontWeight.SemiBold, 26),
    titleLarge = s(20, FontWeight.SemiBold, 26),
    titleMedium = s(15, FontWeight.SemiBold, 22),
    titleSmall = s(13, FontWeight.SemiBold, 18),
    bodyLarge = s(15, FontWeight.Normal, 22),
    bodyMedium = s(15, FontWeight.Normal, 22),
    bodySmall = s(13, FontWeight.Normal, 19),
    labelLarge = s(15, FontWeight.SemiBold, 20),
    labelMedium = s(13, FontWeight.Normal, 18),
    labelSmall = s(11, FontWeight.SemiBold, 14),
)
