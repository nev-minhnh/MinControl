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

val AppTypography = Typography().let { base ->
    base.copy(
        headlineSmall = TextStyle(fontFamily = BeVietnamPro, fontWeight = FontWeight.Bold, fontSize = 22.sp, lineHeight = 28.sp),
        titleMedium = TextStyle(fontFamily = BeVietnamPro, fontWeight = FontWeight.SemiBold, fontSize = 16.sp, lineHeight = 22.sp),
        bodyLarge = TextStyle(fontFamily = BeVietnamPro, fontWeight = FontWeight.Normal, fontSize = 16.sp, lineHeight = 24.sp),
        bodyMedium = TextStyle(fontFamily = BeVietnamPro, fontWeight = FontWeight.Normal, fontSize = 14.sp, lineHeight = 20.sp),
        labelMedium = TextStyle(fontFamily = BeVietnamPro, fontWeight = FontWeight.Medium, fontSize = 12.sp, lineHeight = 16.sp),
    )
}
