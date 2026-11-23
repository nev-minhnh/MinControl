package io.github.nevminhnh.mincontrol.master.ui.theme

import androidx.compose.ui.graphics.Color

// Palette taken from docs/design/master-app/project/*.dc.html
val Background = Color(0xFFF4F6FA)
val Surface = Color(0xFFFFFFFF)
val TextPrimary = Color(0xFF0E1726)
/** Secondary text: darkened for WCAG AA (>= 7:1 on Background, was #5B6577). */
val TextSecondary = Color(0xFF4A5568)
val TextBody = Color(0xFF374151)
val Primary = Color(0xFF2F54EB)
val PrimaryPressed = Color(0xFF1D3BC2)
val PrimaryContainer = Color(0xFFE8EDFF)
val QuickActionBg = Color(0xFFF1F4FE)
val QuickActionBorder = Color(0xFFDCE3F5)
val Success = Color(0xFF13795B)
val SuccessDot = Color(0xFF17A673)
val SuccessContainer = Color(0xFFE6F4EE)
val WarningBg = Color(0xFFFFF3DC)
val WarningText = Color(0xFF7A4700)
val WarningIcon = Color(0xFF9A5B00)
val Danger = Color(0xFFC0262D)
val DangerText = Color(0xFFB3232A)
val DangerContainer = Color(0xFFFDECEC)
val DangerBorder = Color(0xFFF6CFD1)
val Outline = Color(0xFFE3E8F0)
val ChipBorder = Color(0xFFDCE3EE)
val Divider = Color(0xFFEEF1F5)
val Track = Color(0xFFEDF0F5)
val SegmentBg = Color(0xFFE9ECF2)
val NeutralIconBg = Color(0xFFE9ECF1)
/** Non-text indicator (dots, rails): >= 3:1 against Surface. */
val OfflineDot = Color(0xFF7B8494)
val Handle = Color(0xFFD5DBE5)
val Rail = Color(0xFFD5DBE5)
val Purple = Color(0xFF7C3AED)
val SearchBg = Color(0xFFF1EBFE)
val SearchFg = Color(0xFF6D3FD6)
val CodeBg = Color(0xFFF1F3F7)
val Scrim = Color(0xFF5E6676)

/** Disabled foreground (WCAG exempts disabled controls, but keep it legible: ~3:1 on Surface). */
val DisabledFg = Color(0xFF8A94A6)
/** Unchecked switch thumb/border (>= 3:1 non-text contrast on Surface). */
val SwitchOff = Color(0xFF6B7588)

/** Avatar colour pairs (background, foreground) cycled per child. */
val AvatarColors = listOf(
    Color(0xFFE8EDFF) to Color(0xFF2F54EB),
    Color(0xFFFCEBDD) to Color(0xFFA04A0C),
    Color(0xFFE6F4EE) to Color(0xFF13795B),
    Color(0xFFF1EBFE) to Color(0xFF6D3FD6),
)

/** Screenshot placeholder tints (game / web / chat). */
val ShotGame = Color(0xFF6E8B3D)
val ShotWeb = Color(0xFF5B7BE0)
val ShotChat = Color(0xFF3A8FB7)

/** WCAG 2.x contrast helpers (pure, unit-tested in ContrastTest). */
object Contrast {
    private fun channel(c: Float): Double = if (c <= 0.03928f) c / 12.92 else Math.pow((c + 0.055) / 1.055, 2.4)

    fun luminance(c: Color): Double = 0.2126 * channel(c.red) + 0.7152 * channel(c.green) + 0.0722 * channel(c.blue)

    fun ratio(a: Color, b: Color): Double {
        val la = luminance(a)
        val lb = luminance(b)
        return (maxOf(la, lb) + 0.05) / (minOf(la, lb) + 0.05)
    }

    /** Every text/background pair used by the screens (foreground, background, name). Body text needs >= 4.5:1. */
    val textPairs: List<Triple<Color, Color, String>> = listOf(
        Triple(TextPrimary, Background, "primary/background"),
        Triple(TextPrimary, Surface, "primary/surface"),
        Triple(TextSecondary, Background, "secondary/background"),
        Triple(TextSecondary, Surface, "secondary/surface"),
        Triple(TextSecondary, SegmentBg, "secondary/segment pill"),
        Triple(TextSecondary, NeutralIconBg, "secondary/neutral icon"),
        Triple(TextBody, Background, "body/background"),
        Triple(TextBody, Surface, "body/surface"),
        Triple(TextBody, SegmentBg, "body/segment"),
        Triple(Primary, Surface, "primary link/surface"),
        Triple(Primary, Background, "primary link/background"),
        Triple(Primary, PrimaryContainer, "primary chip"),
        Triple(Primary, QuickActionBg, "quick action"),
        Triple(TextBody, QuickActionBg, "info note"),
        Triple(Surface, Primary, "button text"),
        Triple(Surface, TextPrimary, "selected chip"),
        Triple(Surface, Danger, "badge text"),
        Triple(DangerText, DangerContainer, "danger chip/banner"),
        Triple(DangerText, Surface, "danger text"),
        Triple(Success, SuccessContainer, "success pill"),
        Triple(Success, Surface, "success text"),
        Triple(WarningText, WarningBg, "warning banner"),
        Triple(WarningIcon, WarningBg, "warning icon"),
        Triple(SearchFg, SearchBg, "search badge"),
        Triple(Purple, Surface, "app group"),
    ) + AvatarColors.mapIndexed { i, (bg, fg) -> Triple(fg, bg, "avatar $i") }

    /** Non-text UI (dots, switch borders, rails next to text): >= 3:1. */
    val nonTextPairs: List<Triple<Color, Color, String>> = listOf(
        Triple(OfflineDot, Surface, "offline dot"),
        Triple(SuccessDot, Surface, "online dot"),
        Triple(Danger, Surface, "block dot"),
        Triple(SwitchOff, Surface, "switch off"),
        Triple(DisabledFg, Surface, "disabled"),
    )
}
