package io.github.nevminhnh.mincontrol.master.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable

private val LightColors = lightColorScheme(
    primary = Primary,
    onPrimary = Surface,
    primaryContainer = PrimaryContainer,
    onPrimaryContainer = Primary,
    secondary = TextPrimary,
    onSecondary = Surface,
    background = Background,
    onBackground = TextPrimary,
    surface = Surface,
    onSurface = TextPrimary,
    surfaceVariant = Background,
    onSurfaceVariant = TextSecondary,
    surfaceContainerLow = Surface,
    surfaceContainer = Surface,
    surfaceContainerHigh = Surface,
    surfaceContainerHighest = SegmentBg,
    outline = ChipBorder,
    outlineVariant = Divider,
    error = Danger,
    onError = Surface,
    errorContainer = DangerContainer,
    onErrorContainer = DangerText,
)

/** Light theme only (matches the mock-ups). */
@Composable
fun MinControlTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = LightColors, typography = AppTypography, content = content)
}
