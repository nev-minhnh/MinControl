package io.github.nevminhnh.mincontrol.master.ui.components

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import io.github.nevminhnh.mincontrol.master.ui.theme.ChipBorder
import io.github.nevminhnh.mincontrol.master.ui.theme.Primary
import io.github.nevminhnh.mincontrol.master.ui.theme.Surface
import io.github.nevminhnh.mincontrol.master.ui.theme.TextPrimary
import io.github.nevminhnh.mincontrol.master.ui.theme.TextSecondary

/** One dropdown choice; [note] is a short secondary line (e.g. "chỉ có tác dụng ở chế độ…"). */
data class DropdownOption<T>(val value: T, val label: String, val note: String? = null)

/** Material 3 exposed dropdown (read-only field + menu), full width so long Vietnamese labels never truncate badly. */
@Composable
fun <T> DropdownField(
    value: T, options: List<DropdownOption<T>>, onPick: (T) -> Unit, modifier: Modifier = Modifier,
    label: String? = null, enabled: Boolean = true, valueColor: androidx.compose.ui.graphics.Color = TextPrimary,
) {
    var open by remember { mutableStateOf(false) }
    val current = options.firstOrNull { it.value == value }
    ExposedDropdownMenuBox(expanded = open && enabled, onExpandedChange = { if (enabled) open = it }, modifier = modifier) {
        OutlinedTextField(
            value = current?.label ?: "", onValueChange = {}, readOnly = true, enabled = enabled, singleLine = true,
            label = label?.let { { Text(it) } },
            textStyle = MaterialTheme.typography.bodyMedium.copy(color = valueColor),
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = open) },
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = Primary, unfocusedBorderColor = ChipBorder,
                focusedContainerColor = Surface, unfocusedContainerColor = Surface,
                focusedLabelColor = Primary, unfocusedLabelColor = TextSecondary,
            ),
            modifier = Modifier.fillMaxWidth().menuAnchor(MenuAnchorType.PrimaryNotEditable, enabled),
        )
        ExposedDropdownMenu(expanded = open && enabled, onDismissRequest = { open = false }, containerColor = Surface) {
            options.forEach { o ->
                DropdownMenuItem(
                    text = {
                        Column {
                            Text(o.label, style = MaterialTheme.typography.bodyMedium, color = TextPrimary)
                            o.note?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = TextSecondary, maxLines = 2, overflow = TextOverflow.Ellipsis) }
                        }
                    },
                    onClick = { open = false; onPick(o.value) },
                    contentPadding = ExposedDropdownMenuDefaults.ItemContentPadding,
                )
            }
        }
    }
}
