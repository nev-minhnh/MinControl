package io.github.nevminhnh.mincontrol.master.ui.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import io.github.nevminhnh.mincontrol.master.data.protocol.MasterSettings
import io.github.nevminhnh.mincontrol.master.ui.components.DropdownField
import io.github.nevminhnh.mincontrol.master.ui.components.DropdownOption
import io.github.nevminhnh.mincontrol.master.ui.components.McSwitch
import io.github.nevminhnh.mincontrol.master.ui.theme.Divider
import io.github.nevminhnh.mincontrol.master.ui.theme.TextPrimary
import io.github.nevminhnh.mincontrol.master.ui.theme.TextSecondary

/**
 * "Cảnh báo" (API.md §19): per alert type a switch and, when on, how often at most.
 * Rows stack vertically (title/description, then a full-width dropdown) so they work at 320 dp and 1.3x font.
 */
@Composable
fun AlertSettingsList(ms: MasterSettings, loaded: Boolean, onChange: (MasterSettings) -> Unit) {
    val eff = AlertSettingsLogic.effective(ms)
    val freq = AlertSettingsLogic.FREQUENCIES.map { DropdownOption(it.first, it.second) }
    Column(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
        Text(
            "Chọn loại sự việc sẽ gửi thông báo về điện thoại. Mặc định chỉ báo khi con tìm cách can thiệp hoặc vượt rào; " +
                "các mục khác vẫn được ghi trong Hoạt động.",
            style = MaterialTheme.typography.bodySmall, color = TextSecondary, modifier = Modifier.padding(vertical = 8.dp),
        )
        AlertSettingsLogic.TYPES.forEachIndexed { i, t ->
            val s = eff[t.type] ?: AlertSettingsLogic.default(t.type)
            Column(Modifier.fillMaxWidth().padding(vertical = 10.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(t.title, style = MaterialTheme.typography.bodyMedium, color = TextPrimary)
                        Text(t.description, style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                    }
                    Row(Modifier.semantics { contentDescription = "Báo khi ${t.title}" }) {
                        McSwitch(s.enabled) { v -> if (loaded) onChange(AlertSettingsLogic.update(ms, t.type, enabled = v)) }
                    }
                }
                if (s.enabled) DropdownField(
                    value = AlertSettingsLogic.snap(s.minIntervalMin), options = freq, label = "Tần suất", enabled = loaded,
                    onPick = { v -> onChange(AlertSettingsLogic.update(ms, t.type, minIntervalMin = v)) },
                )
            }
            if (i < AlertSettingsLogic.TYPES.lastIndex) HorizontalDivider(color = Divider)
        }
    }
}
