package io.github.nevminhnh.mincontrol.master.ui.policy

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.rememberModalBottomSheetState
import io.github.nevminhnh.mincontrol.master.ui.components.DropdownField
import io.github.nevminhnh.mincontrol.master.ui.components.DropdownOption
import io.github.nevminhnh.mincontrol.master.ui.theme.Divider
import io.github.nevminhnh.mincontrol.master.ui.theme.QuickActionBg
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.RadioButtonDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.github.nevminhnh.mincontrol.master.data.protocol.UserPolicy
import io.github.nevminhnh.mincontrol.master.policy.BlockingV2
import io.github.nevminhnh.mincontrol.master.policy.Service
import io.github.nevminhnh.mincontrol.master.policy.ServiceCatalog
import io.github.nevminhnh.mincontrol.master.policy.ServiceState
import io.github.nevminhnh.mincontrol.master.ui.components.McSwitch
import io.github.nevminhnh.mincontrol.master.ui.theme.AvatarColors
import io.github.nevminhnh.mincontrol.master.ui.theme.ChipBorder
import io.github.nevminhnh.mincontrol.master.ui.theme.DangerContainer
import io.github.nevminhnh.mincontrol.master.ui.theme.DangerText
import io.github.nevminhnh.mincontrol.master.ui.theme.Primary
import io.github.nevminhnh.mincontrol.master.ui.theme.PrimaryContainer
import io.github.nevminhnh.mincontrol.master.ui.theme.Success
import io.github.nevminhnh.mincontrol.master.ui.theme.SuccessContainer
import io.github.nevminhnh.mincontrol.master.ui.theme.Surface
import io.github.nevminhnh.mincontrol.master.ui.theme.SwitchOff
import io.github.nevminhnh.mincontrol.master.ui.theme.TextBody
import io.github.nevminhnh.mincontrol.master.ui.theme.TextPrimary
import io.github.nevminhnh.mincontrol.master.ui.theme.TextSecondary

/** Blocklist / allowlist choice as two radio cards (long labels wrap instead of being squeezed into a segmented control). */
@Composable
internal fun ModeChoice(
    allowlist: Boolean, changed: Boolean, blocklistHelp: String, allowlistHelp: String, onChange: (Boolean) -> Unit,
) {
    Column(Modifier.fillMaxWidth().padding(vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        ModeOption(BlockingV2.APP_BLOCKLIST_TITLE, blocklistHelp, !allowlist) { onChange(false) }
        ModeOption(BlockingV2.APP_ALLOWLIST_TITLE, allowlistHelp, allowlist) { onChange(true) }
        if (changed) Text("Đã đổi chế độ — chưa áp dụng", style = MaterialTheme.typography.labelSmall, color = Primary)
    }
}

@Composable
private fun ModeOption(title: String, help: String, selected: Boolean, onClick: () -> Unit) {
    val shape = RoundedCornerShape(14.dp)
    Row(
        Modifier.fillMaxWidth().clip(shape)
            .background(if (selected) PrimaryContainer else Surface)
            .border(1.dp, if (selected) Primary else ChipBorder, shape)
            .selectable(selected = selected, role = Role.RadioButton, onClick = onClick)
            .padding(start = 4.dp, end = 12.dp, top = 8.dp, bottom = 10.dp),
        verticalAlignment = Alignment.Top,
    ) {
        RadioButton(selected, onClick = null, modifier = Modifier.padding(12.dp),
            colors = RadioButtonDefaults.colors(selectedColor = Primary, unselectedColor = SwitchOff))
        Column(Modifier.weight(1f).padding(top = 10.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(title, style = MaterialTheme.typography.titleSmall, color = TextPrimary, fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Medium)
            Text(help, style = MaterialTheme.typography.bodySmall, color = TextBody)
        }
    }
}

private val categoryLabels = mapOf(
    "social" to "Mạng xã hội", "video" to "Video", "games" to "Trò chơi", "game" to "Trò chơi", "chat" to "Nhắn tin",
    "messaging" to "Nhắn tin", "music" to "Âm nhạc", "streaming" to "Phim/stream", "shopping" to "Mua sắm", "ai" to "AI", "other" to "Khác",
)

fun serviceCategoryLabel(c: String): String = categoryLabels[c.lowercase()] ?: c.replaceFirstChar { it.uppercase() }

/** Small explanation block (info icon + body text) used under SafeSearch, YouTube, categories… */
@Composable
internal fun InfoNote(text: String, modifier: Modifier = Modifier) {
    Row(
        modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).background(QuickActionBg).padding(12.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.Top,
    ) {
        Icon(Icons.Outlined.Info, contentDescription = null, tint = Primary, modifier = Modifier.size(18.dp).padding(top = 1.dp))
        Text(text, style = MaterialTheme.typography.bodySmall, color = TextBody, modifier = Modifier.weight(1f))
    }
}

/**
 * "Dịch vụ": full-height bottom sheet, services grouped by category, each with a dropdown
 * "Không áp dụng / Chặn / Cho phép". Narrow screens stack name and dropdown; wider ones put them side by side.
 */
@Composable
internal fun ServicesSheet(up: UserPolicy, orig: UserPolicy?, catalog: ServiceCatalog, onDismiss: () -> Unit, onSet: (String, ServiceState) -> Unit) {
    val allowlist = BlockingV2.allowlistActive(up)
    val options = BlockingV2.serviceOptions(allowlist).map { DropdownOption(it.state, it.label, it.note) }
    val groups = remember(catalog) { BlockingV2.groupedServices(catalog) }
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true), containerColor = Surface) {
        Column(Modifier.fillMaxWidth().fillMaxHeight().navigationBarsPadding()) {
            Row(Modifier.fillMaxWidth().padding(start = 20.dp, end = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("Dịch vụ", style = MaterialTheme.typography.titleLarge, color = TextPrimary)
                    Text(BlockingV2.servicesSummary(up.web), style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                }
                TextButton(onClick = onDismiss) { Text("Xong", style = MaterialTheme.typography.labelLarge, color = Primary) }
            }
            LazyColumn(
                Modifier.fillMaxWidth().weight(1f),
                contentPadding = PaddingValues(start = 20.dp, end = 20.dp, top = 8.dp, bottom = 24.dp),
            ) {
                item { InfoNote(BlockingV2.SERVICES_HELP, Modifier.padding(bottom = 8.dp)) }
                if (catalog.services.isEmpty()) item {
                    Text("Danh mục dịch vụ chưa có trong bản cài này.", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                }
                groups.forEach { (cat, list) ->
                    item(key = "h-$cat") {
                        Text(serviceCategoryLabel(cat), style = MaterialTheme.typography.titleSmall, color = TextSecondary,
                            modifier = Modifier.padding(top = 16.dp, bottom = 4.dp))
                    }
                    items(list, key = { it.id }) { s ->
                        val st = BlockingV2.serviceState(up.web, s.id)
                        val changed = orig != null && BlockingV2.serviceState(orig.web, s.id) != st
                        ServiceLine(s, st, changed, options) { onSet(s.id, it) }
                        HorizontalDivider(color = Divider)
                    }
                }
            }
        }
    }
}

@Composable
private fun ServiceLine(s: Service, st: ServiceState, changed: Boolean, options: List<DropdownOption<ServiceState>>, onPick: (ServiceState) -> Unit) {
    val color = when (st) { ServiceState.BLOCKED -> DangerText; ServiceState.ALLOWED -> Success; ServiceState.NONE -> TextPrimary }
    BoxWithConstraints(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
        val name = @Composable { m: Modifier ->
            Row(m, verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                val avatar = AvatarColors[(s.id.hashCode() and 0x7fffffff) % AvatarColors.size]
                Box(Modifier.size(32.dp).clip(CircleShape).background(avatar.first), contentAlignment = Alignment.Center) {
                    Text(s.name.take(1).uppercase(), style = MaterialTheme.typography.titleSmall, color = avatar.second)
                }
                Column(Modifier.weight(1f)) {
                    Text(s.name, style = MaterialTheme.typography.bodyMedium, color = TextPrimary, maxLines = 2, overflow = TextOverflow.Ellipsis)
                    if (changed) Text("Đã đổi — chưa áp dụng", style = MaterialTheme.typography.labelSmall, color = Primary)
                }
            }
        }
        if (maxWidth < 400.dp) {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                name(Modifier.fillMaxWidth())
                DropdownField(st, options, onPick, Modifier.fillMaxWidth().semantics { contentDescription = "${s.name}: ${BlockingV2.stateLabel(st)}" }, valueColor = color)
            }
        } else {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                name(Modifier.weight(1f))
                DropdownField(st, options, onPick, Modifier.width(220.dp).semantics { contentDescription = "${s.name}: ${BlockingV2.stateLabel(st)}" }, valueColor = color)
            }
        }
    }
}

/** "Từ khóa bị cấm": chips + add field (paste many, separated by comma / newline) + the two match toggles. */
@Composable
internal fun KeywordsEditor(up: UserPolicy, orig: UserPolicy?, edit: ((UserPolicy) -> UserPolicy) -> Unit) {
    var text by remember { mutableStateOf("") }
    val kw = up.keywords
    val words = kw?.words.orEmpty()
    val pending = BlockingV2.parseKeywords(text)
    Column(Modifier.fillMaxWidth().padding(vertical = 10.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Không phân biệt hoa thường và dấu (vd: “danh bai” khớp “đánh bài”). Khi gặp, máy tính đóng tab hoặc cửa sổ trong 1–2 giây.",
            style = MaterialTheme.typography.bodySmall, color = TextSecondary)
        if (words.isNotEmpty()) FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            words.forEach { w ->
                val shape = RoundedCornerShape(16.dp)
                Row(
                    Modifier.clip(shape).background(DangerContainer).clickable(onClickLabel = "Xóa từ khóa $w") { edit { BlockingV2.removeKeyword(it, w) } }
                        .padding(start = 12.dp, end = 8.dp, top = 6.dp, bottom = 6.dp),
                    verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Text(w, style = MaterialTheme.typography.labelMedium, color = DangerText, maxLines = 1, overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f, fill = false))
                    Text("✕", style = MaterialTheme.typography.labelMedium, color = DangerText)
                }
            }
        } else Text("Chưa có từ khóa nào.", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
        OutlinedTextField(
            text, { text = it }, modifier = Modifier.fillMaxWidth(), minLines = 1, maxLines = 5,
            label = { Text("Thêm từ khóa (dán nhiều, cách nhau bằng dấu phẩy hoặc xuống dòng)") },
        )
        TextButton(enabled = pending.isNotEmpty(), onClick = { edit { BlockingV2.addKeywords(it, text) }; text = "" }) {
            Text(if (pending.size > 1) "Thêm ${pending.size} từ khóa" else "Thêm")
        }
        ToggleLine("Chặn khi tìm kiếm", "Google, Bing, Cốc Cốc, YouTube, DuckDuckGo…", kw?.matchSearches ?: true,
            orig != null && (orig.keywords?.matchSearches ?: true) != (kw?.matchSearches ?: true)) { v -> edit { BlockingV2.setKeywordFlags(it, matchSearches = v) } }
        ToggleLine("Chặn khi tiêu đề trang/video chứa từ này", "Tiêu đề tab trình duyệt, video YouTube và cửa sổ ứng dụng khác", kw?.matchTitles ?: true,
            orig != null && (orig.keywords?.matchTitles ?: true) != (kw?.matchTitles ?: true)) { v -> edit { BlockingV2.setKeywordFlags(it, matchTitles = v) } }
    }
}

@Composable
private fun ToggleLine(title: String, sub: String, value: Boolean, changed: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyMedium, color = if (changed) Primary else TextPrimary)
            Text(sub, style = MaterialTheme.typography.bodySmall, color = TextSecondary)
        }
        McSwitch(value, onChange)
    }
}
