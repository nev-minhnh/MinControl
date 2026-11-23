package io.github.nevminhnh.mincontrol.master.ui.policy

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.InputChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import io.github.nevminhnh.mincontrol.master.data.protocol.AppMatch
import io.github.nevminhnh.mincontrol.master.data.protocol.InventoryApp
import io.github.nevminhnh.mincontrol.master.policy.AppPicker
import io.github.nevminhnh.mincontrol.master.ui.theme.TextBody
import io.github.nevminhnh.mincontrol.master.ui.theme.ChipBorder
import io.github.nevminhnh.mincontrol.master.ui.components.PrimaryButton
import io.github.nevminhnh.mincontrol.master.data.protocol.AppRule
import io.github.nevminhnh.mincontrol.master.data.protocol.RuleAction
import androidx.compose.foundation.border
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.background
import androidx.compose.ui.draw.clip
import androidx.compose.ui.unit.Dp
import io.github.nevminhnh.mincontrol.master.ui.theme.Surface
import androidx.compose.ui.text.style.TextOverflow
import io.github.nevminhnh.mincontrol.master.ui.theme.TextSecondary

/** "Chọn từ máy tính" picker + selected-match chips + "Nhập tay" fallback. Mutates [matches]. */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun AppMatchEditor(
    vm: PolicyViewModel, activity: FragmentActivity, groupLabel: String, matches: MutableList<AppMatch>,
    action: RuleAction? = null, rules: List<AppRule> = emptyList(),
    listHeight: Dp = 280.dp, startPicking: Boolean = false,
) {
    val inv by vm.inventory.collectAsState()
    var picking by remember { mutableStateOf(startPicking) }
    var manual by remember { mutableStateOf(false) }
    var query by remember { mutableStateOf("") }
    var manualText by remember { mutableStateOf("") }
    val selected = remember { mutableStateListOf<String>() }
    var showAll by remember { mutableStateOf(false) }
    LaunchedEffect(picking) { if (picking) vm.loadInventory() }

    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text("Ứng dụng đã chọn (${matches.size})", style = MaterialTheme.typography.titleSmall)
        // While the picker is open the chips collapse to a count, so the list and its button stay near the top.
        if (matches.isNotEmpty() && !picking) FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            matches.toList().forEach { m ->
                InputChip(selected = false, onClick = { matches.remove(m) },
                    label = { Text(AppPicker.describe(m), maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.widthIn(max = 200.dp)) },
                    trailingIcon = { Text("✕") })
            }
        }
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(onClick = { picking = !picking }) { Text(if (picking) "Đóng danh sách" else "Chọn từ máy tính") }
            TextButton(onClick = { manual = !manual }) { Text("Nhập tay") }
        }
        if (picking) when (val s = inv) {
            InventoryState.Idle, InventoryState.Loading -> CircularProgressIndicator()
            InventoryState.Refreshing -> Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                CircularProgressIndicator(Modifier.padding(4.dp)); Text("Đang chờ máy tính gửi danh sách…", color = TextBody)
            }
            InventoryState.Missing -> Column {
                Text("Máy chưa gửi danh sách ứng dụng — bấm Làm mới", color = TextBody)
                TextButton(onClick = { vm.refreshInventory(activity) }) { Text("Làm mới") }
            }
            is InventoryState.Failed -> Column {
                Text(s.message, color = TextBody)
                TextButton(onClick = { vm.refreshInventory(activity) }) { Text("Làm mới") }
            }
            is InventoryState.Ready -> {
                val list = remember(s.apps, query, showAll, action, rules) { AppPicker.pickerList(s.apps, query, rules, action, showAll) }
                val shown = list.apps
                OutlinedTextField(query, { query = it }, singleLine = true, label = { Text("Tìm ứng dụng") }, modifier = Modifier.fillMaxWidth())
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    if (AppPicker.isGameGroup(groupLabel)) TextButton(onClick = { selected.addAll(AppPicker.suggestGames(shown) - selected.toSet()) }) { Text("Gợi ý") }
                    TextButton(onClick = { vm.refreshInventory(activity) }) { Text("Làm mới") }
                    Row(Modifier.clickable { showAll = !showAll }.padding(end = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(showAll, { showAll = it })
                        Text("Hiện tất cả", style = MaterialTheme.typography.labelLarge)
                    }
                }
                if (list.hiddenOpposite > 0) Text(
                    "Đã ẩn ${list.hiddenOpposite} ứng dụng đang nằm trong danh sách “${if (action == RuleAction.BLOCK) "Cho phép" else "Chặn"}”. " +
                        "Muốn đổi, hãy xóa quy tắc đó trước.",
                    style = MaterialTheme.typography.bodySmall, color = TextSecondary,
                )
                if (!showAll && list.hiddenSystem > 0) Text("Đã ẩn ${list.hiddenSystem} ứng dụng hệ thống — chọn “Hiện tất cả” để xem.",
                    style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                // Fixed-height bordered box with its own scroll: the button below is always right under it.
                val boxShape = RoundedCornerShape(12.dp)
                LazyColumn(
                    Modifier.fillMaxWidth().height(listHeight).clip(boxShape).border(1.dp, ChipBorder, boxShape).background(Surface),
                    contentPadding = PaddingValues(vertical = 4.dp),
                ) {
                    items(shown.take(300), key = { it.id }) { a -> AppRow(a, a.id in selected) { if (it) selected.add(a.id) else selected.remove(a.id) } }
                    if (shown.isEmpty()) item { Text("Không có ứng dụng phù hợp", color = TextSecondary, modifier = Modifier.padding(12.dp)) }
                }
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (selected.isNotEmpty()) TextButton(onClick = { selected.clear() }) { Text("Bỏ chọn") }
                    Spacer(Modifier.weight(1f))
                    PrimaryButton(
                        if (selected.isEmpty()) "Chọn ứng dụng" else "Chọn ${selected.size} ứng dụng",
                        onClick = {
                            val merged = AppPicker.merge(matches.toList(), s.apps.filter { it.id in selected })
                            matches.clear(); matches.addAll(merged); selected.clear(); picking = false
                        },
                        enabled = selected.isNotEmpty(), height = 44.dp,
                    )
                }
            }
        }
        if (manual) {
            OutlinedTextField(manualText, { manualText = it }, label = { Text("Mỗi dòng: Minecraft*.exe hoặc publisher:Valve*") }, minLines = 2, modifier = Modifier.fillMaxWidth())
            TextButton(enabled = manualText.isNotBlank(), onClick = {
                AppPicker.parseManual(manualText).forEach { if (it !in matches) matches.add(it) }
                manualText = ""
            }) { Text("Thêm") }
        }
    }
}

@Composable
private fun AppRow(a: InventoryApp, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth().clickable { onChange(!checked) }.padding(end = 8.dp), verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked, onChange)
        Column(Modifier.weight(1f)) {
            Text(a.name, style = MaterialTheme.typography.bodyMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
            val sub = listOfNotNull(a.publisher, a.minutes7d?.takeIf { it > 0 }?.let { "đã dùng $it phút / 7 ngày" }).joinToString(" · ")
            if (sub.isNotEmpty()) Text(sub, style = MaterialTheme.typography.bodySmall, color = TextSecondary, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        AppPicker.categoryLabel(a.category)?.let {
            Text(it, style = MaterialTheme.typography.labelSmall, color = TextBody, maxLines = 1,
                modifier = Modifier.padding(start = 4.dp).border(1.dp, ChipBorder, RoundedCornerShape(8.dp)).padding(horizontal = 6.dp, vertical = 2.dp))
        }
    }
}
