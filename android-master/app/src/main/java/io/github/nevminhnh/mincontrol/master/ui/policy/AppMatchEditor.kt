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
import io.github.nevminhnh.mincontrol.master.ui.theme.TextSecondary

/** "Chọn từ máy tính" picker + selected-match chips + "Nhập tay" fallback. Mutates [matches]. */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun AppMatchEditor(vm: PolicyViewModel, activity: FragmentActivity, groupLabel: String, matches: MutableList<AppMatch>) {
    val inv by vm.inventory.collectAsState()
    var picking by remember { mutableStateOf(false) }
    var manual by remember { mutableStateOf(false) }
    var query by remember { mutableStateOf("") }
    var manualText by remember { mutableStateOf("") }
    val selected = remember { mutableStateListOf<String>() }
    LaunchedEffect(picking) { if (picking) vm.loadInventory() }

    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text("Ứng dụng (${matches.size})", style = MaterialTheme.typography.titleSmall)
        if (matches.isNotEmpty()) FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            matches.toList().forEach { m ->
                InputChip(selected = false, onClick = { matches.remove(m) }, label = { Text(AppPicker.describe(m), maxLines = 1) },
                    trailingIcon = { Text("✕") })
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
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
                val shown = remember(s.apps, query) { AppPicker.sortFilter(s.apps, query) }
                OutlinedTextField(query, { query = it }, singleLine = true, label = { Text("Tìm ứng dụng") }, modifier = Modifier.fillMaxWidth())
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (AppPicker.isGameGroup(groupLabel)) TextButton(onClick = { selected.addAll(AppPicker.suggestGames(s.apps) - selected.toSet()) }) { Text("Gợi ý") }
                    TextButton(onClick = { vm.refreshInventory(activity) }) { Text("Làm mới") }
                }
                Column(Modifier.heightIn(max = 280.dp).verticalScroll(rememberScrollState())) {
                    shown.take(150).forEach { a -> AppRow(a, a.id in selected) { if (it) selected.add(a.id) else selected.remove(a.id) } }
                    if (shown.isEmpty()) Text("Không có ứng dụng phù hợp", color = TextSecondary)
                }
                TextButton(enabled = selected.isNotEmpty(), onClick = {
                    val merged = AppPicker.merge(matches.toList(), s.apps.filter { it.id in selected })
                    matches.clear(); matches.addAll(merged); selected.clear()
                }) { Text("Thêm ${selected.size} ứng dụng đã chọn") }
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
    Row(Modifier.fillMaxWidth().clickable { onChange(!checked) }, verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked, onChange)
        Column(Modifier.weight(1f)) {
            Text(a.name, style = MaterialTheme.typography.bodyMedium, maxLines = 1)
            val sub = listOfNotNull(a.publisher, a.minutes7d?.takeIf { it > 0 }?.let { "đã dùng $it phút / 7 ngày" }).joinToString(" · ")
            if (sub.isNotEmpty()) Text(sub, style = MaterialTheme.typography.bodySmall, color = TextSecondary, maxLines = 1)
        }
        AppPicker.categoryLabel(a.category)?.let { AssistChip(onClick = {}, label = { Text(it, style = MaterialTheme.typography.labelSmall) }) }
    }
}
