package io.github.nevminhnh.mincontrol.master.ui.policy

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ChevronRight
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import io.github.nevminhnh.mincontrol.master.data.protocol.AppGroup
import io.github.nevminhnh.mincontrol.master.data.protocol.AppMatch
import io.github.nevminhnh.mincontrol.master.data.protocol.NewExecutable
import io.github.nevminhnh.mincontrol.master.data.protocol.UserPolicy
import io.github.nevminhnh.mincontrol.master.data.protocol.WebCategory
import io.github.nevminhnh.mincontrol.master.data.protocol.WebMode
import io.github.nevminhnh.mincontrol.master.data.protocol.Weekday
import io.github.nevminhnh.mincontrol.master.data.protocol.WeekdayMinutes
import io.github.nevminhnh.mincontrol.master.data.protocol.WeekdayWindows
import io.github.nevminhnh.mincontrol.master.data.protocol.YouTubeMode
import io.github.nevminhnh.mincontrol.master.policy.PolicyDiff
import io.github.nevminhnh.mincontrol.master.policy.PolicyValidation
import io.github.nevminhnh.mincontrol.master.policy.formatMinutes
import io.github.nevminhnh.mincontrol.master.ui.ChildSwitcher
import io.github.nevminhnh.mincontrol.master.ui.components.EmptyState
import io.github.nevminhnh.mincontrol.master.ui.components.McCard
import io.github.nevminhnh.mincontrol.master.ui.components.McSwitch
import io.github.nevminhnh.mincontrol.master.ui.components.PrimaryButton
import io.github.nevminhnh.mincontrol.master.ui.components.SectionLabel
import io.github.nevminhnh.mincontrol.master.ui.components.SettingRow
import io.github.nevminhnh.mincontrol.master.ui.rememberActivity
import io.github.nevminhnh.mincontrol.master.ui.theme.Background
import io.github.nevminhnh.mincontrol.master.ui.theme.ChipBorder
import io.github.nevminhnh.mincontrol.master.ui.theme.DangerText
import io.github.nevminhnh.mincontrol.master.ui.theme.Outline
import io.github.nevminhnh.mincontrol.master.ui.theme.Primary
import io.github.nevminhnh.mincontrol.master.ui.theme.Surface
import io.github.nevminhnh.mincontrol.master.ui.theme.TextBody
import io.github.nevminhnh.mincontrol.master.ui.theme.TextPrimary
import io.github.nevminhnh.mincontrol.master.ui.theme.TextSecondary

private val WEEKDAYS = listOf(Weekday.MON, Weekday.TUE, Weekday.WED, Weekday.THU, Weekday.FRI)
private val WEEKEND = listOf(Weekday.SAT, Weekday.SUN)
private const val STEP = 15

private sealed interface PolicyDialog {
    data class Windows(val days: List<Weekday>, val title: String) : PolicyDialog
    data class Group(val id: String?) : PolicyDialog
    data object Categories : PolicyDialog
    data class Domains(val block: Boolean) : PolicyDialog
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PolicyScreen(vm: PolicyViewModel = viewModel()) {
    val activity = rememberActivity()
    val children by vm.children.collectAsState()
    val child by vm.child.collectAsState()
    val current by vm.current.collectAsState()
    val changes by vm.changes.collectAsState()
    val loading by vm.loading.collectAsState()
    val applying by vm.applying.collectAsState()
    val message by vm.message.collectAsState()
    val snackbar = remember { SnackbarHostState() }
    var dialog by remember { mutableStateOf<PolicyDialog?>(null) }
    var review by remember { mutableStateOf(false) }
    var perDay by remember { mutableStateOf(false) }
    LaunchedEffect(message) { message?.let { snackbar.showSnackbar(it); vm.message.value = null } }

    val c = child
    val up = c?.let { current?.draft?.users?.get(it.sid) }
    val orig = c?.let { current?.original?.users?.get(it.sid) }

    Box(Modifier.fillMaxSize().background(Background)) {
        Column(Modifier.fillMaxSize().statusBarsPadding()) {
            Row(
                Modifier.fillMaxWidth().padding(start = 16.dp, end = 16.dp, top = 24.dp, bottom = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text("Quy tắc", style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
                ChildSwitcher(children, c, { vm.select(it) })
            }
            if (up == null) {
                if (loading) Box(Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) { CircularProgressIndicator(color = Primary) }
                else EmptyState(if (c == null) "Chưa có máy tính nào được quản lý" else "Không tải được quy tắc")
            } else {
                Column(
                    Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(start = 16.dp, end = 16.dp, bottom = 24.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Editor(up, orig, perDay, { perDay = !perDay }, vm::edit) { dialog = it }
                }
            }
            if (changes.isNotEmpty()) {
                HorizontalDivider(color = Outline)
                Row(
                    Modifier.fillMaxWidth().background(Surface).padding(horizontal = 16.dp, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Text(
                        buildAnnotatedString {
                            withStyle(SpanStyle(fontWeight = FontWeight.SemiBold, color = TextPrimary)) { append("${changes.size} thay đổi") }
                            append(" chưa áp dụng")
                        },
                        style = MaterialTheme.typography.bodySmall, color = TextBody, modifier = Modifier.weight(1f),
                    )
                    PrimaryButton("Xem & áp dụng", { review = true }, icon = Icons.Outlined.Fingerprint)
                }
            }
        }
        SnackbarHost(snackbar, Modifier.align(Alignment.BottomCenter).padding(16.dp))
    }

    if (up != null) when (val d = dialog) {
        is PolicyDialog.Windows -> WindowsDialog(d.title, up.screenTime.allowedWindows.get(d.days.first()), { dialog = null }) { list ->
            vm.edit { u -> u.copy(screenTime = u.screenTime.copy(allowedWindows = d.days.fold(u.screenTime.allowedWindows) { w, day -> w.with(day, list) })) }
            dialog = null
        }
        is PolicyDialog.Group -> GroupDialog(d.id, d.id?.let { up.appGroups[it] }, { dialog = null }) { id, g ->
            vm.edit { u -> u.copy(appGroups = if (g == null) u.appGroups - id else u.appGroups + (id to g)) }
            dialog = null
        }
        PolicyDialog.Categories -> CategoriesDialog(up, { dialog = null }) { blocked, schedules ->
            vm.edit { u -> u.copy(web = u.web.copy(blockedCategories = blocked, categorySchedules = schedules.ifEmpty { null })) }
            dialog = null
        }
        is PolicyDialog.Domains -> DomainsDialog(d.block, if (d.block) up.web.blockDomains else up.web.allowDomains, { dialog = null }) { list ->
            vm.edit { u -> u.copy(web = if (d.block) u.web.copy(blockDomains = list) else u.web.copy(allowDomains = list)) }
            dialog = null
        }
        null -> {}
    }

    if (review) {
        ModalBottomSheet(onDismissRequest = { review = false }, sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true), containerColor = Surface) {
            Column(Modifier.fillMaxWidth().padding(start = 24.dp, end = 24.dp, bottom = 24.dp).navigationBarsPadding(), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("${changes.size} thay đổi", style = MaterialTheme.typography.titleLarge)
                Column(Modifier.heightIn(max = 360.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    changes.forEach { ch ->
                        Column {
                            Text(ch.title, style = MaterialTheme.typography.titleSmall)
                            Text("${ch.from} → ${ch.to}", style = MaterialTheme.typography.bodySmall, color = TextBody)
                        }
                    }
                }
                val errs = vm.errors()
                errs.forEach { Text(it, style = MaterialTheme.typography.bodySmall, color = DangerText) }
                Text("Phiên bản mới: ${(current?.original?.version ?: 0) + 1} · gửi tới ${c?.hostname ?: ""}",
                    style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                if (applying) {
                    Box(Modifier.fillMaxWidth().height(56.dp), contentAlignment = Alignment.Center) { CircularProgressIndicator(color = Primary) }
                } else {
                    PrimaryButton("Ký & áp dụng bằng vân tay", { vm.apply(activity) { review = false } }, Modifier.fillMaxWidth(),
                        height = 56.dp, radius = 16.dp, enabled = errs.isEmpty(), icon = Icons.Outlined.Fingerprint)
                    TextButton(onClick = { vm.discard(); review = false }, modifier = Modifier.fillMaxWidth()) {
                        Text("Bỏ các thay đổi", color = TextBody, style = MaterialTheme.typography.labelLarge)
                    }
                }
            }
        }
    }
}

@Composable
private fun Editor(
    up: UserPolicy, orig: UserPolicy?, perDay: Boolean, togglePerDay: () -> Unit,
    edit: ((UserPolicy) -> UserPolicy) -> Unit, open: (PolicyDialog) -> Unit,
) {
    val st = up.screenTime
    val ost = orig?.screenTime
    fun quotaOf(days: List<Weekday>, m: WeekdayMinutes) = days.map { m.get(it) }.distinct().singleOrNull()
    fun setQuota(days: List<Weekday>, v: Int) = edit { u ->
        u.copy(screenTime = u.screenTime.copy(dailyQuotaMin = days.fold(u.screenTime.dailyQuotaMin) { m, d -> m.with(d, v.coerceIn(0, 1440)) }))
    }
    fun changedQuota(days: List<Weekday>) = ost != null && days.any { ost.dailyQuotaMin.get(it) != st.dailyQuotaMin.get(it) }
    fun changedWindows(days: List<Weekday>) = ost != null && days.any { ost.allowedWindows.get(it) != st.allowedWindows.get(it) }
    fun windowsText(days: List<Weekday>, w: WeekdayWindows): String {
        val distinct = days.map { w.get(it) }.distinct()
        return if (distinct.size == 1) {
            val l = distinct.first()
            if (l.isEmpty()) "Không cho dùng" else l.joinToString(", ") { it.replace("-", " – ") }
        } else "Khác nhau"
    }

    SectionLabel("Thời gian sử dụng")
    PolicyCard {
        QuotaRow("Ngày thường", quotaOf(WEEKDAYS, st.dailyQuotaMin), changedQuota(WEEKDAYS), { setQuota(WEEKDAYS, it) }, st.dailyQuotaMin.get(Weekday.MON))
        QuotaRow("Cuối tuần", quotaOf(WEEKEND, st.dailyQuotaMin), changedQuota(WEEKEND), { setQuota(WEEKEND, it) }, st.dailyQuotaMin.get(Weekday.SAT))
        SettingRow("Từng ngày", subtitle = if (perDay) "Đặt riêng cho mỗi ngày" else "Chạm để đặt riêng", onClick = togglePerDay) {
            Icon(Icons.Outlined.ChevronRight, null, tint = TextSecondary)
        }
        if (perDay) Weekday.entries.forEach { d ->
            QuotaRow(d.label, st.dailyQuotaMin.get(d), changedQuota(listOf(d)), { setQuota(listOf(d), it) }, st.dailyQuotaMin.get(d))
        }
        SettingRow("Khung giờ được dùng", subtitle = "Thứ 2 – Thứ 6", changed = changedWindows(WEEKDAYS),
            onClick = { open(PolicyDialog.Windows(WEEKDAYS, "Khung giờ · Thứ 2 – Thứ 6")) }) {
            Text(windowsText(WEEKDAYS, st.allowedWindows), style = MaterialTheme.typography.titleMedium.copy(fontFeatureSettings = "tnum"))
        }
        SettingRow("Khung giờ được dùng", subtitle = "Thứ 7 – Chủ nhật", changed = changedWindows(WEEKEND), last = !perDay,
            onClick = { open(PolicyDialog.Windows(WEEKEND, "Khung giờ · Cuối tuần")) }) {
            Text(windowsText(WEEKEND, st.allowedWindows), style = MaterialTheme.typography.titleMedium.copy(fontFeatureSettings = "tnum"))
        }
        if (perDay) Weekday.entries.forEachIndexed { i, d ->
            SettingRow("Khung giờ · ${d.label}", changed = changedWindows(listOf(d)), last = i == 6,
                onClick = { open(PolicyDialog.Windows(listOf(d), "Khung giờ · ${d.label}")) }) {
                Text(windowsText(listOf(d), st.allowedWindows), style = MaterialTheme.typography.bodySmall)
            }
        }
    }

    SectionLabel("Ứng dụng", Modifier.padding(top = 8.dp))
    PolicyCard {
        up.appGroups.forEach { (id, g) ->
            val q = g.dailyQuotaMin
            val text = when {
                q == null -> "Không giới hạn"
                Weekday.entries.map { q.get(it) }.distinct().size == 1 -> "${formatMinutes(q.mon)} / ngày"
                else -> "${formatMinutes(q.mon)} · ${formatMinutes(q.sat)}"
            }
            SettingRow(g.label, subtitle = "${g.match.size} mẫu ứng dụng", changed = orig != null && orig.appGroups[id] != g,
                onClick = { open(PolicyDialog.Group(id)) }) {
                Text(text, style = MaterialTheme.typography.titleMedium)
            }
        }
        SettingRow("Thêm nhóm ứng dụng", onClick = { open(PolicyDialog.Group(null)) }) {
            Text("+", style = MaterialTheme.typography.titleLarge, color = Primary)
        }
        Dropdown(
            "Ứng dụng lạ",
            subtitle = when (up.newExecutable) {
                NewExecutable.ASK -> "Chặn và hỏi anh trước"; NewExecutable.ALLOW -> "Cho chạy, chỉ ghi lại"; NewExecutable.BLOCK -> "Luôn chặn"
            },
            value = PolicyDiff.newExeLabel(up.newExecutable),
            options = NewExecutable.entries.map { PolicyDiff.newExeLabel(it) to it },
            changed = orig != null && orig.newExecutable != up.newExecutable, last = true,
        ) { v -> edit { it.copy(newExecutable = v) } }
    }

    val w = up.web
    val ow = orig?.web
    SectionLabel("Web", Modifier.padding(top = 8.dp))
    PolicyCard {
        Dropdown("Chế độ", value = PolicyDiff.webModeLabel(w.mode), options = WebMode.entries.map { PolicyDiff.webModeLabel(it) to it },
            changed = ow != null && ow.mode != w.mode) { v -> edit { it.copy(web = it.web.copy(mode = v)) } }
        SettingRow("SafeSearch", changed = ow != null && ow.safeSearch != w.safeSearch) {
            McSwitch(w.safeSearch) { v -> edit { it.copy(web = it.web.copy(safeSearch = v)) } }
        }
        Dropdown("YouTube", value = PolicyDiff.youtubeLabel(w.youtube), options = YouTubeMode.entries.map { PolicyDiff.youtubeLabel(it) to it },
            changed = ow != null && ow.youtube != w.youtube) { v -> edit { it.copy(web = it.web.copy(youtube = v)) } }
        val catText = (w.blockedCategories.map { it.label } + w.categorySchedules.orEmpty().keys.map { "${it.label} (giờ học)" })
            .joinToString(", ").ifEmpty { "Không chặn danh mục nào" }
        SettingRow("Danh mục chặn", subtitle = catText,
            changed = ow != null && (ow.blockedCategories.toSet() != w.blockedCategories.toSet() || ow.categorySchedules.orEmpty() != w.categorySchedules.orEmpty()),
            onClick = { open(PolicyDialog.Categories) }) { Icon(Icons.Outlined.ChevronRight, null, tint = TextSecondary) }
        SettingRow("Trang bị chặn", subtitle = "${w.blockDomains.size} tên miền", changed = ow != null && ow.blockDomains != w.blockDomains,
            onClick = { open(PolicyDialog.Domains(true)) }) { Icon(Icons.Outlined.ChevronRight, null, tint = TextSecondary) }
        SettingRow("Trang luôn cho phép", subtitle = "${w.allowDomains.size} tên miền", changed = ow != null && ow.allowDomains != w.allowDomains, last = true,
            onClick = { open(PolicyDialog.Domains(false)) }) { Icon(Icons.Outlined.ChevronRight, null, tint = TextSecondary) }
    }

    val m = up.monitoring
    val om = orig?.monitoring
    SectionLabel("Giám sát", Modifier.padding(top = 8.dp))
    PolicyCard {
        Toggle("Ghi tiêu đề cửa sổ", m.foregroundTitles, om?.foregroundTitles) { v -> edit { it.copy(monitoring = it.monitoring.copy(foregroundTitles = v)) } }
        Toggle("Lịch sử trình duyệt", m.browserHistory, om?.browserHistory) { v -> edit { it.copy(monitoring = it.monitoring.copy(browserHistory = v)) } }
        Toggle("Nhật ký tên miền", m.domainLog, om?.domainLog) { v -> edit { it.copy(monitoring = it.monitoring.copy(domainLog = v)) } }
        Toggle("Tải xuống", m.downloads, om?.downloads) { v -> edit { it.copy(monitoring = it.monitoring.copy(downloads = v)) } }
        Toggle("USB", m.usb, om?.usb) { v -> edit { it.copy(monitoring = it.monitoring.copy(usb = v)) } }
        Dropdown(
            "Ảnh màn hình", value = PolicyDiff.screenshotLabel(m.screenshots.intervalMin),
            options = listOf(0, 5, 10, 15, 30, 60).map { PolicyDiff.screenshotLabel(it) to it },
            changed = om != null && om.screenshots.intervalMin != m.screenshots.intervalMin, last = true,
        ) { v -> edit { it.copy(monitoring = it.monitoring.copy(screenshots = it.monitoring.screenshots.copy(intervalMin = v))) } }
    }
}

@Composable
private fun PolicyCard(content: @Composable () -> Unit) {
    McCard(radius = 20.dp, padding = PaddingValues(horizontal = 16.dp, vertical = 4.dp)) { content() }
}

@Composable
private fun QuotaRow(title: String, value: Int?, changed: Boolean, onSet: (Int) -> Unit, base: Int) {
    SettingRow(title, changed = changed) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            StepButton("−", "Giảm") { onSet(((value ?: base) - STEP).coerceAtLeast(0)) }
            Text(value?.let { formatMinutes(it) } ?: "Khác nhau", style = MaterialTheme.typography.titleMedium.copy(fontFeatureSettings = "tnum"),
                modifier = Modifier.widthIn(min = 64.dp), textAlign = androidx.compose.ui.text.style.TextAlign.Center)
            StepButton("+", "Tăng") { onSet(((value ?: base) + STEP).coerceAtMost(1440)) }
        }
    }
}

@Composable
private fun StepButton(text: String, label: String, onClick: () -> Unit) {
    Box(
        Modifier.size(36.dp).clip(CircleShape).background(Surface).border(1.dp, ChipBorder, CircleShape).clickable(onClickLabel = label, onClick = onClick),
        contentAlignment = Alignment.Center,
    ) { Text(text, style = MaterialTheme.typography.titleMedium) }
}

@Composable
private fun Toggle(title: String, value: Boolean, orig: Boolean?, onChange: (Boolean) -> Unit) {
    SettingRow(title, changed = orig != null && orig != value) { McSwitch(value, onChange) }
}

@Composable
private fun <T> Dropdown(
    title: String, value: String, options: List<Pair<String, T>>, changed: Boolean, subtitle: String? = null, last: Boolean = false,
    onPick: (T) -> Unit,
) {
    var open by remember { mutableStateOf(false) }
    SettingRow(title, subtitle = subtitle, changed = changed, last = last, onClick = { open = true }) {
        Box {
            Text("$value ▾", style = MaterialTheme.typography.titleMedium, color = Primary)
            DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
                options.forEach { (label, v) -> DropdownMenuItem(text = { Text(label) }, onClick = { open = false; onPick(v) }) }
            }
        }
    }
}

// ---------------- dialogs ----------------

@Composable
private fun WindowsDialog(title: String, initial: List<String>, onDismiss: () -> Unit, onSave: (List<String>) -> Unit) {
    val rows = remember { mutableStateListOf<Pair<String, String>>().apply { initial.forEach { add(it.substringBefore('-') to it.substringAfter('-')) } } }
    val list = rows.map { "${it.first.trim()}-${it.second.trim()}" }
    val error = PolicyValidation.windowsError(list)
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (rows.isEmpty()) Text("Không cho dùng máy trong ngày này.", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                rows.forEachIndexed { i, (a, b) ->
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedTextField(a, { rows[i] = it.take(5) to b }, Modifier.weight(1f), singleLine = true, label = { Text("Từ") })
                        OutlinedTextField(b, { rows[i] = a to it.take(5) }, Modifier.weight(1f), singleLine = true, label = { Text("Đến") })
                        TextButton(onClick = { rows.removeAt(i) }) { Text("Xóa", color = DangerText) }
                    }
                }
                if (rows.size < 8) TextButton(onClick = { rows.add("15:00" to "21:00") }) { Text("+ Thêm khung giờ") }
                error?.let { Text(it, color = DangerText, style = MaterialTheme.typography.bodySmall) }
            }
        },
        confirmButton = { TextButton(onClick = { onSave(list.sortedBy { it }) }, enabled = error == null) { Text("Lưu") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Hủy") } },
        containerColor = Surface,
    )
}

@Composable
private fun GroupDialog(id: String?, group: AppGroup?, onDismiss: () -> Unit, onSave: (String, AppGroup?) -> Unit) {
    var label by remember { mutableStateOf(group?.label ?: "") }
    var key by remember { mutableStateOf(id ?: "") }
    var patterns by remember {
        mutableStateOf(group?.match.orEmpty().joinToString("\n") { m ->
            m.exe?.let { "exe:$it" } ?: m.publisher?.let { "publisher:$it" } ?: m.path?.let { "path:$it" } ?: m.sha256?.let { "sha256:$it" } ?: ""
        })
    }
    var limited by remember { mutableStateOf(group?.dailyQuotaMin != null) }
    var weekday by remember { mutableStateOf(group?.dailyQuotaMin?.mon ?: 60) }
    var weekend by remember { mutableStateOf(group?.dailyQuotaMin?.sat ?: 60) }
    val matches = patterns.lines().map { it.trim() }.filter { it.isNotEmpty() }.map { line ->
        val (k, v) = if (':' in line) line.substringBefore(':').lowercase() to line.substringAfter(':').trim() else "exe" to line
        when (k) {
            "publisher" -> AppMatch(publisher = v); "path" -> AppMatch(path = v); "sha256" -> AppMatch(sha256 = v.lowercase()); else -> AppMatch(exe = v)
        }
    }
    val keyOk = Regex("^[a-z][a-z0-9_-]{0,31}$").matches(key)
    val ok = keyOk && label.isNotBlank() && matches.isNotEmpty()
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (group == null) "Nhóm ứng dụng mới" else "Nhóm ${group.label}") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(label, { label = it.take(40) }, singleLine = true, label = { Text("Tên nhóm") }, modifier = Modifier.fillMaxWidth())
                if (id == null) OutlinedTextField(key, { key = it.lowercase().take(32) }, singleLine = true, label = { Text("Mã nhóm (vd: games)") },
                    isError = key.isNotEmpty() && !keyOk, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(patterns, { patterns = it }, label = { Text("Ứng dụng (mỗi dòng: Minecraft*.exe hoặc publisher:Valve*)") },
                    minLines = 3, modifier = Modifier.fillMaxWidth())
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Giới hạn thời gian", modifier = Modifier.weight(1f))
                    McSwitch(limited) { limited = it }
                }
                if (limited) {
                    QuotaRow("Ngày thường", weekday, false, { weekday = it }, weekday)
                    QuotaRow("Cuối tuần", weekend, false, { weekend = it }, weekend)
                }
                if (id != null) TextButton(onClick = { onSave(id, null) }) { Text("Xóa nhóm này", color = DangerText) }
            }
        },
        confirmButton = {
            TextButton(enabled = ok, onClick = {
                onSave(key, AppGroup(label.trim(), matches, if (limited) WeekdayMinutes.of(weekday, weekend) else null))
            }) { Text("Lưu") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Hủy") } },
        containerColor = Surface,
    )
}

private enum class CatState(val label: String) { OFF("Không chặn"), ALWAYS("Luôn chặn"), SCHEDULE("Trong giờ học") }
private val SCHEDULABLE = setOf(WebCategory.GAMES, WebCategory.SOCIAL, WebCategory.VIDEO)

@Composable
private fun CategoriesDialog(up: UserPolicy, onDismiss: () -> Unit, onSave: (List<WebCategory>, Map<WebCategory, WeekdayWindows>) -> Unit) {
    val state = remember {
        androidx.compose.runtime.mutableStateMapOf<WebCategory, CatState>().apply {
            WebCategory.entries.forEach { c ->
                put(c, when { c in up.web.blockedCategories -> CatState.ALWAYS; up.web.categorySchedules?.containsKey(c) == true -> CatState.SCHEDULE; else -> CatState.OFF })
            }
        }
    }
    val existing = up.web.categorySchedules?.values?.firstOrNull()?.mon
    var study by remember { mutableStateOf((existing ?: listOf("07:00-11:30", "13:30-17:00")).joinToString(", ")) }
    val studyList = study.split(',').map { it.trim().replace(" ", "") }.filter { it.isNotEmpty() }
    val studyErr = PolicyValidation.windowsError(studyList)
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Danh mục chặn") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                WebCategory.entries.forEach { c ->
                    val s = state[c] ?: CatState.OFF
                    var open by remember { mutableStateOf(false) }
                    Row(Modifier.fillMaxWidth().clickable { open = true }.padding(vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                        Text(c.label, modifier = Modifier.weight(1f))
                        Box {
                            Text("${s.label} ▾", color = if (s == CatState.OFF) TextSecondary else Primary, style = MaterialTheme.typography.titleSmall)
                            DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
                                CatState.entries.filter { it != CatState.SCHEDULE || c in SCHEDULABLE }.forEach { o ->
                                    DropdownMenuItem(text = { Text(o.label) }, onClick = { state[c] = o; open = false })
                                }
                            }
                        }
                    }
                }
                if (state.values.any { it == CatState.SCHEDULE }) {
                    OutlinedTextField(study, { study = it }, label = { Text("Giờ học (Thứ 2 – Thứ 6)") }, isError = studyErr != null, modifier = Modifier.fillMaxWidth())
                    studyErr?.let { Text(it, color = DangerText, style = MaterialTheme.typography.bodySmall) }
                }
            }
        },
        confirmButton = {
            TextButton(enabled = studyErr == null || state.values.none { it == CatState.SCHEDULE }, onClick = {
                val windows = WeekdayWindows.of(studyList, emptyList())
                onSave(
                    WebCategory.entries.filter { state[it] == CatState.ALWAYS },
                    WebCategory.entries.filter { state[it] == CatState.SCHEDULE }.associateWith { windows },
                )
            }) { Text("Lưu") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Hủy") } },
        containerColor = Surface,
    )
}

@Composable
private fun DomainsDialog(block: Boolean, initial: List<String>, onDismiss: () -> Unit, onSave: (List<String>) -> Unit) {
    var text by remember { mutableStateOf(initial.joinToString("\n")) }
    val list = text.lines().map { it.trim().lowercase() }.filter { it.isNotEmpty() }.distinct()
    val err = list.firstNotNullOfOrNull { PolicyValidation.domainError(it) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (block) "Trang bị chặn" else "Trang luôn cho phép") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Mỗi dòng một tên miền, vd: poki.com hoặc *.edu.vn", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                OutlinedTextField(text, { text = it }, minLines = 5, isError = err != null, modifier = Modifier.fillMaxWidth())
                err?.let { Text(it, color = DangerText, style = MaterialTheme.typography.bodySmall) }
            }
        },
        confirmButton = { TextButton(enabled = err == null, onClick = { onSave(list) }) { Text("Lưu") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Hủy") } },
        containerColor = Surface,
    )
}
