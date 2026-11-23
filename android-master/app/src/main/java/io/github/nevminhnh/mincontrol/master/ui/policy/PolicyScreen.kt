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
import androidx.compose.foundation.layout.imePadding
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
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
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
import io.github.nevminhnh.mincontrol.master.ui.activity.WebLabels
import io.github.nevminhnh.mincontrol.master.data.protocol.WebMode
import io.github.nevminhnh.mincontrol.master.data.protocol.Weekday
import io.github.nevminhnh.mincontrol.master.data.protocol.WeekdayMinutes
import io.github.nevminhnh.mincontrol.master.data.protocol.WeekdayWindows
import io.github.nevminhnh.mincontrol.master.data.protocol.YouTubeMode
import io.github.nevminhnh.mincontrol.master.data.protocol.RuleAction
import io.github.nevminhnh.mincontrol.master.policy.AppRules
import io.github.nevminhnh.mincontrol.master.policy.PolicyHelp
import io.github.nevminhnh.mincontrol.master.data.protocol.AppRule
import io.github.nevminhnh.mincontrol.master.policy.PolicyDiff
import io.github.nevminhnh.mincontrol.master.refresh.AutoRefreshEffect
import io.github.nevminhnh.mincontrol.master.refresh.RefreshBox
import io.github.nevminhnh.mincontrol.master.refresh.UpdatedLine
import io.github.nevminhnh.mincontrol.master.policy.PolicyValidation
import io.github.nevminhnh.mincontrol.master.policy.formatMinutes
import io.github.nevminhnh.mincontrol.master.policy.formatWindows
import io.github.nevminhnh.mincontrol.master.ui.ChildSwitcher
import io.github.nevminhnh.mincontrol.master.ui.components.TabHeader
import io.github.nevminhnh.mincontrol.master.data.Child
import io.github.nevminhnh.mincontrol.master.data.protocol.AppMode
import io.github.nevminhnh.mincontrol.master.policy.BlockingV2
import io.github.nevminhnh.mincontrol.master.policy.ServiceCatalog
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.foundation.horizontalScroll
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
    data object NetExempt : PolicyDialog
    data class AppRuleAdd(val action: RuleAction) : PolicyDialog
    data object Services : PolicyDialog
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PolicyScreen(onSettings: (() -> Unit)? = null, vm: PolicyViewModel = viewModel()) {
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
    val focusManager = androidx.compose.ui.platform.LocalFocusManager.current
    var perDay by remember { mutableStateOf(false) }
    LaunchedEffect(message) { message?.let { snackbar.showSnackbar(it); vm.message.value = null } }
    AutoRefreshEffect(vm.refresher)

    val c = child
    val up = c?.let { current?.draft?.users?.get(it.sid) }
    val orig = c?.let { current?.original?.users?.get(it.sid) }
    val ctx = androidx.compose.ui.platform.LocalContext.current
    val catalog = remember { ServiceCatalog.load(ctx) }
    val engines = remember { io.github.nevminhnh.mincontrol.master.policy.SearchEngines.load(ctx) }
    val groupCatalog = remember { io.github.nevminhnh.mincontrol.master.policy.AppGroupCatalog.current }

    Box(Modifier.fillMaxSize().background(Background)) {
        Column(Modifier.fillMaxSize().statusBarsPadding()) {
            PolicyHeader(children, c, { vm.select(it) }, onSettings)
            if (up == null) {
                if (loading) Box(Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) { CircularProgressIndicator(color = Primary) }
                else EmptyState(if (c == null) "Chưa có máy tính nào được quản lý" else "Không tải được quy tắc")
            } else {
                RefreshBox(vm.refresher, Modifier.weight(1f)) {
                    Column(
                        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(start = 16.dp, end = 16.dp, bottom = 24.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        UpdatedLine(vm.refresher)
                        Editor(up, orig, perDay, { perDay = !perDay }, vm::edit, catalog, engines, groupCatalog) { dialog = it }
                    }
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
        is PolicyDialog.Group -> GroupEditor(vm, activity, d.id, d.id?.let { up.appGroups[it] }, up.appGroups.keys, { dialog = null }) { id, g ->
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
        is PolicyDialog.AppRuleAdd -> AppRuleDialog(vm, activity, up, d.action, { dialog = null }) { action, matches ->
            vm.edit { u -> u.copy(appRules = AppRules.add(u.appRules, action, matches)) }
            dialog = null
        }
        PolicyDialog.NetExempt -> NetExemptDialog(up.web.netExemptApps, { dialog = null }) { list ->
            vm.edit { u -> u.copy(web = u.web.copy(netExemptApps = list)) }
            dialog = null
        }
        PolicyDialog.Services -> ServicesSheet(up, orig, catalog, { dialog = null }) { id, st -> vm.edit { BlockingV2.setServiceState(it, id, st) } }
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
                    PrimaryButton("Ký & áp dụng bằng vân tay", { focusManager.clearFocus(); vm.apply(activity) { review = false } }, Modifier.fillMaxWidth(),
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
    edit: ((UserPolicy) -> UserPolicy) -> Unit, catalog: ServiceCatalog, engines: List<String>,
    groupCatalog: io.github.nevminhnh.mincontrol.master.policy.AppGroupCatalog, open: (PolicyDialog) -> Unit,
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
            formatWindows(distinct.first())
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
            Text(windowsText(WEEKDAYS, st.allowedWindows), style = MaterialTheme.typography.titleMedium.copy(fontFeatureSettings = "tnum"), maxLines = 2, overflow = TextOverflow.Ellipsis, textAlign = TextAlign.End)
        }
        SettingRow("Khung giờ được dùng", subtitle = "Thứ 7 – Chủ nhật", changed = changedWindows(WEEKEND), last = !perDay,
            onClick = { open(PolicyDialog.Windows(WEEKEND, "Khung giờ · Cuối tuần")) }) {
            Text(windowsText(WEEKEND, st.allowedWindows), style = MaterialTheme.typography.titleMedium.copy(fontFeatureSettings = "tnum"), maxLines = 2, overflow = TextOverflow.Ellipsis, textAlign = TextAlign.End)
        }
        if (perDay) Weekday.entries.forEachIndexed { i, d ->
            SettingRow("Khung giờ · ${d.label}", changed = changedWindows(listOf(d)), last = i == 6,
                onClick = { open(PolicyDialog.Windows(listOf(d), "Khung giờ · ${d.label}")) }) {
                Text(windowsText(listOf(d), st.allowedWindows), style = MaterialTheme.typography.bodySmall, maxLines = 2, overflow = TextOverflow.Ellipsis, textAlign = TextAlign.End)
            }
        }
    }

    val allowApps = up.effectiveAppMode == AppMode.ALLOWLIST
    SectionLabel("Ứng dụng", Modifier.padding(top = 8.dp))
    PolicyCard {
        ModeChoice(allowApps, orig != null && orig.effectiveAppMode != up.effectiveAppMode, BlockingV2.APP_BLOCKLIST_HELP, BlockingV2.APP_ALLOWLIST_HELP) { a ->
            edit { BlockingV2.setAppMode(it, if (a) AppMode.ALLOWLIST else AppMode.BLOCKLIST) }
        }
        if (!allowApps) Dropdown(
            "Ứng dụng lạ",
            subtitle = when (up.newExecutable) {
                NewExecutable.ASK -> "Chặn và hỏi anh trước"; NewExecutable.ALLOW -> "Cho chạy, chỉ ghi lại"; NewExecutable.BLOCK -> "Luôn chặn"
            },
            value = PolicyDiff.newExeLabel(up.newExecutable),
            options = NewExecutable.entries.map { PolicyDiff.newExeLabel(it) to it },
            changed = orig != null && orig.newExecutable != up.newExecutable, last = true,
        ) { v -> edit { it.copy(newExecutable = v) } }
    }

    val (allowedRules, blockedRules) = AppRules.sections(up.appRules)
    RuleSection("Ứng dụng được phép", if (allowApps) PolicyHelp.APPS_ALLOWED_HELP_ALLOWLIST else PolicyHelp.APPS_ALLOWED_HELP_BLOCKLIST,
        allowedRules, up.appRules.size, orig, RuleAction.ALLOW, "Thêm ứng dụng được phép", edit, open)
    RuleSection("Ứng dụng bị chặn", if (allowApps) PolicyHelp.APPS_BLOCKED_HELP_ALLOWLIST else PolicyHelp.APPS_BLOCKED_HELP_BLOCKLIST,
        blockedRules, up.appRules.size, orig, RuleAction.BLOCK, "Thêm ứng dụng bị chặn", edit, open)
    if (allowedRules.isNotEmpty() && blockedRules.isNotEmpty())
        Text(AppRules.ORDER_HELP, style = MaterialTheme.typography.bodySmall, color = TextSecondary, modifier = Modifier.padding(horizontal = 4.dp))

    SectionLabel("Nhóm ứng dụng & giới hạn giờ", Modifier.padding(top = 8.dp))
    PolicyCard {
        Text(PolicyHelp.GROUPS_HELP, style = MaterialTheme.typography.bodySmall, color = TextSecondary, modifier = Modifier.padding(top = 10.dp, bottom = 4.dp))
        up.appGroups.forEach { (id, g) ->
            val q = g.dailyQuotaMin
            val limitText = when {
                q == null -> "Không giới hạn"
                Weekday.entries.map { q.get(it) }.distinct().size == 1 -> "${formatMinutes(q.mon)} / ngày"
                else -> "${formatMinutes(q.mon)} ngày thường · ${formatMinutes(q.sat)} cuối tuần"
            }
            val desc = groupCatalog.byId(id)?.description?.takeIf { it.isNotBlank() } ?: "${g.match.size} mẫu ứng dụng"
            SettingRow(g.label, subtitle = "$limitText · $desc",
                changed = orig != null && orig.appGroups[id] != g, trailingMax = 64.dp,
                onClick = { open(PolicyDialog.Group(id)) }) {
                McSwitch(q != null) { on ->
                    edit { u ->
                        val cur = u.appGroups[id]
                        if (cur == null) u else u.copy(appGroups = u.appGroups + (id to cur.copy(dailyQuotaMin = if (on) WeekdayMinutes.of(60, 60) else null)))
                    }
                }
            }
        }
        SettingRow("Thêm nhóm ứng dụng", onClick = { open(PolicyDialog.Group(null)) }, last = true) {
            Text("+", style = MaterialTheme.typography.titleLarge, color = Primary)
        }
    }

    SectionLabel("Dịch vụ", Modifier.padding(top = 8.dp))
    PolicyCard {
        val svcChanged = orig != null && (orig.web.blockedServices.orEmpty().toSet() != up.web.blockedServices.orEmpty().toSet() ||
            orig.web.allowedServices.orEmpty().toSet() != up.web.allowedServices.orEmpty().toSet())
        SettingRow("Dịch vụ", subtitle = BlockingV2.servicesSummary(up.web) + " · ${catalog.services.size} dịch vụ (YouTube, TikTok, Roblox…)",
            changed = svcChanged, last = true, onClick = { open(PolicyDialog.Services) }) {
            Icon(Icons.Outlined.ChevronRight, contentDescription = "Mở danh sách dịch vụ", tint = TextSecondary)
        }
    }

    val w = up.web
    val ow = orig?.web
    SectionLabel("Web", Modifier.padding(top = 8.dp))
    PolicyCard {
        ModeChoice(w.mode == WebMode.ALLOWLIST, ow != null && ow.mode != w.mode, BlockingV2.WEB_BLOCKLIST_HELP, BlockingV2.WEB_ALLOWLIST_HELP) { a ->
            edit { BlockingV2.setWebMode(it, if (a) WebMode.ALLOWLIST else WebMode.BLOCKLIST) }
        }
        SettingRow("SafeSearch", subtitle = if (w.safeSearch) "Bật · chỉ cho phép Google và Bing" else "Tắt",
            changed = ow != null && ow.safeSearch != w.safeSearch, last = true) {
            McSwitch(w.safeSearch) { v -> edit { it.copy(web = it.web.copy(safeSearch = v)) } }
        }
        InfoNote(PolicyHelp.safeSearch(engines), Modifier.padding(bottom = 8.dp))
        Dropdown("YouTube · chế độ hạn chế", value = PolicyDiff.youtubeLabel(w.youtube), options = YouTubeMode.entries.map { PolicyDiff.youtubeLabel(it) to it },
            changed = ow != null && ow.youtube != w.youtube, last = true) { v -> edit { it.copy(web = it.web.copy(youtube = v)) } }
        InfoNote(PolicyHelp.YOUTUBE, Modifier.padding(bottom = 8.dp))
        val catText = (w.blockedCategories.map { it.label } + w.categorySchedules.orEmpty().keys.map { "${it.label} (giờ học)" })
            .joinToString(", ").ifEmpty { "Không chặn danh mục nào" }
        SettingRow("Danh mục chặn", subtitle = catText,
            changed = ow != null && (ow.blockedCategories.toSet() != w.blockedCategories.toSet() || ow.categorySchedules.orEmpty() != w.categorySchedules.orEmpty()),
            onClick = { open(PolicyDialog.Categories) }) { Icon(Icons.Outlined.ChevronRight, null, tint = TextSecondary) }
        SettingRow("Trang bị chặn", subtitle = "${w.blockDomains.size} tên miền", changed = ow != null && ow.blockDomains != w.blockDomains,
            onClick = { open(PolicyDialog.Domains(true)) }) { Icon(Icons.Outlined.ChevronRight, null, tint = TextSecondary) }
        SettingRow("Trang luôn cho phép", subtitle = "${w.allowDomains.size} tên miền", changed = ow != null && ow.allowDomains != w.allowDomains,
            onClick = { open(PolicyDialog.Domains(false)) }) { Icon(Icons.Outlined.ChevronRight, null, tint = TextSecondary) }
        SettingRow("Ứng dụng miễn lọc mạng", subtitle = "${w.netExemptApps.size} ứng dụng", changed = ow != null && ow.netExemptApps != w.netExemptApps, last = true,
            onClick = { open(PolicyDialog.NetExempt) }) { Icon(Icons.Outlined.ChevronRight, null, tint = TextSecondary) }
    }

    SectionLabel("Từ khóa bị cấm", Modifier.padding(top = 8.dp))
    PolicyCard { KeywordsEditor(up, orig, edit) }

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
            Text("$value ▾", style = MaterialTheme.typography.titleMedium, color = Primary, maxLines = 2, overflow = TextOverflow.Ellipsis, textAlign = TextAlign.End)
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
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(onClick = { rows.clear(); rows.add("00:00" to "24:00") }) { Text("Cả ngày") }
                    TextButton(onClick = { rows.clear() }) { Text("Không dùng") }
                }
                if (rows.isEmpty()) Text("Không dùng máy trong ngày này.", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
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
private fun GroupEditor(
    vm: PolicyViewModel, activity: androidx.fragment.app.FragmentActivity, id: String?, group: AppGroup?, existingIds: Set<String>,
    onDismiss: () -> Unit, onSave: (String, AppGroup?) -> Unit,
) {
    var label by remember { mutableStateOf(group?.label ?: "") }
    val matches = remember { mutableStateListOf<AppMatch>().apply { addAll(group?.match.orEmpty()) } }
    var limited by remember { mutableStateOf(group?.dailyQuotaMin != null) }
    var weekday by remember { mutableStateOf(group?.dailyQuotaMin?.mon ?: 60) }
    var weekend by remember { mutableStateOf(group?.dailyQuotaMin?.sat ?: 60) }
    val key = id ?: GroupKeys.slug(label, existingIds)
    val ok = label.isNotBlank() && matches.isNotEmpty()
    FullScreenEditor(
        title = if (group == null) "Nhóm ứng dụng mới" else "Nhóm ${group.label}",
        saveEnabled = ok, onDismiss = onDismiss,
        onSave = { onSave(key, AppGroup(label.trim(), matches.toList(), if (limited) WeekdayMinutes.of(weekday, weekend) else null)) },
        bottom = {
            // Pinned: always visible, never pushed off-screen by a long app list.
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Column(Modifier.weight(1f)) {
                    Text("Giới hạn thời gian", style = MaterialTheme.typography.bodyMedium, color = TextPrimary)
                    Text(if (limited) "Tổng thời gian mỗi ngày cho cả nhóm" else "Không giới hạn", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                }
                McSwitch(limited) { limited = it }
            }
            if (limited) {
                QuotaRow("Ngày thường", weekday, false, { weekday = it }, weekday)
                QuotaRow("Cuối tuần", weekend, false, { weekend = it }, weekend)
            }
        },
    ) { listHeight ->
        OutlinedTextField(label, { label = it.take(40) }, singleLine = true, label = { Text("Tên nhóm") }, modifier = Modifier.fillMaxWidth())
        AppMatchEditor(vm, activity, label, matches, listHeight = listHeight, startPicking = group == null)
        if (id != null) TextButton(onClick = { onSave(id, null) }) { Text("Xóa nhóm này", color = DangerText) }
    }
}

/** Group ids for new groups are derived from the name (the parent never types an id). */
internal object GroupKeys {
    private val ID = Regex("^[a-z][a-z0-9_-]{0,31}$")

    fun slug(label: String, existing: Set<String>): String {
        val ascii = java.text.Normalizer.normalize(label.lowercase().replace('đ', 'd'), java.text.Normalizer.Form.NFD)
            .replace(Regex("\\p{M}+"), "").replace(Regex("[^a-z0-9]+"), "-").trim('-')
        var base = (if (ascii.firstOrNull()?.isLetter() == true) ascii else "nhom-$ascii").trimEnd('-').take(28).trimEnd('-')
        if (!ID.matches(base)) base = "nhom"
        if (base !in existing) return base
        var n = 2
        while ("$base-$n" in existing) n++
        return "$base-$n"
    }
}

/**
 * Full-screen editor: top bar (Hủy · title · Lưu), a scrolling middle and an optional pinned [bottom] area.
 * The middle gets a fixed-height app list ([content] receives its height: ~40 % of the screen, 160–360 dp).
 */
@Composable
private fun FullScreenEditor(
    title: String, saveEnabled: Boolean, onDismiss: () -> Unit, onSave: () -> Unit, saveLabel: String = "Lưu",
    bottom: (@Composable androidx.compose.foundation.layout.ColumnScope.() -> Unit)? = null,
    content: @Composable androidx.compose.foundation.layout.ColumnScope.(androidx.compose.ui.unit.Dp) -> Unit,
) {
    androidx.compose.ui.window.Dialog(
        onDismissRequest = onDismiss,
        properties = androidx.compose.ui.window.DialogProperties(usePlatformDefaultWidth = false, decorFitsSystemWindows = false),
    ) {
        androidx.compose.foundation.layout.BoxWithConstraints(Modifier.fillMaxSize().background(Background)) {
            val listHeight = (maxHeight * 0.4f).coerceIn(160.dp, 360.dp)
            Column(Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding().imePadding()) {
                Row(Modifier.fillMaxWidth().background(Surface).padding(horizontal = 4.dp, vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                    TextButton(onClick = onDismiss) { Text("Hủy", color = TextBody, style = MaterialTheme.typography.labelLarge) }
                    Text(title, style = MaterialTheme.typography.titleMedium, color = TextPrimary, maxLines = 1,
                        overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f), textAlign = TextAlign.Center)
                    TextButton(onClick = onSave, enabled = saveEnabled) { Text(saveLabel, style = MaterialTheme.typography.labelLarge) }
                }
                HorizontalDivider(color = Outline)
                Column(
                    Modifier.weight(1f).fillMaxWidth().verticalScroll(rememberScrollState()).padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) { content(listHeight) }
                if (bottom != null) {
                    HorizontalDivider(color = Outline)
                    Column(Modifier.fillMaxWidth().background(Surface).padding(horizontal = 16.dp, vertical = 8.dp), content = bottom)
                }
            }
        }
    }
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
                InfoNote(PolicyHelp.CATEGORY_SOURCE, Modifier.padding(bottom = 4.dp))
                WebCategory.entries.forEach { c ->
                    val s = state[c] ?: CatState.OFF
                    var open by remember { mutableStateOf(false) }
                    Row(Modifier.fillMaxWidth().clickable { open = true }.padding(vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f).padding(end = 8.dp)) {
                            Text(c.label)
                            Text(WebLabels.categoryDescription(c), style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                        }
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
                Text("Mỗi dòng một tên miền. poki.com chỉ khớp đúng tên này; *.poki.com khớp poki.com và mọi tên miền con", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                OutlinedTextField(text, { text = it }, minLines = 5, isError = err != null, modifier = Modifier.fillMaxWidth())
                err?.let { Text(it, color = DangerText, style = MaterialTheme.typography.bodySmall) }
            }
        },
        confirmButton = { TextButton(enabled = err == null, onClick = { onSave(list) }) { Text("Lưu") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Hủy") } },
        containerColor = Surface,
    )
}

@Composable
private fun NetExemptDialog(initial: List<AppMatch>, onDismiss: () -> Unit, onSave: (List<AppMatch>) -> Unit) {
    var text by remember { mutableStateOf(initial.mapNotNull { it.path }.joinToString("\n")) }
    val list = text.lines().map { it.trim() }.filter { it.isNotEmpty() }.distinct()
    val err = list.firstNotNullOfOrNull { PolicyValidation.pathError(it) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Ứng dụng miễn lọc mạng") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Mỗi dòng một đường dẫn đầy đủ, vd: C:\\Program Files\\App\\app.exe", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                OutlinedTextField(text, { text = it }, minLines = 4, isError = err != null, modifier = Modifier.fillMaxWidth())
                err?.let { Text(it, color = DangerText, style = MaterialTheme.typography.bodySmall) }
            }
        },
        confirmButton = { TextButton(enabled = err == null, onClick = { onSave(list.map { AppMatch(path = it) }) }) { Text("Lưu") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Hủy") } },
        containerColor = Surface,
    )
}

@Composable
private fun RuleBtn(text: String, desc: String, enabled: Boolean, onClick: () -> Unit) {
    Text(
        text, color = if (enabled) TextBody else io.github.nevminhnh.mincontrol.master.ui.theme.DisabledFg,
        modifier = Modifier.clip(CircleShape).then(if (enabled) Modifier.clickable(onClick = onClick) else Modifier)
            .semantics { contentDescription = desc }.padding(horizontal = 10.dp, vertical = 8.dp),
    )
}

/** Adds app rules to "Ứng dụng được phép" / "Ứng dụng bị chặn": pick apps from the PC or type patterns. One rule per pattern. */
@Composable
private fun AppRuleDialog(
    vm: PolicyViewModel, activity: androidx.fragment.app.FragmentActivity, up: UserPolicy, action: RuleAction, onDismiss: () -> Unit,
    onSave: (RuleAction, List<AppMatch>) -> Unit,
) {
    val matches = remember { mutableStateListOf<AppMatch>() }
    val err = matches.firstNotNullOfOrNull { AppRules.matchError(AppRules.clean(it)) }
    FullScreenEditor(
        title = if (action == RuleAction.ALLOW) "Thêm ứng dụng được phép" else "Thêm ứng dụng bị chặn",
        saveEnabled = matches.isNotEmpty() && err == null, saveLabel = "Thêm", onDismiss = onDismiss,
        onSave = { onSave(action, matches.toList()) },
    ) { listHeight ->
        Text(
            if (action == RuleAction.BLOCK) "Các ứng dụng này sẽ không chạy được trên máy của con."
            else "Các ứng dụng này luôn được phép chạy.",
            style = MaterialTheme.typography.bodySmall, color = TextSecondary,
        )
        AppMatchEditor(vm, activity, "", matches, action = action, rules = up.appRules, listHeight = listHeight, startPicking = true)
        if (err != null) Text(err, style = MaterialTheme.typography.bodySmall, color = DangerText)
    }
}

/** One of the two rule lists. Indexes are positions in `appRules` (= evaluation order). */
@Composable
private fun RuleSection(
    title: String, help: String, list: List<IndexedValue<AppRule>>, total: Int, orig: UserPolicy?, action: RuleAction, addLabel: String,
    edit: ((UserPolicy) -> UserPolicy) -> Unit, open: (PolicyDialog) -> Unit,
) {
    SectionLabel(title, Modifier.padding(top = 8.dp))
    PolicyCard {
        Text(help, style = MaterialTheme.typography.bodySmall, color = TextSecondary, modifier = Modifier.padding(top = 10.dp, bottom = 4.dp))
        if (list.isEmpty()) Text("Chưa có ứng dụng nào.", style = MaterialTheme.typography.bodySmall, color = TextSecondary, modifier = Modifier.padding(vertical = 8.dp))
        list.forEach { (i, r) ->
            SettingRow(
                AppRules.describe(r), trailingMax = 132.dp,
                subtitle = "Thứ tự xét ${i + 1}/$total",
                changed = orig != null && orig.appRules.getOrNull(i) != r,
            ) {
                RuleBtn("▲", "Xét sớm hơn", i > 0) { edit { u -> u.copy(appRules = AppRules.move(u.appRules, i, -1)) } }
                RuleBtn("▼", "Xét muộn hơn", i < total - 1) { edit { u -> u.copy(appRules = AppRules.move(u.appRules, i, 1)) } }
                RuleBtn("✕", "Xóa ${AppRules.describe(r)}", true) { edit { u -> u.copy(appRules = AppRules.remove(u.appRules, i)) } }
            }
        }
        SettingRow(addLabel, last = true, onClick = { open(PolicyDialog.AppRuleAdd(action)) }) {
            Text("+", style = MaterialTheme.typography.titleLarge, color = Primary)
        }
    }
}

@Composable
private fun PolicyHeader(children: List<Child>, selected: Child?, onSelect: (Child) -> Unit, onSettings: (() -> Unit)?) {
    Column(Modifier.fillMaxWidth().padding(bottom = 12.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        TabHeader("Quy tắc", onSettings)
        ChildSwitcher(children, selected, onSelect)
    }
}

private val previewChildren = listOf(
    Child("d1", "PC-PHONG-KHACH", "S-1", "Minh Anh", true, null, null),
    Child("d2", "LAPTOP-HOC-TAP-CUA-CON", "S-2", "Bảo Ngọc Nguyễn Hoàng", false, null, null),
    Child("d3", "PC-GAMING", "S-3", "Minh Anh", true, null, null),
)

@androidx.compose.ui.tooling.preview.Preview(name = "Quy tắc · 3 máy · 1.3x", widthDp = 360, heightDp = 900, fontScale = 1.3f, showBackground = true, backgroundColor = 0xFFF4F6FA)
@Composable
private fun PolicyHeaderPreview() {
    io.github.nevminhnh.mincontrol.master.ui.theme.MinControlTheme {
        val up = io.github.nevminhnh.mincontrol.master.policy.PolicyDefaults.user("Minh Anh").copy(
            keywords = io.github.nevminhnh.mincontrol.master.data.protocol.Keywords(listOf("đánh bài", "cá độ", "phim người lớn")),
            web = io.github.nevminhnh.mincontrol.master.policy.PolicyDefaults.user("x").web.copy(blockedServices = listOf("tiktok")),
        )
        val catalog = ServiceCatalog(listOf(
            io.github.nevminhnh.mincontrol.master.policy.Service("youtube", "YouTube", "video"),
            io.github.nevminhnh.mincontrol.master.policy.Service("tiktok", "TikTok", "social"),
            io.github.nevminhnh.mincontrol.master.policy.Service("roblox", "Roblox", "games"),
            io.github.nevminhnh.mincontrol.master.policy.Service("epicgames", "Epic Games Store", "games"),
        ))
        Column(Modifier.background(Background).verticalScroll(rememberScrollState())) {
            PolicyHeader(previewChildren, previewChildren[1], {}, {})
            Column(Modifier.padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Editor(up, up, false, {}, {}, catalog, io.github.nevminhnh.mincontrol.master.policy.SearchEngines.FALLBACK,
                    io.github.nevminhnh.mincontrol.master.policy.AppGroupCatalog.BUILTIN) {}
            }
        }
    }
}
