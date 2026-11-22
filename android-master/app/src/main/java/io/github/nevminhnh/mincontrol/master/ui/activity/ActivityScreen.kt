package io.github.nevminhnh.mincontrol.master.ui.activity

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.GridItemSpan
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Download
import androidx.compose.material.icons.outlined.ExpandMore
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.PhotoCamera
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DatePicker
import androidx.compose.material3.DatePickerDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberDatePickerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.lifecycle.viewmodel.compose.viewModel
import io.github.nevminhnh.mincontrol.master.data.Child
import io.github.nevminhnh.mincontrol.master.data.protocol.ScreenshotItem
import io.github.nevminhnh.mincontrol.master.data.protocol.Weekday
import io.github.nevminhnh.mincontrol.master.data.protocol.WebItem
import io.github.nevminhnh.mincontrol.master.ui.ActivityTabRequest
import io.github.nevminhnh.mincontrol.master.ui.ChildSwitcher
import io.github.nevminhnh.mincontrol.master.ui.Fmt
import io.github.nevminhnh.mincontrol.master.ui.components.ChipRow
import io.github.nevminhnh.mincontrol.master.ui.components.EmptyState
import io.github.nevminhnh.mincontrol.master.ui.components.FilterChip
import io.github.nevminhnh.mincontrol.master.ui.components.IconCircle
import io.github.nevminhnh.mincontrol.master.ui.components.McCard
import io.github.nevminhnh.mincontrol.master.ui.components.PrimaryButton
import io.github.nevminhnh.mincontrol.master.ui.components.ProgressTrack
import io.github.nevminhnh.mincontrol.master.ui.components.SecondaryButton
import io.github.nevminhnh.mincontrol.master.ui.components.SegmentedTabs
import io.github.nevminhnh.mincontrol.master.ui.rememberActivity
import io.github.nevminhnh.mincontrol.master.ui.theme.Background
import io.github.nevminhnh.mincontrol.master.ui.theme.BeVietnamPro
import io.github.nevminhnh.mincontrol.master.ui.theme.ChipBorder
import io.github.nevminhnh.mincontrol.master.ui.theme.Danger
import io.github.nevminhnh.mincontrol.master.ui.theme.DangerContainer
import io.github.nevminhnh.mincontrol.master.ui.theme.DangerText
import io.github.nevminhnh.mincontrol.master.ui.theme.Divider
import io.github.nevminhnh.mincontrol.master.ui.theme.OfflineDot
import io.github.nevminhnh.mincontrol.master.ui.theme.Primary
import io.github.nevminhnh.mincontrol.master.ui.theme.PrimaryContainer
import io.github.nevminhnh.mincontrol.master.ui.theme.Purple
import io.github.nevminhnh.mincontrol.master.ui.theme.QuickActionBorder
import io.github.nevminhnh.mincontrol.master.ui.theme.Rail
import io.github.nevminhnh.mincontrol.master.ui.theme.SearchBg
import io.github.nevminhnh.mincontrol.master.ui.theme.SearchFg
import io.github.nevminhnh.mincontrol.master.ui.theme.ShotChat
import io.github.nevminhnh.mincontrol.master.ui.theme.ShotGame
import io.github.nevminhnh.mincontrol.master.ui.theme.ShotWeb
import io.github.nevminhnh.mincontrol.master.ui.theme.Success
import io.github.nevminhnh.mincontrol.master.ui.theme.SuccessDot
import io.github.nevminhnh.mincontrol.master.ui.theme.Surface
import io.github.nevminhnh.mincontrol.master.ui.theme.TextBody
import io.github.nevminhnh.mincontrol.master.ui.theme.TextPrimary
import io.github.nevminhnh.mincontrol.master.ui.theme.TextSecondary
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ActivityScreen(vm: ActivityViewModel = viewModel()) {
    val child by vm.child.collectAsState()
    val children by vm.children.collectAsState()
    val tab by vm.tab.collectAsState()
    val date by vm.date.collectAsState()
    val message by vm.message.collectAsState()
    val request by ActivityTabRequest.collectAsState()
    val snackbar = remember { SnackbarHostState() }
    var pickDate by remember { mutableStateOf(false) }

    LaunchedEffect(request) { request?.let { vm.tab.value = it; ActivityTabRequest.value = null } }
    LaunchedEffect(message) { message?.let { snackbar.showSnackbar(it); vm.message.value = null } }

    Box(Modifier.fillMaxSize().background(Background)) {
        Column(Modifier.fillMaxSize().statusBarsPadding()) {
            Column(Modifier.padding(start = 16.dp, end = 16.dp, top = 16.dp, bottom = 12.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.height(44.dp)) {
                    val dayText = if (date == LocalDate.now()) "Hôm nay" else Fmt.dayMonth(date)
                    Text("${child?.label ?: "Hoạt động"} · $dayText", style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f),
                        maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Row(
                        Modifier.height(36.dp).clip(RoundedCornerShape(18.dp)).background(Surface)
                            .border(1.dp, ChipBorder, RoundedCornerShape(18.dp)).clickable { pickDate = true }.padding(horizontal = 12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(Fmt.dayMonth(date), style = MaterialTheme.typography.labelMedium)
                        Icon(Icons.Outlined.ExpandMore, null, modifier = Modifier.size(16.dp))
                    }
                }
                ChildSwitcher(children, child, { vm.select(it) })
                SegmentedTabs(ActivityTab.entries.map { it.label }, tab.ordinal, { vm.tab.value = ActivityTab.entries[it] })
                if (tab == ActivityTab.Web) WebSearchHeader(vm)
            }
            val c = child
            if (c == null) {
                EmptyState("Chưa có máy tính nào được quản lý")
            } else when (tab) {
                ActivityTab.Timeline -> TimelineTab(vm, c)
                ActivityTab.Web -> WebTab(vm)
                ActivityTab.Apps -> AppsTab(vm, c)
                ActivityTab.Shots -> ShotsTab(vm)
            }
        }
        SnackbarHost(snackbar, Modifier.align(Alignment.BottomCenter).padding(16.dp))
    }

    if (pickDate) {
        val state = rememberDatePickerState(
            initialSelectedDateMillis = date.atStartOfDay(ZoneOffset.UTC).toInstant().toEpochMilli(),
            selectableDates = object : androidx.compose.material3.SelectableDates {
                override fun isSelectableDate(utcTimeMillis: Long) = utcTimeMillis <= System.currentTimeMillis()
            },
        )
        DatePickerDialog(
            onDismissRequest = { pickDate = false },
            confirmButton = {
                TextButton(onClick = {
                    state.selectedDateMillis?.let { vm.date.value = Instant.ofEpochMilli(it).atZone(ZoneOffset.UTC).toLocalDate() }
                    pickDate = false
                }) { Text("Chọn") }
            },
            dismissButton = { TextButton(onClick = { pickDate = false }) { Text("Hủy") } },
        ) { DatePicker(state) }
    }
}

// ---------------- Timeline ----------------

@Composable
private fun TimelineTab(vm: ActivityViewModel, child: Child) {
    val events by vm.events.collectAsState()
    val usage by vm.usage.collectAsState()
    val policy by vm.policy.collectAsState()
    val loading by vm.loading.collectAsState()
    val date by vm.date.collectAsState()
    val groupLabels = policy?.users?.get(child.sid)?.appGroups?.mapValues { it.value.label }.orEmpty()
    val decided by vm.decided.collectAsState()
    val rows = remember(events, groupLabels, decided) { TimelineBuilder.build(events, child.hostname, groupLabels, decided) }
    val st = child.state
    val isToday = date == LocalDate.now()
    val usedMin = if (isToday && st != null) st.usedMin else (usage?.totalSec ?: 0) / 60
    val gameMin = if (isToday && st?.groups?.get("games") != null) st.groups["games"]!!.usedMin
        else (usage?.apps?.filter { it.group == "games" }?.sumOf { it.activeSec } ?: 0) / 60
    val webCount = events.count { it.type == "web.visit" }

    LazyColumn(contentPadding = PaddingValues(start = 16.dp, end = 16.dp, bottom = 24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                StatTile("${usedMin}p", "sử dụng", Modifier.weight(1f))
                StatTile("${gameMin}p", "chơi game", Modifier.weight(1f))
                StatTile("$webCount", "trang web", Modifier.weight(1f))
            }
        }
        item {
            McCard(padding = PaddingValues(start = 16.dp, end = 16.dp, top = 20.dp, bottom = 4.dp)) {
                val live = if (isToday && child.online && st?.active == true && st.foregroundExe != null) {
                    val remaining = st.groups["games"]?.remainingMin
                    TimelineRow(Instant.now().toString(), DotKind.LIVE, "Đang dùng ${Fmt.appName(st.foregroundExe)}",
                        remaining?.let { "còn $it phút trong hạn mức game" } ?: "còn ${st.remainingMin ?: 0} phút hôm nay")
                } else null
                val all = listOfNotNull(live) + rows
                if (all.isEmpty()) {
                    if (loading) CircularProgressIndicator(Modifier.align(Alignment.CenterHorizontally).padding(16.dp), color = Primary)
                    else EmptyState("Chưa có hoạt động")
                }
                all.forEachIndexed { i, r ->
                    TimelineRowView(r, last = i == all.lastIndex, onApprove = { vm.tab.value = ActivityTab.Apps })
                }
            }
        }
    }
}

@Composable
private fun StatTile(value: String, label: String, modifier: Modifier) {
    Column(modifier.clip(RoundedCornerShape(16.dp)).background(Surface).padding(12.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(value, style = MaterialTheme.typography.titleLarge.copy(fontFeatureSettings = "tnum"))
        Text(label, style = MaterialTheme.typography.bodySmall, color = TextSecondary)
    }
}

@Composable
private fun TimelineRowView(r: TimelineRow, last: Boolean, onApprove: () -> Unit) {
    Row(Modifier.fillMaxWidth().height(androidx.compose.foundation.layout.IntrinsicSize.Min)) {
        Text(Fmt.time(r.ts), style = MaterialTheme.typography.bodySmall.copy(fontFeatureSettings = "tnum"), color = TextSecondary,
            modifier = Modifier.width(48.dp).padding(top = 2.dp))
        Spacer(Modifier.width(8.dp))
        Column(Modifier.width(20.dp).fillMaxHeight(), horizontalAlignment = Alignment.CenterHorizontally) {
            val color = when (r.dot) {
                DotKind.LIVE -> SuccessDot; DotKind.INFO -> Primary; DotKind.BLOCK -> Danger; DotKind.APP -> Purple; DotKind.NEUTRAL -> OfflineDot
            }
            Spacer(Modifier.height(6.dp))
            Box(
                Modifier.size(if (r.dot == DotKind.LIVE) 18.dp else 10.dp)
                    .then(if (r.dot == DotKind.LIVE) Modifier.clip(CircleShape).background(SuccessDot.copy(alpha = 0.18f)) else Modifier),
                contentAlignment = Alignment.Center,
            ) { Box(Modifier.size(10.dp).clip(CircleShape).background(color)) }
            if (!last) Box(Modifier.padding(top = 4.dp).width(2.dp).weight(1f).background(Rail))
        }
        Spacer(Modifier.width(8.dp))
        Column(Modifier.weight(1f).padding(bottom = 16.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(r.title, style = MaterialTheme.typography.titleMedium, color = if (r.red) DangerText else TextPrimary, modifier = Modifier.weight(1f, fill = false))
                if (r.device) Text("Máy", style = MaterialTheme.typography.labelSmall, color = TextSecondary,
                    modifier = Modifier.clip(RoundedCornerShape(6.dp)).background(Background).padding(horizontal = 6.dp, vertical = 2.dp))
            }
            if (r.sub.isNotBlank()) Text(r.sub, style = MaterialTheme.typography.bodySmall, color = TextBody)
            if (r.approve) {
                Text("Duyệt ngay", style = MaterialTheme.typography.labelLarge, color = Primary,
                    modifier = Modifier.clip(RoundedCornerShape(8.dp)).clickable(onClick = onApprove).padding(top = 4.dp, bottom = 4.dp, end = 8.dp))
            }
        }
    }
}

// ---------------- Web ----------------

@Composable
private fun WebSearchHeader(vm: ActivityViewModel) {
    val q by vm.webQuery.collectAsState()
    val filter by vm.webFilter.collectAsState()
    val items by vm.webItems.collectAsState()
    Row(
        Modifier.fillMaxWidth().height(48.dp).clip(RoundedCornerShape(14.dp)).background(Surface)
            .border(1.dp, ChipBorder, RoundedCornerShape(14.dp)).padding(horizontal = 14.dp),
        verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Icon(Icons.Outlined.Search, null, tint = TextSecondary, modifier = Modifier.size(20.dp))
        Box(Modifier.weight(1f)) {
            if (q.isEmpty()) Text("Tìm trong lịch sử web", style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
            BasicTextField(
                value = q, onValueChange = vm::setWebQuery, singleLine = true,
                textStyle = TextStyle(fontFamily = BeVietnamPro, fontSize = MaterialTheme.typography.bodyMedium.fontSize, color = TextPrimary),
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
    ChipRow {
        WebFilter.entries.forEach { f ->
            val n = when (f) {
                WebFilter.ALL -> items.size
                WebFilter.BLOCKED -> items.count { it.kind == "blocked" }
                WebFilter.SEARCH -> items.count { it.kind == "search" }
            }
            FilterChip(if (filter == f || f == WebFilter.ALL || filter == WebFilter.ALL) "${f.label} · $n" else f.label, filter == f, { vm.setWebFilter(f) })
        }
    }
}

@Composable
private fun WebTab(vm: ActivityViewModel) {
    val items by vm.webItems.collectAsState()
    val hasMore by vm.webHasMore.collectAsState()
    LazyColumn(contentPadding = PaddingValues(start = 16.dp, end = 16.dp, bottom = 24.dp)) {
        if (items.isEmpty()) item { McCard { EmptyState("Không có lịch sử web") } }
        items(items.size) { i ->
            val it = items[i]
            val shape = when {
                items.size == 1 -> RoundedCornerShape(24.dp)
                i == 0 -> RoundedCornerShape(topStart = 24.dp, topEnd = 24.dp)
                i == items.lastIndex -> RoundedCornerShape(bottomStart = 24.dp, bottomEnd = 24.dp)
                else -> RoundedCornerShape(0.dp)
            }
            Box(Modifier.fillMaxWidth().clip(shape).background(Surface).padding(horizontal = 16.dp, vertical = if (i == 0 || i == items.lastIndex) 4.dp else 0.dp)) {
                WebRow(it, divider = i != items.lastIndex)
            }
            if (i == items.lastIndex && hasMore) LaunchedEffect(items.size) { vm.loadWeb() }
        }
    }
}

@Composable
private fun WebRow(it: WebItem, divider: Boolean) {
    val host = it.host ?: it.url?.substringAfter("://")?.substringBefore('/') ?: ""
    val (bg, fg, badge) = when (it.kind) {
        "blocked" -> Triple(DangerContainer, DangerText, "⦸")
        "search" -> Triple(SearchBg, SearchFg, "G")
        else -> Triple(PrimaryContainer, Primary, host.removePrefix("www.").take(1).uppercase())
    }
    val title = when (it.kind) {
        "blocked" -> "Đã chặn: $host"
        "search" -> it.query?.ifBlank { null } ?: it.title?.ifBlank { null } ?: host
        else -> it.title?.ifBlank { null } ?: host
    }
    val sub = when (it.kind) {
        "blocked" -> it.category?.let { "Danh mục $it" } ?: "Bị chặn"
        "search" -> ("Tìm kiếm " + Fmt.engineLabel(it.engine, host)).trim()
        else -> host + (it.durationSec?.takeIf { s -> s >= 60 }?.let { s -> " · ${s / 60} phút" } ?: "")
    }
    Row(
        Modifier.fillMaxWidth().then(if (divider) Modifier.drawDivider() else Modifier).padding(vertical = 12.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(Modifier.size(36.dp).clip(RoundedCornerShape(10.dp)).background(bg), contentAlignment = Alignment.Center) {
            Text(badge, style = MaterialTheme.typography.titleSmall, color = fg)
        }
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium, color = if (it.kind == "blocked") DangerText else TextPrimary,
                maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(sub, style = MaterialTheme.typography.bodySmall, color = TextSecondary, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        Text(Fmt.time(it.ts), style = MaterialTheme.typography.bodySmall.copy(fontFeatureSettings = "tnum"), color = TextSecondary)
    }
}

private fun Modifier.drawDivider() = drawBehind {
    drawLine(Divider, Offset(0f, size.height), Offset(size.width, size.height), 1.dp.toPx())
}

// ---------------- Apps ----------------

@Composable
private fun AppsTab(vm: ActivityViewModel, child: Child) {
    val activity = rememberActivity()
    val usage by vm.usage.collectAsState()
    val policy by vm.policy.collectAsState()
    val pending by vm.pendingApprovals.collectAsState()
    val busy by vm.busy.collectAsState()
    val date by vm.date.collectAsState()
    val up = policy?.users?.get(child.sid)
    val day = Weekday.of(date.dayOfWeek)

    LazyColumn(contentPadding = PaddingValues(start = 16.dp, end = 16.dp, bottom = 24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        items(pending, key = { it.view.item.id }) { card ->
            McCard(spacing = 12.dp, border = QuickActionBorder, elevated = true) {
                Text("CHỜ ANH DUYỆT", style = MaterialTheme.typography.titleSmall, color = Primary)
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.CenterVertically) {
                    IconCircle(Icons.Outlined.Download, PrimaryContainer, Primary, size = 44.dp, square = true)
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(card.body.substringBefore(" · ").ifBlank { "Ứng dụng mới" }, style = MaterialTheme.typography.titleMedium)
                        Text(card.body.substringAfter(" · ", ""), style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                    }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    SecondaryButton("Chặn", { vm.decide(activity, card, false) }, Modifier.weight(1f), height = 44.dp, radius = 12.dp, enabled = card.view.item.id !in busy)
                    PrimaryButton("Cho phép", { vm.decide(activity, card, true) }, Modifier.weight(1f), height = 44.dp, radius = 12.dp, enabled = card.view.item.id !in busy)
                }
            }
        }
        val groups = up?.appGroups.orEmpty().filter { it.value.dailyQuotaMin != null }
        if (groups.isNotEmpty()) item {
            McCard(spacing = 8.dp) {
                groups.entries.forEachIndexed { i, (id, g) ->
                    val quota = g.dailyQuotaMin!!.get(day)
                    val used = if (date == LocalDate.now()) child.state?.groups?.get(id)?.usedMin
                        ?: ((usage?.apps?.filter { it.group == id }?.sumOf { it.activeSec } ?: 0) / 60)
                        else (usage?.apps?.filter { it.group == id }?.sumOf { it.activeSec } ?: 0) / 60
                    if (i > 0) Spacer(Modifier.height(8.dp))
                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.Bottom) {
                        Text("Nhóm ${g.label}", style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                        Text("$used / $quota phút", style = MaterialTheme.typography.bodySmall.copy(fontFeatureSettings = "tnum"), color = TextSecondary)
                    }
                    ProgressTrack(if (quota > 0) used.toFloat() / quota else 1f, if (id == "games") Purple else Primary)
                }
            }
        }
        item {
            McCard(spacing = 16.dp) {
                Text("Thời gian theo ứng dụng", style = MaterialTheme.typography.titleMedium)
                val apps = usage?.apps.orEmpty().sortedByDescending { it.activeSec }
                if (apps.isEmpty()) EmptyState("Chưa có dữ liệu sử dụng")
                val max = apps.maxOfOrNull { it.activeSec }?.coerceAtLeast(1) ?: 1
                apps.forEach { a ->
                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Row(Modifier.fillMaxWidth()) {
                            Text(Fmt.appName(a.exe), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text("${a.activeSec / 60} phút", style = MaterialTheme.typography.bodyMedium.copy(fontFeatureSettings = "tnum"), color = TextBody)
                        }
                        val color = when {
                            a.group == "games" -> Purple
                            a.exe.equals("explorer.exe", true) -> OfflineDot
                            else -> Primary
                        }
                        ProgressTrack(a.activeSec.toFloat() / max, color)
                        val groupLabel = a.group?.let { up?.appGroups?.get(it)?.label ?: it } ?: "Không thuộc nhóm"
                        Text(groupLabel, style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                    }
                }
            }
        }
    }
}

// ---------------- Screenshots ----------------

@Composable
private fun ShotsTab(vm: ActivityViewModel) {
    val activity = rememberActivity()
    val shots by vm.shots.collectAsState()
    val hasMore by vm.shotsHasMore.collectAsState()
    val decrypted by vm.decrypted.collectAsState()
    val decrypting by vm.decrypting.collectAsState()
    var open by remember { mutableStateOf<ScreenshotItem?>(null) }
    val auto by vm.autoOpen.collectAsState()
    val child by vm.child.collectAsState()
    LaunchedEffect(auto) { auto?.let { open = it; vm.clearAutoOpen() } }

    LazyVerticalGrid(
        columns = GridCells.Fixed(2),
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, bottom = 24.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item(span = { GridItemSpan(2) }) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.padding(bottom = 4.dp)) {
                Row(Modifier.weight(1f), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Icon(Icons.Outlined.Lock, null, tint = Success, modifier = Modifier.size(16.dp).padding(top = 2.dp))
                    Text("Mã hóa đầu cuối · chỉ điện thoại này giải mã được", style = MaterialTheme.typography.bodySmall, color = TextBody)
                }
                PrimaryButton("Chụp ngay", { vm.captureNow(activity) }, height = 44.dp, icon = Icons.Outlined.PhotoCamera)
            }
        }
        if (child?.online == false) item(span = { GridItemSpan(2) }) {
            Text("Máy đang tắt — chỉ xem được thông tin ảnh, mở ảnh khi máy online", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
        }
        if (decrypting.isNotEmpty()) item(span = { GridItemSpan(2) }) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                Text(io.github.nevminhnh.mincontrol.master.data.api.BLOB_PROGRESS_TEXT, style = MaterialTheme.typography.bodySmall, color = TextBody)
            }
        }
        if (shots.isEmpty()) item(span = { GridItemSpan(2) }) { EmptyState("Chưa có ảnh màn hình") }
        items(shots, key = { it.eventId }) { s ->
            val bmp = decrypted[s.eventId]
            Column(
                Modifier.clip(RoundedCornerShape(16.dp)).background(Surface)
                    .clickable { if (bmp != null) open = s else vm.decrypt(s, openWhenDone = true) },
            ) {
                Box(Modifier.fillMaxWidth().height(96.dp).background(shotTint(s.foregroundExe)), contentAlignment = Alignment.Center) {
                    if (bmp != null) {
                        Image(bmp.asImageBitmap(), contentDescription = "Ảnh ${Fmt.time(s.ts)}", contentScale = ContentScale.Crop, modifier = Modifier.fillMaxSize())
                    } else {
                        Column(Modifier.fillMaxSize().padding(8.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            listOf(0.6f, 0.85f, 0.4f).forEach { w ->
                                Box(Modifier.fillMaxWidth(w).height(6.dp).clip(RoundedCornerShape(3.dp)).background(Color.White.copy(alpha = 0.55f)))
                            }
                        }
                        if (s.eventId in decrypting) CircularProgressIndicator(color = Color.White, modifier = Modifier.size(24.dp))
                        else Icon(Icons.Outlined.Lock, "Chạm để giải mã", tint = Color.White, modifier = Modifier.size(20.dp))
                    }
                }
                Column(Modifier.padding(start = 12.dp, end = 12.dp, top = 8.dp, bottom = 12.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(Fmt.appName(s.foregroundExe), style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(Fmt.time(s.ts), style = MaterialTheme.typography.bodySmall.copy(fontFeatureSettings = "tnum"), color = TextSecondary)
                }
            }
            if (s == shots.last() && hasMore) LaunchedEffect(shots.size) { vm.loadShots() }
        }
    }

    open?.let { s ->
        val bmp = decrypted[s.eventId]
        if (bmp != null) {
            Dialog(onDismissRequest = { open = null }, properties = DialogProperties(usePlatformDefaultWidth = false)) {
                Column(
                    Modifier.fillMaxWidth().padding(16.dp).clip(RoundedCornerShape(16.dp)).background(Surface).clickable { open = null },
                ) {
                    Image(bmp.asImageBitmap(), contentDescription = null, contentScale = ContentScale.Fit,
                        modifier = Modifier.fillMaxWidth().aspectRatio(bmp.width.toFloat() / bmp.height.coerceAtLeast(1)))
                    Text("${Fmt.appName(s.foregroundExe)} · ${Fmt.time(s.ts)}", style = MaterialTheme.typography.titleSmall,
                        modifier = Modifier.padding(12.dp))
                }
            }
        }
    }
}

private fun shotTint(exe: String?): Color {
    val e = exe?.lowercase() ?: return ShotWeb
    return when {
        e.contains("minecraft") || e.contains("roblox") || e.contains("javaw") || e.contains("steam") -> ShotGame
        e.contains("zalo") || e.contains("discord") || e.contains("messenger") || e.contains("teams") -> ShotChat
        else -> ShotWeb
    }
}
