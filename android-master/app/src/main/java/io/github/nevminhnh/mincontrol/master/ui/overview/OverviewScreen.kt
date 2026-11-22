package io.github.nevminhnh.mincontrol.master.ui.overview

import androidx.compose.foundation.BorderStroke
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
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowForwardIos
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.ChevronRight
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.LockOpen
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.WarningAmber
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import io.github.nevminhnh.mincontrol.master.data.Child
import io.github.nevminhnh.mincontrol.master.ui.Fmt
import io.github.nevminhnh.mincontrol.master.ui.components.Avatar
import io.github.nevminhnh.mincontrol.master.ui.components.Dot
import io.github.nevminhnh.mincontrol.master.ui.components.McCard
import io.github.nevminhnh.mincontrol.master.ui.components.PrimaryButton
import io.github.nevminhnh.mincontrol.master.ui.components.ProgressTrack
import io.github.nevminhnh.mincontrol.master.ui.confirm.LockConfirmSheet
import io.github.nevminhnh.mincontrol.master.ui.rememberActivity
import io.github.nevminhnh.mincontrol.master.ui.theme.AvatarColors
import io.github.nevminhnh.mincontrol.master.ui.theme.Background
import io.github.nevminhnh.mincontrol.master.ui.theme.DangerBorder
import io.github.nevminhnh.mincontrol.master.ui.theme.DangerContainer
import io.github.nevminhnh.mincontrol.master.ui.theme.DangerText
import io.github.nevminhnh.mincontrol.master.ui.theme.Outline
import io.github.nevminhnh.mincontrol.master.ui.theme.OfflineDot
import io.github.nevminhnh.mincontrol.master.ui.theme.Primary
import io.github.nevminhnh.mincontrol.master.ui.theme.QuickActionBg
import io.github.nevminhnh.mincontrol.master.ui.theme.QuickActionBorder
import io.github.nevminhnh.mincontrol.master.ui.theme.SegmentBg
import io.github.nevminhnh.mincontrol.master.ui.theme.Success
import io.github.nevminhnh.mincontrol.master.ui.theme.SuccessContainer
import io.github.nevminhnh.mincontrol.master.ui.theme.SuccessDot
import io.github.nevminhnh.mincontrol.master.ui.theme.Surface
import io.github.nevminhnh.mincontrol.master.ui.theme.TextPrimary
import io.github.nevminhnh.mincontrol.master.ui.theme.TextSecondary
import io.github.nevminhnh.mincontrol.master.ui.theme.WarningBg
import io.github.nevminhnh.mincontrol.master.ui.theme.WarningText
import kotlinx.coroutines.delay

@Composable
fun OverviewScreen(
    onAddDevice: () -> Unit,
    onSettings: () -> Unit,
    onAlerts: () -> Unit,
    onActivity: () -> Unit,
    vm: OverviewViewModel = viewModel(),
) {
    val activity = rememberActivity()
    val children by vm.children.collectAsState()
    val alertCount by vm.alertCount.collectAsState()
    val policies by vm.policies.collectAsState()
    val refreshing by vm.refreshing.collectAsState()
    val pending by vm.pending.collectAsState()
    val message by vm.message.collectAsState()
    val snackbar = remember { SnackbarHostState() }
    var lockTarget by remember { mutableStateOf<Child?>(null) }
    var now by remember { mutableStateOf(java.time.ZonedDateTime.now()) }

    LaunchedEffect(Unit) { while (true) { now = java.time.ZonedDateTime.now(); delay(30_000) } }
    LaunchedEffect(message) { message?.let { snackbar.showSnackbar(it); vm.message.value = null } }

    Box(Modifier.fillMaxSize().background(Background)) {
        PullToRefreshBox(isRefreshing = refreshing, onRefresh = { vm.refresh() }, modifier = Modifier.fillMaxSize()) {
            LazyColumn(
                Modifier.fillMaxSize().statusBarsPadding(),
                contentPadding = PaddingValues(start = 16.dp, end = 16.dp, bottom = 24.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                item {
                    Row(Modifier.fillMaxWidth().padding(top = 24.dp), verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text(Fmt.headerNow(now), style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                            Text("Xin chào, ${vm.parentName}", style = MaterialTheme.typography.titleLarge)
                        }
                        RoundIconButton(Icons.Outlined.Settings, "Cài đặt", onSettings)
                        Spacer(Modifier.width(8.dp))
                        RoundIconButton(Icons.Outlined.Add, "Thêm máy tính", onAddDevice)
                    }
                }
                if (alertCount > 0) item { AlertBanner(alertCount, onAlerts) }
                if (children.isEmpty()) item { EmptyOverview(refreshing, onAddDevice) }
                items(children, key = { "${it.deviceId}/${it.sid}" }) { child ->
                    val index = children.indexOf(child)
                    val colors = AvatarColors[index % AvatarColors.size]
                    policies.size // recompose when policies change
                    ChildCard(
                        child = child,
                        avatar = colors,
                        quotaToday = vm.quotaToday(child),
                        bedtime = vm.bedtime(child),
                        busy = child.sid in pending,
                        onLock = { lockTarget = child },
                        onUnlock = { vm.unlockNow(activity, child) },
                        onAdd = { vm.addTime(activity, child, it) },
                        onActivity = { vm.select(child); onActivity() },
                    )
                }
            }
        }
        SnackbarHost(snackbar, Modifier.align(Alignment.BottomCenter).padding(16.dp))
    }

    lockTarget?.let { child ->
        LockConfirmSheet(
            targetName = child.label,
            hostLabel = child.hostname,
            graceSec = vm.graceSec(child),
            onDismiss = { lockTarget = null },
            onLock = { until -> vm.lock(activity, child, until) },
            onUnlock = { vm.unlock(activity, child) },
        )
    }
}

@Composable
private fun RoundIconButton(icon: androidx.compose.ui.graphics.vector.ImageVector, label: String, onClick: () -> Unit) {
    Box(
        Modifier.size(44.dp).clip(CircleShape).background(Surface).border(1.dp, Outline, CircleShape).clickable(onClick = onClick),
        contentAlignment = Alignment.Center,
    ) { Icon(icon, contentDescription = label, tint = TextPrimary, modifier = Modifier.size(20.dp)) }
}

@Composable
private fun AlertBanner(count: Int, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).background(WarningBg).clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Icon(Icons.Outlined.WarningAmber, null, tint = WarningText, modifier = Modifier.size(20.dp))
        Text(
            buildAnnotatedString {
                withStyle(SpanStyle(fontWeight = FontWeight.SemiBold)) { append("$count cảnh báo") }
                append(" cần anh xem")
            },
            style = MaterialTheme.typography.bodyMedium, color = WarningText, modifier = Modifier.weight(1f),
        )
        Icon(Icons.Outlined.ChevronRight, null, tint = WarningText, modifier = Modifier.size(20.dp))
    }
}

@Composable
private fun EmptyOverview(refreshing: Boolean, onAdd: () -> Unit) {
    McCard(spacing = 12.dp) {
        if (refreshing) {
            CircularProgressIndicator(Modifier.align(Alignment.CenterHorizontally), color = Primary)
        } else {
            Text("Chưa có máy tính nào được quản lý", style = MaterialTheme.typography.titleMedium)
            Text("Thêm máy tính của con, rồi chọn tài khoản cần quản lý.", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
            PrimaryButton("Thêm máy tính", onAdd, Modifier.fillMaxWidth(), icon = Icons.Outlined.Add)
        }
    }
}

@Composable
private fun ChildCard(
    child: Child,
    avatar: Pair<Color, Color>,
    quotaToday: Int?,
    bedtime: String?,
    busy: Boolean,
    onLock: () -> Unit,
    onUnlock: () -> Unit,
    onAdd: (Int) -> Unit,
    onActivity: () -> Unit,
) {
    val st = child.state
    val used = st?.usedMin ?: 0
    val remaining = st?.remainingMin ?: quotaToday?.let { (it - used).coerceAtLeast(0) }
    val total = quotaToday ?: remaining?.let { it + used }
    val lockUi = LockUi.of(st)
    val active = child.online && st?.loggedOn == true && st.active && !st.locked

    if (!child.online) {
        McCard(spacing = 16.dp) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Avatar(child.label, avatar.first, avatar.second)
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(child.label, style = MaterialTheme.typography.titleLarge)
                    StatusLine(OfflineDot, "${child.hostname} · Offline từ ${Fmt.relativeDayTime(child.lastSeen)}")
                }
                Column(horizontalAlignment = Alignment.End, verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(remaining?.let(Fmt::hMm) ?: "–", style = MaterialTheme.typography.titleLarge.copy(fontFeatureSettings = "tnum"))
                    Text(if (used == 0) "chưa dùng" else "còn lại", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                }
            }
            Text(
                "Lệnh gửi lúc này sẽ được thực hiện khi máy online lại.",
                style = MaterialTheme.typography.bodySmall, color = TextSecondary,
                modifier = Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).background(Background).padding(horizontal = 12.dp, vertical = 8.dp),
            )
            QuickActions(busy, false, onLock, onUnlock, onAdd)
        }
        return
    }

    McCard(elevated = true, spacing = 20.dp) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Avatar(child.label, avatar.first, avatar.second)
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(child.label, style = MaterialTheme.typography.titleLarge)
                StatusLine(SuccessDot, "${child.hostname} · Đang online")
            }
            val (pillText, pillBg, pillFg) = when {
                st?.locked == true -> Triple("Đã khóa", DangerContainer, DangerText)
                active -> Triple("Đang dùng", SuccessContainer, Success)
                st?.loggedOn == true -> Triple("Đang rảnh", SegmentBg, TextSecondary)
                else -> Triple("Chưa đăng nhập", SegmentBg, TextSecondary)
            }
            Text(
                pillText, style = MaterialTheme.typography.titleSmall, color = pillFg,
                modifier = Modifier.clip(RoundedCornerShape(12.dp)).background(pillBg).padding(horizontal = 10.dp, vertical = 4.dp),
            )
        }
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.Bottom) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(remaining?.let(Fmt::hMm) ?: "–", style = MaterialTheme.typography.displaySmall.copy(letterSpacing = (-0.5).sp, fontFeatureSettings = "tnum"))
                Text("còn lại hôm nay", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
            }
            if (st?.foregroundExe != null && st.loggedOn) {
                Column(horizontalAlignment = Alignment.End, verticalArrangement = Arrangement.spacedBy(4.dp), modifier = Modifier.weight(1f)) {
                    Text(Fmt.appName(st.foregroundExe), style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(
                        "đang mở" + (Fmt.openMinutes(st.foregroundStartedAt)?.let { " · ${Fmt.duration(it)}" } ?: "") + (st.foregroundTitle?.takeIf { it.isNotBlank() }?.let { " · $it" } ?: ""),
                        style = MaterialTheme.typography.bodySmall, color = TextSecondary, maxLines = 1, overflow = TextOverflow.Ellipsis,
                    )
                }
            }
        }
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            ProgressTrack(if (total != null && total > 0) used.toFloat() / total else 0f)
            val parts = buildList {
                add("Đã dùng ${Fmt.duration(used)}" + (total?.let { " / ${Fmt.duration(it)}" } ?: ""))
                bedtime?.let { add("Giờ ngủ lúc $it") }
                lockUi.untilText?.let { add(it) }
            }
            Text(parts.joinToString(" · "), style = MaterialTheme.typography.bodySmall.copy(fontFeatureSettings = "tnum"), color = TextSecondary)
        }
        QuickActions(busy, lockUi.unlock, onLock, onUnlock, onAdd)
        Row(
            Modifier.clickable(onClick = onActivity).padding(vertical = 2.dp),
            verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text("Xem hoạt động hôm nay", style = MaterialTheme.typography.labelLarge, color = Primary)
            Icon(Icons.Outlined.ChevronRight, null, tint = Primary, modifier = Modifier.size(20.dp))
        }
    }
}

@Composable
private fun StatusLine(dot: Color, text: String) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        Dot(dot)
        Text(text, style = MaterialTheme.typography.bodySmall, color = TextSecondary, maxLines = 1, overflow = TextOverflow.Ellipsis)
    }
}

@Composable
private fun QuickActions(busy: Boolean, locked: Boolean, onLock: () -> Unit, onUnlock: () -> Unit, onAdd: (Int) -> Unit) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        QuickAction(Modifier.weight(1f), if (locked) QuickActionBg else DangerContainer, if (locked) QuickActionBorder else DangerBorder, if (locked) Primary else DangerText, if (locked) onUnlock else onLock, enabled = !busy) {
            val fg = if (locked) Primary else DangerText
            Icon(if (locked) Icons.Outlined.LockOpen else Icons.Outlined.Lock, null, tint = fg, modifier = Modifier.size(20.dp))
            Spacer(Modifier.width(4.dp))
            Text(if (locked) "Mở khóa" else "Khóa", style = MaterialTheme.typography.labelLarge, color = fg)
        }
        listOf(15, 30, 60).forEach { m ->
            QuickAction(Modifier.weight(1f), QuickActionBg, QuickActionBorder, Primary, { onAdd(m) }, enabled = !busy) {
                Text("+$m", style = MaterialTheme.typography.labelLarge, color = Primary)
            }
        }
    }
}

@Composable
private fun QuickAction(
    modifier: Modifier, bg: Color, border: Color, fg: Color, onClick: () -> Unit, enabled: Boolean,
    content: @Composable () -> Unit,
) {
    val shape = RoundedCornerShape(14.dp)
    Row(
        modifier.height(48.dp).clip(shape).background(bg).border(BorderStroke(1.dp, border), shape)
            .clickable(enabled = enabled, onClick = onClick),
        horizontalArrangement = Arrangement.Center, verticalAlignment = Alignment.CenterVertically,
    ) { content() }
}
