package io.github.nevminhnh.mincontrol.master.ui.alerts

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.AccessTime
import androidx.compose.material.icons.outlined.DesktopWindows
import androidx.compose.material.icons.outlined.GppMaybe
import androidx.compose.material.icons.outlined.Language
import androidx.compose.material.icons.outlined.WifiOff
import androidx.compose.material.icons.outlined.NotificationsNone
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import io.github.nevminhnh.mincontrol.master.refresh.AutoRefreshEffect
import io.github.nevminhnh.mincontrol.master.refresh.RefreshBox
import io.github.nevminhnh.mincontrol.master.refresh.UpdatedLine
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import io.github.nevminhnh.mincontrol.master.ui.components.ChipRow
import io.github.nevminhnh.mincontrol.master.ui.components.EmptyState
import io.github.nevminhnh.mincontrol.master.ui.components.FilterChip
import io.github.nevminhnh.mincontrol.master.ui.components.IconCircle
import io.github.nevminhnh.mincontrol.master.ui.components.PrimaryButton
import io.github.nevminhnh.mincontrol.master.ui.components.SecondaryButton
import io.github.nevminhnh.mincontrol.master.ui.rememberActivity
import io.github.nevminhnh.mincontrol.master.ui.theme.Background
import io.github.nevminhnh.mincontrol.master.ui.theme.DangerBorder
import io.github.nevminhnh.mincontrol.master.ui.theme.DangerContainer
import io.github.nevminhnh.mincontrol.master.ui.theme.DangerText
import io.github.nevminhnh.mincontrol.master.ui.theme.NeutralIconBg
import io.github.nevminhnh.mincontrol.master.ui.theme.Primary
import io.github.nevminhnh.mincontrol.master.ui.theme.PrimaryContainer
import io.github.nevminhnh.mincontrol.master.ui.theme.Surface
import io.github.nevminhnh.mincontrol.master.ui.theme.TextBody
import io.github.nevminhnh.mincontrol.master.ui.theme.TextSecondary
import io.github.nevminhnh.mincontrol.master.ui.theme.WarningBg
import io.github.nevminhnh.mincontrol.master.ui.theme.WarningIcon

@Composable
fun AlertsScreen(onTimeline: () -> Unit, onWeb: () -> Unit, vm: AlertsViewModel = viewModel()) {
    val activity = rememberActivity()
    val cards by vm.cards.collectAsState()
    val filter by vm.filter.collectAsState()
    val unacked by vm.unackedCount.collectAsState()
    val refreshing by vm.refreshing.collectAsState()
    val busy by vm.busy.collectAsState()
    val message by vm.message.collectAsState()
    val snackbar = remember { SnackbarHostState() }
    LaunchedEffect(message) { message?.let { snackbar.showSnackbar(it); vm.message.value = null } }
    AutoRefreshEffect(vm.refresher)

    Box(Modifier.fillMaxSize().background(Background)) {
        Column(Modifier.fillMaxSize().statusBarsPadding()) {
            Column(Modifier.padding(start = 16.dp, end = 16.dp, top = 24.dp, bottom = 16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                Text("Cảnh báo", style = MaterialTheme.typography.titleLarge)
                ChipRow {
                    AlertFilter.entries.forEach { f ->
                        FilterChip(if (f == AlertFilter.ALL) "${f.label} · $unacked" else f.label, filter == f, { vm.filter.value = f })
                    }
                }
            }
            UpdatedLine(vm.refresher, Modifier.padding(horizontal = 16.dp))
            RefreshBox(vm.refresher, Modifier.fillMaxSize()) {
                LazyColumn(
                    Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(start = 16.dp, end = 16.dp, bottom = 24.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    if (cards.isEmpty() && !refreshing) item { EmptyState("Không có cảnh báo nào") }
                    var lastDay: String? = null
                    cards.forEach { card ->
                        if (card.day != lastDay) {
                            val first = lastDay == null
                            lastDay = card.day
                            item(key = "day-${card.day}") {
                                Text(card.day, style = MaterialTheme.typography.titleSmall, color = TextSecondary,
                                    modifier = Modifier.padding(top = if (first) 0.dp else 8.dp))
                            }
                        }
                        item(key = card.view.item.id) {
                            AlertCardView(
                                card, card.view.item.id in busy,
                                onAllow = { vm.decide(activity, card, true) },
                                onBlock = { vm.decide(activity, card, false) },
                                onAck = { vm.ack(card) },
                                onTimeline = onTimeline, onWeb = onWeb,
                            )
                        }
                    }
                }
            }
        }
        SnackbarHost(snackbar, Modifier.align(Alignment.BottomCenter).padding(16.dp))
    }
}

@Composable
private fun AlertCardView(
    card: AlertCard, busy: Boolean,
    onAllow: () -> Unit, onBlock: () -> Unit, onAck: () -> Unit, onTimeline: () -> Unit, onWeb: () -> Unit,
) {
    val muted = card.view.acked || card.kind == AlertKind.OFFLINE || card.kind == AlertKind.QUOTA && card.view.item.severity == "info"
    val critical = card.view.item.severity == "critical" && !card.view.acked
    val (icon, colors) = when (card.kind) {
        AlertKind.TAMPER -> Icons.Outlined.GppMaybe to (DangerContainer to DangerText)
        AlertKind.REQUEST -> Icons.Outlined.DesktopWindows to (PrimaryContainer to Primary)
        AlertKind.WEB -> Icons.Outlined.Language to (WarningBg to WarningIcon)
        AlertKind.QUOTA -> Icons.Outlined.AccessTime to (NeutralIconBg to TextSecondary)
        AlertKind.OFFLINE -> Icons.Outlined.WifiOff to (NeutralIconBg to TextSecondary)
        AlertKind.OTHER -> Icons.Outlined.NotificationsNone to (NeutralIconBg to TextSecondary)
    }
    val shape = RoundedCornerShape(20.dp)
    Row(
        Modifier.fillMaxWidth()
            .then(if (critical) Modifier.background(DangerBorder, shape).padding(1.dp) else Modifier)
            .clip(shape)
            .background(if (muted) Color.Transparent else Surface)
            .padding(horizontal = 16.dp, vertical = if (muted) 8.dp else 16.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (muted) IconCircle(icon, NeutralIconBg, TextSecondary) else IconCircle(icon, colors.first, colors.second)
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    card.title, style = MaterialTheme.typography.bodyMedium,
                    fontWeight = if (muted) FontWeight.Normal else FontWeight.SemiBold,
                    color = if (muted) TextBody else Color.Unspecified, modifier = Modifier.weight(1f),
                )
                Text(card.time, style = MaterialTheme.typography.bodySmall, color = TextSecondary)
            }
            if (card.body.isNotBlank()) Text(card.body, style = MaterialTheme.typography.bodySmall, color = if (muted) TextSecondary else TextBody)
            if (!card.view.acked) {
                when (card.kind) {
                    AlertKind.REQUEST -> Row(Modifier.padding(top = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        SecondaryButton("Chặn", onBlock, Modifier.weight(1f), height = 44.dp, radius = 12.dp, enabled = !busy)
                        PrimaryButton("Cho phép", onAllow, Modifier.weight(1f), height = 44.dp, radius = 12.dp, enabled = !busy)
                    }
                    else -> Row(Modifier.padding(top = 4.dp), horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                        when (card.kind) {
                            AlertKind.TAMPER -> Link("Xem trong dòng thời gian") { onAck(); onTimeline() }
                            AlertKind.WEB -> Link("Xem lịch sử web") { onAck(); onWeb() }
                            else -> {}
                        }
                        Link("Đã xem", TextSecondary, onAck)
                    }
                }
            }
        }
    }
}

@Composable
private fun Link(text: String, color: Color = Primary, onClick: () -> Unit) {
    Text(text, style = MaterialTheme.typography.titleSmall, color = color, modifier = Modifier.clickable(onClick = onClick))
}
