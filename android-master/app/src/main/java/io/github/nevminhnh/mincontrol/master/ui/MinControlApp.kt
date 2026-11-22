package io.github.nevminhnh.mincontrol.master.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import io.github.nevminhnh.mincontrol.master.graph
import io.github.nevminhnh.mincontrol.master.ui.activity.ActivityScreen
import io.github.nevminhnh.mincontrol.master.ui.activity.ActivityTab
import io.github.nevminhnh.mincontrol.master.ui.alerts.AlertsScreen
import io.github.nevminhnh.mincontrol.master.ui.overview.OverviewScreen
import io.github.nevminhnh.mincontrol.master.ui.pairing.PairingScreen
import io.github.nevminhnh.mincontrol.master.ui.policy.PolicyScreen
import io.github.nevminhnh.mincontrol.master.ui.settings.SettingsScreen
import io.github.nevminhnh.mincontrol.master.ui.setup.SetupLink
import io.github.nevminhnh.mincontrol.master.ui.setup.SetupScreen
import io.github.nevminhnh.mincontrol.master.ui.theme.Background
import io.github.nevminhnh.mincontrol.master.ui.theme.Danger
import io.github.nevminhnh.mincontrol.master.ui.theme.Outline
import io.github.nevminhnh.mincontrol.master.ui.theme.Primary
import io.github.nevminhnh.mincontrol.master.ui.theme.Surface
import io.github.nevminhnh.mincontrol.master.ui.theme.TextSecondary
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map

/** Which Activity sub-tab to open when navigating from another screen. */
val ActivityTabRequest = MutableStateFlow<ActivityTab?>(null)

@Composable
fun MinControlApp(openTab: String? = null) {
    val graph = LocalContext.current.graph
    val registered by graph.settings.registered.collectAsState()
    if (!registered) {
        SetupScreen()
        return
    }
    val nav = rememberNavController()
    val entry by nav.currentBackStackEntryAsState()
    val current = entry?.destination?.route
    val alertCountFlow = remember { graph.repo.alerts.map { list -> list.count { !it.acked } } }
    val alertCount by alertCountFlow.collectAsState(initial = 0)

    // First run: nothing enrolled yet -> go straight to "Thêm máy tính".
    LaunchedEffect(Unit) {
        if (!SetupLink.justRegistered) return@LaunchedEffect
        SetupLink.justRegistered = false
        val any = runCatching { graph.repo.refreshDevices().isNotEmpty() }
            .getOrElse { runCatching { graph.repo.cachedDevices().isNotEmpty() }.getOrDefault(false) }
        if (!any) nav.navigate(Routes.PAIRING)
    }

    LaunchedEffect(openTab) {
        if (openTab != null && Destination.entries.any { it.route == openTab }) nav.switchTab(openTab)
    }

    fun openActivity(tab: ActivityTab) {
        ActivityTabRequest.value = tab
        nav.switchTab(Destination.Activity.route)
    }

    Scaffold(
        containerColor = Background,
        bottomBar = {
            if (Destination.entries.any { it.route == current }) BottomBar(current, alertCount) { nav.switchTab(it) }
        },
    ) { inner ->
        NavHost(nav, startDestination = Destination.Overview.route, modifier = Modifier.fillMaxSize().padding(inner)) {
            composable(Destination.Overview.route) {
                OverviewScreen(
                    onAddDevice = { nav.navigate(Routes.PAIRING) },
                    onSettings = { nav.navigate(Routes.SETTINGS) },
                    onAlerts = { nav.switchTab(Destination.Alerts.route) },
                    onActivity = { openActivity(ActivityTab.Timeline) },
                )
            }
            composable(Destination.Activity.route) { ActivityScreen() }
            composable(Destination.Alerts.route) {
                AlertsScreen(
                    onTimeline = { openActivity(ActivityTab.Timeline) },
                    onWeb = { openActivity(ActivityTab.Web) },
                )
            }
            composable(Destination.Rules.route) { PolicyScreen() }
            composable(Routes.PAIRING) { PairingScreen(onBack = { nav.popBackStack() }) }
            composable(Routes.SETTINGS) { SettingsScreen(onBack = { nav.popBackStack() }) }
        }
    }
}

private fun NavHostController.switchTab(route: String) {
    navigate(route) {
        popUpTo(graph.findStartDestination().id) { saveState = true }
        launchSingleTop = true
        restoreState = true
    }
}

@Composable
private fun BottomBar(current: String?, alertCount: Int, onSelect: (String) -> Unit) {
    Column(Modifier.fillMaxWidth().background(Surface).navigationBarsPadding()) {
        HorizontalDivider(color = Outline, thickness = 1.dp)
        Row(Modifier.fillMaxWidth().height(79.dp)) {
            Destination.entries.forEach { d ->
                val on = d.route == current
                Column(
                    Modifier.weight(1f).fillMaxHeight().clickable { onSelect(d.route) },
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(4.dp, Alignment.CenterVertically),
                ) {
                    Box {
                        Icon(d.icon, contentDescription = null, tint = if (on) Primary else TextSecondary, modifier = Modifier.size(22.dp))
                        if (d == Destination.Alerts && alertCount > 0) {
                            Box(
                                Modifier.offset(x = 12.dp, y = (-4).dp).widthIn(min = 16.dp).height(16.dp)
                                    .clip(RoundedCornerShape(8.dp)).background(Danger).padding(horizontal = 4.dp),
                                contentAlignment = Alignment.Center,
                            ) {
                                Text(if (alertCount > 99) "99+" else "$alertCount", color = Surface, fontSize = 11.sp,
                                    fontWeight = FontWeight.SemiBold, lineHeight = 12.sp)
                            }
                        }
                    }
                    Text(
                        stringResource(d.title), style = MaterialTheme.typography.labelMedium,
                        color = if (on) Primary else TextSecondary,
                        fontWeight = if (on) FontWeight.SemiBold else FontWeight.Normal,
                    )
                }
            }
        }
    }
}
