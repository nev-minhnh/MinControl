package io.github.nevminhnh.mincontrol.master.ui

import androidx.annotation.StringRes
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.NotificationsNone
import androidx.compose.material.icons.outlined.ShowChart
import androidx.compose.material.icons.outlined.Tune
import androidx.compose.ui.graphics.vector.ImageVector
import io.github.nevminhnh.mincontrol.master.R

enum class Destination(val route: String, @StringRes val title: Int, val icon: ImageVector) {
    Overview("overview", R.string.tab_overview, Icons.Outlined.Home),
    Activity("activity", R.string.tab_activity, Icons.Outlined.ShowChart),
    Alerts("alerts", R.string.tab_alerts, Icons.Outlined.NotificationsNone),
    Rules("rules", R.string.tab_rules, Icons.Outlined.Tune),
}

object Routes {
    const val PAIRING = "pairing"
    const val SETTINGS = "settings"
    const val TRANSFER = "transfer"
}
