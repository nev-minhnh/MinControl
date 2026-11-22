package io.github.nevminhnh.mincontrol.master.ui

import androidx.annotation.StringRes
import io.github.nevminhnh.mincontrol.master.R

enum class Destination(val route: String, @StringRes val title: Int, val glyph: String) {
    Overview("overview", R.string.tab_overview, "▦"),
    Activity("activity", R.string.tab_activity, "◴"),
    Alerts("alerts", R.string.tab_alerts, "△"),
    Rules("rules", R.string.tab_rules, "☰"),
}
