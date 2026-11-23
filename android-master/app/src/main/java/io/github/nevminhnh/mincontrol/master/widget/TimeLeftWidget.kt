package io.github.nevminhnh.mincontrol.master.widget

import android.content.Context
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.glance.GlanceId
import androidx.glance.GlanceModifier
import androidx.glance.GlanceTheme
import androidx.glance.action.actionStartActivity
import androidx.glance.action.clickable
import androidx.glance.appwidget.GlanceAppWidget
import androidx.glance.appwidget.GlanceAppWidgetReceiver
import androidx.glance.appwidget.cornerRadius
import androidx.glance.appwidget.provideContent
import androidx.glance.appwidget.updateAll
import androidx.glance.background
import androidx.glance.layout.Alignment
import androidx.glance.layout.Column
import androidx.glance.layout.Row
import androidx.glance.layout.Spacer
import androidx.glance.layout.fillMaxSize
import androidx.glance.layout.fillMaxWidth
import androidx.glance.layout.height
import androidx.glance.layout.padding
import androidx.glance.layout.width
import androidx.glance.text.FontWeight
import androidx.glance.text.Text
import androidx.glance.text.TextStyle
import androidx.glance.unit.ColorProvider
import io.github.nevminhnh.mincontrol.master.MainActivity
import io.github.nevminhnh.mincontrol.master.data.Child
import io.github.nevminhnh.mincontrol.master.data.children
import io.github.nevminhnh.mincontrol.master.graph

/** Home-screen widget: time left today per child (from the offline cache). */
class TimeLeftWidget : GlanceAppWidget() {
    override suspend fun provideGlance(context: Context, id: GlanceId) {
        val kids = runCatching { context.graph.repo.cachedDevices().flatMap { it.children() } }.getOrDefault(emptyList())
        provideContent { GlanceTheme { Content(kids) } }
    }

    @Composable
    private fun Content(kids: List<Child>) {
        Column(
            GlanceModifier.fillMaxSize().background(Color.White).cornerRadius(24.dp).padding(16.dp)
                .clickable(actionStartActivity<MainActivity>()),
        ) {
            Text("Thời gian còn lại", style = TextStyle(fontSize = 13.sp, color = ColorProvider(Color(0xFF4A5568))))
            Spacer(GlanceModifier.height(8.dp))
            if (kids.isEmpty()) {
                Text("Chưa có dữ liệu", style = TextStyle(fontSize = 15.sp, color = ColorProvider(Color(0xFF0E1726))))
            }
            kids.take(4).forEach { c ->
                val left = c.state?.remainingMin
                Row(GlanceModifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        c.label, modifier = GlanceModifier.defaultWeight(),
                        style = TextStyle(fontSize = 15.sp, fontWeight = FontWeight.Medium, color = ColorProvider(Color(0xFF0E1726))),
                    )
                    Text(
                        if (!c.online) "offline" else if (c.state?.locked == true) "đã khóa" else "",
                        style = TextStyle(fontSize = 12.sp, color = ColorProvider(Color(0xFF4A5568))),
                    )
                    Spacer(GlanceModifier.width(8.dp))
                    Text(
                        left?.let { "${it / 60}:${"%02d".format(it % 60)}" } ?: "–",
                        style = TextStyle(fontSize = 20.sp, fontWeight = FontWeight.Bold, color = ColorProvider(Color(0xFF2F54EB))),
                    )
                }
            }
        }
    }
}

class TimeLeftWidgetReceiver : GlanceAppWidgetReceiver() {
    override val glanceAppWidget: GlanceAppWidget = TimeLeftWidget()
}

object WidgetUpdater {
    suspend fun update(context: Context) {
        runCatching { TimeLeftWidget().updateAll(context) }
    }
}
