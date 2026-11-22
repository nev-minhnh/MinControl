package io.github.nevminhnh.mincontrol.master.push

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.google.firebase.FirebaseApp
import com.google.firebase.messaging.FirebaseMessaging
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import io.github.nevminhnh.mincontrol.master.AppGraph
import io.github.nevminhnh.mincontrol.master.MainActivity
import io.github.nevminhnh.mincontrol.master.R
import io.github.nevminhnh.mincontrol.master.data.protocol.PushAlert
import io.github.nevminhnh.mincontrol.master.graph
import io.github.nevminhnh.mincontrol.master.widget.WidgetUpdater
import kotlinx.coroutines.launch

object Notifications {
    const val CH_CRITICAL = "critical"
    const val CH_WARN = "warn"
    const val CH_INFO = "info"
    const val EXTRA_OPEN = "open"

    fun createChannels(context: Context) {
        if (Build.VERSION.SDK_INT < 26) return
        val nm = context.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannels(
            listOf(
                NotificationChannel(CH_CRITICAL, "Cảnh báo nghiêm trọng", NotificationManager.IMPORTANCE_HIGH)
                    .apply { description = "Can thiệp, cố vượt chặn, máy mất kết nối" },
                NotificationChannel(CH_WARN, "Cần xem", NotificationManager.IMPORTANCE_DEFAULT)
                    .apply { description = "Yêu cầu duyệt ứng dụng, hết giờ, trang web bị chặn" },
                NotificationChannel(CH_INFO, "Thông tin", NotificationManager.IMPORTANCE_LOW)
                    .apply { description = "Thông báo thường" },
            ),
        )
    }

    fun parse(data: Map<String, String>): PushAlert? {
        if (data["type"] != "alert") return null
        return PushAlert(
            alertId = data["alertId"],
            deviceId = data["deviceId"],
            userSid = data["userSid"],
            severity = data["severity"] ?: "info",
            title = data["title"] ?: "MinControl",
            body = data["body"] ?: "",
        )
    }

    fun channelFor(severity: String) = when (severity) {
        "critical" -> CH_CRITICAL
        "warn" -> CH_WARN
        else -> CH_INFO
    }

    fun show(context: Context, alert: PushAlert) {
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) return
        val intent = Intent(context, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            .putExtra(EXTRA_OPEN, "alerts")
        val pi = PendingIntent.getActivity(context, alert.alertId.hashCode(), intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val n = NotificationCompat.Builder(context, channelFor(alert.severity))
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(alert.title)
            .setContentText(alert.body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(alert.body))
            .setPriority(if (alert.severity == "critical") NotificationCompat.PRIORITY_HIGH else NotificationCompat.PRIORITY_DEFAULT)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setColor(0xFF2F54EB.toInt())
            .setAutoCancel(true)
            .setContentIntent(pi)
            .build()
        try {
            NotificationManagerCompat.from(context).notify(alert.alertId ?: alert.title, 1, n)
        } catch (e: SecurityException) {
            Log.w("MinControl", "notification permission revoked", e)
        }
    }
}

/** Uploads the FCM token when Firebase is configured (google-services.json present at build time). */
class PushRegistrar(private val graph: AppGraph) {
    fun available(): Boolean = FirebaseApp.getApps(graph.appContext).isNotEmpty()

    fun syncToken() {
        if (!available()) return
        runCatching {
            FirebaseMessaging.getInstance().token.addOnSuccessListener { token -> upload(token) }
        }.onFailure { Log.w("MinControl", "FCM unavailable", it) }
    }

    fun upload(token: String) {
        if (!graph.settings.registered.value || graph.settings.fcmTokenSent == token) return
        graph.scope.launch {
            runCatching { graph.repo.subscribePush(token) }
                .onSuccess { graph.settings.fcmTokenSent = token }
                .onFailure { Log.w("MinControl", "push subscribe failed", it) }
        }
    }
}

class McMessagingService : FirebaseMessagingService() {
    override fun onNewToken(token: String) {
        graph.push.upload(token)
    }

    override fun onMessageReceived(message: RemoteMessage) {
        val alert = Notifications.parse(message.data) ?: return
        Notifications.show(this, alert)
        graph.scope.launch {
            runCatching { graph.repo.refreshAlerts() }
            runCatching { graph.repo.refreshDevices() }
            WidgetUpdater.update(applicationContext)
            io.github.nevminhnh.mincontrol.master.refresh.AppEvents.alertArrived.tryEmit(Unit)
        }
    }
}
