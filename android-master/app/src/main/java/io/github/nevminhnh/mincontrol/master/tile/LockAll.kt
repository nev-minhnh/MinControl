package io.github.nevminhnh.mincontrol.master.tile

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.activity.compose.setContent
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.fragment.app.FragmentActivity
import io.github.nevminhnh.mincontrol.master.data.Child
import io.github.nevminhnh.mincontrol.master.data.children
import io.github.nevminhnh.mincontrol.master.data.protocol.Command
import io.github.nevminhnh.mincontrol.master.graph
import io.github.nevminhnh.mincontrol.master.security.BiometricCancelledException
import io.github.nevminhnh.mincontrol.master.ui.confirm.LockConfirmSheet
import io.github.nevminhnh.mincontrol.master.ui.theme.MinControlTheme
import io.github.nevminhnh.mincontrol.master.util.toRfc3339

/** Quick Settings tile "Khóa tất cả": opens [LockAllActivity] (biometric confirmation). */
class LockAllTileService : TileService() {
    override fun onStartListening() {
        qsTile?.apply {
            state = Tile.STATE_INACTIVE
            label = "Khóa tất cả"
            updateTile()
        }
    }

    @SuppressLint("StartActivityAndCollapseDeprecated")
    override fun onClick() {
        val intent = Intent(this, LockAllActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= 34) {
            startActivityAndCollapse(PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE))
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }
}

/**
 * Translucent activity showing the lock confirmation sheet for every managed child. Each `lock_now`
 * envelope needs its own signature, so the biometric prompt appears once per child.
 */
class LockAllActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { MinControlTheme { LockAll() } }
    }

    @Composable
    private fun LockAll() {
        var kids by remember { mutableStateOf<List<Child>?>(null) }
        LaunchedEffect(Unit) {
            kids = runCatching { graph.repo.refreshDevices() }.getOrNull()?.flatMap { it.children() }
                ?: graph.repo.cachedDevices().flatMap { it.children() }
        }
        val list = kids ?: return
        if (list.isEmpty() || !graph.settings.registered.value) {
            LaunchedEffect(Unit) { finish() }
            return
        }
        LockConfirmSheet(
            targetName = if (list.size == 1) list.first().label else "tất cả các con",
            hostLabel = list.map { it.hostname }.distinct().joinToString(", "),
            graceSec = 60,
            onDismiss = { finish() },
            onLock = { until ->
                var delivered = true
                var locked = 0
                for (c in list) {
                    try {
                        val r = graph.repo.sendCommand(
                            this@LockAllActivity, c.deviceId,
                            Command.LockNow(graph.repo.newCommandId(), c.sid, until?.toRfc3339()),
                            "Khóa máy của ${c.label}", c.hostname,
                        )
                        delivered = delivered && r.delivered
                        locked++
                    } catch (e: BiometricCancelledException) {
                        if (locked == 0) throw e
                    }
                }
                delivered
            },
            onUnlock = null,
        )
    }
}
