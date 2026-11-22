package io.github.nevminhnh.mincontrol.master

import android.Manifest
import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.mutableStateOf
import androidx.fragment.app.FragmentActivity
import io.github.nevminhnh.mincontrol.master.push.Notifications
import io.github.nevminhnh.mincontrol.master.ui.MinControlApp
import io.github.nevminhnh.mincontrol.master.ui.pairing.PairLink
import io.github.nevminhnh.mincontrol.master.ui.setup.SetupLink
import io.github.nevminhnh.mincontrol.master.ui.theme.MinControlTheme

/** FragmentActivity (not plain ComponentActivity) because BiometricPrompt needs it. */
class MainActivity : FragmentActivity() {
    private val openTab = mutableStateOf<String?>(null)
    private val notifPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        openTab.value = intent?.getStringExtra(Notifications.EXTRA_OPEN)
        handleSetupLink(intent)
        if (Build.VERSION.SDK_INT >= 33 && savedInstanceState == null) notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        setContent { MinControlTheme { MinControlApp(openTab.value) } }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        openTab.value = intent.getStringExtra(Notifications.EXTRA_OPEN)
        handleSetupLink(intent)
    }

    private fun handleSetupLink(i: Intent?) {
        SetupLink.parse(i?.dataString)?.let { SetupLink.pending.value = it }
        PairLink.parse(i?.dataString)?.let { PairLink.pending.value = it }
        io.github.nevminhnh.mincontrol.master.transfer.TransferLink.parse(i?.dataString)
            ?.let { io.github.nevminhnh.mincontrol.master.transfer.TransferLink.pending.value = it }
    }
}
