package io.github.nevminhnh.mincontrol.master.refresh

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import io.github.nevminhnh.mincontrol.master.ui.theme.TextSecondary

/** Marks [refresher] visible while the host lifecycle is RESUMED and this composable is in the composition. */
@Composable
fun AutoRefreshEffect(refresher: AutoRefresher) {
    val owner = LocalLifecycleOwner.current
    DisposableEffect(owner, refresher) {
        val obs = LifecycleEventObserver { _, e ->
            when (e) {
                Lifecycle.Event.ON_RESUME -> refresher.setVisible(true)
                Lifecycle.Event.ON_PAUSE -> refresher.setVisible(false)
                else -> {}
            }
        }
        owner.lifecycle.addObserver(obs)
        if (owner.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) refresher.setVisible(true)
        onDispose {
            owner.lifecycle.removeObserver(obs)
            refresher.setVisible(false)
        }
    }
}

/** Small "Cập nhật lúc HH:mm:ss" caption (nothing before the first refresh). */
@Composable
fun UpdatedLine(refresher: AutoRefresher, modifier: Modifier = Modifier) {
    val at by refresher.lastUpdated.collectAsState()
    UpdatedFormat.label(at)?.let {
        Text(it, style = MaterialTheme.typography.bodySmall, color = TextSecondary, modifier = modifier.fillMaxWidth().padding(vertical = 2.dp))
    }
}

/** Pull-to-refresh wrapper bound to [refresher]; the content keeps showing while it loads. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RefreshBox(refresher: AutoRefresher, modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    val refreshing by refresher.refreshing.collectAsState()
    PullToRefreshBox(isRefreshing = refreshing, onRefresh = { refresher.trigger(manual = true) }, modifier = modifier) {
        Box(Modifier.fillMaxSize()) { content() }
    }
}
