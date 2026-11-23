package io.github.nevminhnh.mincontrol.master.ui.diagnose

import android.app.Application
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import io.github.nevminhnh.mincontrol.master.data.api.userMessage
import io.github.nevminhnh.mincontrol.master.data.protocol.Command
import io.github.nevminhnh.mincontrol.master.data.protocol.DeviceInfo
import io.github.nevminhnh.mincontrol.master.graph
import io.github.nevminhnh.mincontrol.master.security.BiometricCancelledException
import io.github.nevminhnh.mincontrol.master.ui.components.BackHeader
import io.github.nevminhnh.mincontrol.master.ui.components.FilterChip
import io.github.nevminhnh.mincontrol.master.ui.components.McCard
import io.github.nevminhnh.mincontrol.master.ui.components.PrimaryButton
import io.github.nevminhnh.mincontrol.master.ui.components.SecondaryButton
import io.github.nevminhnh.mincontrol.master.ui.rememberActivity
import io.github.nevminhnh.mincontrol.master.ui.theme.Background
import io.github.nevminhnh.mincontrol.master.ui.theme.Primary
import io.github.nevminhnh.mincontrol.master.ui.theme.TextBody
import io.github.nevminhnh.mincontrol.master.ui.theme.TextSecondary
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import java.time.Instant

sealed interface DiagState {
    data object Idle : DiagState
    data object Sending : DiagState
    data class Waiting(val sec: Int, val delivered: Boolean) : DiagState
    data class Ready(val sections: List<DiagSection>, val raw: String, val ts: String) : DiagState
    data class Failed(val message: String) : DiagState
}

class DiagnoseViewModel(app: Application) : AndroidViewModel(app) {
    private val repo = app.graph.repo
    val devices: StateFlow<List<DeviceInfo>> = repo.devices.stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())
    val deviceId = MutableStateFlow<String?>(null)
    val state = MutableStateFlow<DiagState>(DiagState.Idle)

    fun select(id: String) { deviceId.value = id; state.value = DiagState.Idle }

    fun run(activity: FragmentActivity) {
        val id = deviceId.value ?: devices.value.firstOrNull()?.deviceId ?: return
        val host = devices.value.firstOrNull { it.deviceId == id }?.hostname
        if (state.value is DiagState.Sending || state.value is DiagState.Waiting) return
        viewModelScope.launch {
            state.value = DiagState.Sending
            val cmdId = repo.newCommandId()
            val from = Instant.now().minusSeconds(DiagnoseLogic.LOOKBACK_SEC)
            val delivered = try {
                repo.sendCommand(activity, id, Command.Diagnose(cmdId), "Chẩn đoán máy ${host ?: ""}".trim(), host).delivered
            } catch (e: BiometricCancelledException) {
                state.value = DiagState.Idle; return@launch
            } catch (e: Exception) {
                state.value = DiagState.Failed(e.userMessage()); return@launch
            }
            val start = System.currentTimeMillis()
            while (System.currentTimeMillis() - start < DiagnoseLogic.POLL_TIMEOUT_MS) {
                state.value = DiagState.Waiting(((System.currentTimeMillis() - start) / 1000).toInt(), delivered)
                delay(DiagnoseLogic.POLL_INTERVAL_MS)
                val page = runCatching { repo.events(id, null, from, Instant.now().plusSeconds(3600), type = "diag.report") }.getOrNull() ?: continue
                val hit = DiagnoseLogic.pick(page.items, cmdId) ?: continue
                state.value = DiagState.Ready(DiagnoseLogic.sections(hit.data), DiagnoseLogic.rawReport(hit.data), hit.ts)
                return@launch
            }
            state.value = DiagState.Failed(
                if (delivered) "Máy chưa gửi báo cáo sau 60 giây. Thử lại sau ít phút." else "Máy đang offline, chưa nhận được lệnh chẩn đoán.",
            )
        }
    }
}

@Composable
fun DiagnoseScreen(onBack: () -> Unit, vm: DiagnoseViewModel = viewModel()) {
    val activity = rememberActivity()
    val devices by vm.devices.collectAsState()
    val selected by vm.deviceId.collectAsState()
    val state by vm.state.collectAsState()
    val clipboard = LocalClipboardManager.current
    val snackbar = remember { SnackbarHostState() }
    var copied by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(copied) { copied?.let { snackbar.showSnackbar(it); copied = null } }
    val current = selected ?: devices.firstOrNull()?.deviceId
    val busy = state is DiagState.Sending || state is DiagState.Waiting

    Box(Modifier.fillMaxSize().background(Background)) {
        Column(Modifier.fillMaxSize().statusBarsPadding()) {
            BackHeader("Chẩn đoán máy", onBack, Modifier.padding(start = 8.dp, end = 16.dp, top = 16.dp, bottom = 8.dp))
            Column(
                Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(start = 16.dp, end = 16.dp, bottom = 24.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                if (devices.isEmpty()) Text("Chưa có máy tính nào.", color = TextSecondary)
                if (devices.size > 1) Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    devices.forEach { d -> FilterChip(d.hostname, d.deviceId == current, { vm.select(d.deviceId) }) }
                }
                Text(
                    "Gửi lệnh chẩn đoán (cần xác thực vân tay) để máy tính trả về tình trạng dịch vụ, bộ lọc mạng, proxy, trình duyệt và nhật ký lỗi. Báo cáo không chứa khóa hay mật khẩu.",
                    style = MaterialTheme.typography.bodySmall, color = TextBody,
                )
                PrimaryButton(
                    if (state is DiagState.Ready) "Chẩn đoán lại" else "Chạy chẩn đoán", { vm.run(activity) },
                    Modifier.fillMaxWidth(), enabled = current != null && !busy, icon = Icons.Outlined.Fingerprint,
                )
                when (val s = state) {
                    DiagState.Idle -> {}
                    DiagState.Sending -> Status("Đang gửi lệnh…")
                    is DiagState.Waiting -> Status(
                        (if (s.delivered) "Đang chờ máy tính trả báo cáo" else "Máy đang offline, lệnh sẽ chạy khi máy online") + " (${s.sec}s / 60s)…",
                    )
                    is DiagState.Failed -> Text(s.message, color = TextBody)
                    is DiagState.Ready -> {
                        Text("Báo cáo lúc ${s.ts}", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                        SecondaryButton("Sao chép để gửi hỗ trợ", { clipboard.setText(AnnotatedString(s.raw)); copied = "Đã sao chép báo cáo." }, Modifier.fillMaxWidth())
                        s.sections.forEach { sec ->
                            SectionCard(sec) { clipboard.setText(AnnotatedString(sec.raw)); copied = "Đã sao chép mục ${DiagnoseLogic.title(sec.name)}." }
                        }
                    }
                }
            }
        }
        SnackbarHost(snackbar, Modifier.align(Alignment.BottomCenter).padding(16.dp))
    }
}

@Composable
private fun Status(text: String) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        CircularProgressIndicator(Modifier.padding(4.dp), color = Primary, strokeWidth = 2.dp)
        Text(text, color = TextBody)
    }
}

@Composable
private fun SectionCard(sec: DiagSection, onCopy: () -> Unit) {
    var open by remember { mutableStateOf(false) }
    McCard(padding = PaddingValues(16.dp), spacing = 8.dp) {
        Row(Modifier.fillMaxWidth().clickable { open = !open }, verticalAlignment = Alignment.CenterVertically) {
            Text(DiagnoseLogic.title(sec.name), style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
            Text(if (open) "Thu gọn" else "${sec.rows.size} mục", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
        }
        if (open) {
            sec.rows.forEach { (k, v) ->
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(k, style = MaterialTheme.typography.bodySmall, color = TextSecondary, modifier = Modifier.weight(0.4f))
                    Text(v, style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(0.6f))
                }
            }
            TextButton(onClick = onCopy) { Text("Sao chép JSON mục này") }
        }
    }
}
