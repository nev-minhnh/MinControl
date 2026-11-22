package io.github.nevminhnh.mincontrol.master.ui.settings

import android.content.Intent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import io.github.nevminhnh.mincontrol.master.data.api.userMessage
import io.github.nevminhnh.mincontrol.master.data.protocol.DeviceInfo
import io.github.nevminhnh.mincontrol.master.data.protocol.SigAlg
import io.github.nevminhnh.mincontrol.master.graph
import io.github.nevminhnh.mincontrol.master.security.KeyRole
import io.github.nevminhnh.mincontrol.master.security.SealKeyBackup
import io.github.nevminhnh.mincontrol.master.security.SigFormat
import io.github.nevminhnh.mincontrol.master.ui.Fmt
import io.github.nevminhnh.mincontrol.master.ui.components.BackHeader
import io.github.nevminhnh.mincontrol.master.ui.components.McCard
import io.github.nevminhnh.mincontrol.master.ui.components.SectionLabel
import io.github.nevminhnh.mincontrol.master.ui.components.SettingRow
import io.github.nevminhnh.mincontrol.master.ui.theme.Background
import io.github.nevminhnh.mincontrol.master.ui.theme.DangerText
import io.github.nevminhnh.mincontrol.master.ui.theme.Mono
import io.github.nevminhnh.mincontrol.master.ui.theme.Primary
import io.github.nevminhnh.mincontrol.master.ui.theme.TextSecondary
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private sealed interface SettingsDialog {
    data object Export : SettingsDialog
    data object Import : SettingsDialog
    data object Name : SettingsDialog
    data object Reregister : SettingsDialog
    data class Revoke(val device: DeviceInfo) : SettingsDialog
}

/** Settings: server, key fingerprints, seal-key backup (export/import), devices (revoke), re-register. */
@Composable
fun SettingsScreen(onBack: () -> Unit, onTransfer: () -> Unit = {}) {
    val ctx = LocalContext.current
    val graph = ctx.graph
    val scope = rememberCoroutineScope()
    val devices by graph.repo.devices.collectAsState(initial = emptyList())
    val snackbar = remember { SnackbarHostState() }
    var msg by remember { mutableStateOf<String?>(null) }
    var dialog by remember { mutableStateOf<SettingsDialog?>(null) }
    var name by remember { mutableStateOf(graph.settings.parentName) }
    LaunchedEffect(msg) { msg?.let { snackbar.showSnackbar(it); msg = null } }

    val sign = remember { runCatching { graph.keys.publicKey(KeyRole.SIGN) }.getOrNull() }
    val read = remember { runCatching { graph.keys.publicKey(KeyRole.READ) }.getOrNull() }

    Box(Modifier.fillMaxSize().background(Background)) {
        Column(Modifier.fillMaxSize().statusBarsPadding()) {
            BackHeader("Cài đặt", onBack, Modifier.padding(start = 8.dp, end = 16.dp, top = 16.dp, bottom = 8.dp))
            Column(
                Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(start = 16.dp, end = 16.dp, bottom = 24.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                SectionLabel("Chung")
                Card {
                    SettingRow("Tên hiển thị", onClick = { dialog = SettingsDialog.Name }) { Text(name, style = MaterialTheme.typography.titleMedium) }
                    SettingRow("Máy chủ", subtitle = graph.settings.serverUrl ?: "—")
                    SettingRow("Thông báo đẩy", subtitle = if (graph.push.available()) "Đã bật (Firebase)" else "Chưa cấu hình Firebase", last = true)
                }

                SectionLabel("Khóa điều khiển", Modifier.padding(top = 8.dp))
                Card {
                    SettingRow("Khóa ký lệnh (vân tay)", subtitle = sign?.let { "${algLabel(it.alg)} · ${it.keyId}" } ?: "—") {
                        Text(sign?.let { SigFormat.fingerprint(it.keyId) } ?: "", fontFamily = Mono, style = MaterialTheme.typography.bodySmall)
                    }
                    SettingRow("Khóa đọc dữ liệu", subtitle = read?.let { "${algLabel(it.alg)} · ${it.keyId}" } ?: "—")
                    SettingRow("Chuyển sang điện thoại mới", subtitle = "Tạo mã QR trên điện thoại này để điện thoại mới nhận quyền quản lý",
                        onClick = onTransfer) {}
                    SettingRow("Đăng ký lại với máy chủ", subtitle = "Cần mã khôi phục. Mọi máy tính sẽ phải ghép nối lại",
                        last = true, onClick = { dialog = SettingsDialog.Reregister }) {}
                }

                SectionLabel("Khóa giải mã ảnh màn hình", Modifier.padding(top = 8.dp))
                Card {
                    SettingRow("Sao lưu khóa", subtitle = "Mã hóa bằng mật khẩu (Argon2id). Giữ bản sao lưu để xem lại ảnh cũ nếu mất điện thoại.",
                        onClick = { dialog = SettingsDialog.Export }) {}
                    SettingRow("Khôi phục từ bản sao lưu", subtitle = "Thay khóa hiện tại; cần đăng ký lại để máy tính dùng khóa này.",
                        last = true, onClick = { dialog = SettingsDialog.Import }) {}
                }

                SectionLabel("Máy tính", Modifier.padding(top = 8.dp))
                Card {
                    if (devices.isEmpty()) SettingRow("Chưa có máy tính", last = true)
                    devices.forEachIndexed { i, d ->
                        SettingRow(
                            d.hostname,
                            subtitle = (if (d.online) "Đang online" else "Offline từ ${Fmt.relativeDayTime(d.lastSeen)}") +
                                " · ${d.users.count { it.managed }} tài khoản được quản lý",
                            last = i == devices.lastIndex,
                        ) {
                            TextButton(onClick = { dialog = SettingsDialog.Revoke(d) }) { Text("Thu hồi", color = DangerText) }
                        }
                    }
                }
            }
        }
        SnackbarHost(snackbar, Modifier.align(Alignment.BottomCenter).padding(16.dp))
    }

    when (val d = dialog) {
        SettingsDialog.Name -> TextDialog("Tên hiển thị", name, false, { dialog = null }) {
            graph.settings.parentName = it; name = it; dialog = null
        }
        SettingsDialog.Export -> ExportDialog({ dialog = null }) { pass ->
            scope.launch {
                try {
                    val text = withContext(Dispatchers.Default) { graph.sealKeys.export(pass.toCharArray()) }
                    ctx.startActivity(Intent.createChooser(
                        Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, text)
                            .putExtra(Intent.EXTRA_SUBJECT, "MinControl seal key backup"),
                        "Lưu bản sao lưu",
                    ))
                    dialog = null
                } catch (e: Exception) { msg = e.userMessage() }
            }
        }
        SettingsDialog.Import -> ImportDialog({ dialog = null }) { text, pass ->
            scope.launch {
                try {
                    withContext(Dispatchers.Default) { graph.sealKeys.import(text, pass.toCharArray()) }
                    msg = "Đã khôi phục khóa. Hãy đăng ký lại với máy chủ."
                    dialog = SettingsDialog.Reregister
                } catch (e: SealKeyBackup.BadPassphrase) {
                    msg = "Sai mật khẩu hoặc bản sao lưu hỏng."
                } catch (e: Exception) { msg = e.userMessage() }
            }
        }
        SettingsDialog.Reregister -> TextDialog("Mã khôi phục", "", true, { dialog = null }) { secret ->
            scope.launch {
                try {
                    graph.repo.register(graph.settings.serverUrl ?: error("no server"), secret)
                    msg = "Đã đăng ký lại. Máy tính đã ghép nối vẫn dùng khóa cũ cho tới khi ghép nối lại."
                    dialog = null
                } catch (e: Exception) { msg = e.userMessage() }
            }
        }
        is SettingsDialog.Revoke -> AlertDialog(
            onDismissRequest = { dialog = null },
            title = { Text("Thu hồi ${d.device.hostname}?") },
            text = { Text("Máy sẽ bị ngắt khỏi MinControl và phải ghép nối lại. Dữ liệu cũ vẫn được giữ theo thời hạn lưu.") },
            confirmButton = {
                TextButton(onClick = {
                    scope.launch {
                        try { graph.repo.revokeDevice(d.device.deviceId); msg = "Đã thu hồi ${d.device.hostname}." } catch (e: Exception) { msg = e.userMessage() }
                        dialog = null
                    }
                }) { Text("Thu hồi", color = DangerText) }
            },
            dismissButton = { TextButton(onClick = { dialog = null }) { Text("Hủy") } },
        )
        null -> {}
    }
}

private fun algLabel(a: SigAlg) = when (a) { SigAlg.ED25519 -> "Ed25519"; SigAlg.ES256 -> "ECDSA P-256" }

@Composable
private fun Card(content: @Composable () -> Unit) {
    McCard(radius = 20.dp, padding = PaddingValues(horizontal = 16.dp, vertical = 4.dp)) { content() }
}

@Composable
private fun TextDialog(title: String, initial: String, secret: Boolean, onDismiss: () -> Unit, onSave: (String) -> Unit) {
    var v by remember { mutableStateOf(initial) }
    AlertDialog(
        onDismissRequest = onDismiss, title = { Text(title) },
        text = {
            OutlinedTextField(v, { v = it }, singleLine = true, modifier = Modifier.fillMaxWidth(),
                visualTransformation = if (secret) PasswordVisualTransformation() else androidx.compose.ui.text.input.VisualTransformation.None)
        },
        confirmButton = { TextButton(enabled = v.isNotBlank(), onClick = { onSave(v.trim()) }) { Text("OK", color = Primary) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Hủy") } },
    )
}

@Composable
private fun ExportDialog(onDismiss: () -> Unit, onExport: (String) -> Unit) {
    var a by remember { mutableStateOf("") }
    var b by remember { mutableStateOf("") }
    val err = when {
        a.length in 1..9 -> "Mật khẩu tối thiểu 10 ký tự"
        b.isNotEmpty() && a != b -> "Hai mật khẩu không khớp"
        else -> null
    }
    AlertDialog(
        onDismissRequest = onDismiss, title = { Text("Sao lưu khóa ảnh") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Không có mật khẩu này thì bản sao lưu vô dụng. Hãy ghi lại ở nơi an toàn.", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                OutlinedTextField(a, { a = it }, label = { Text("Mật khẩu") }, singleLine = true, visualTransformation = PasswordVisualTransformation())
                OutlinedTextField(b, { b = it }, label = { Text("Nhập lại") }, singleLine = true, visualTransformation = PasswordVisualTransformation())
                err?.let { Text(it, color = DangerText, style = MaterialTheme.typography.bodySmall) }
            }
        },
        confirmButton = { TextButton(enabled = err == null && a.length >= 10 && a == b, onClick = { onExport(a) }) { Text("Xuất") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Hủy") } },
    )
}

@Composable
private fun ImportDialog(onDismiss: () -> Unit, onImport: (String, String) -> Unit) {
    var text by remember { mutableStateOf("") }
    var pass by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss, title = { Text("Khôi phục khóa ảnh") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(text, { text = it }, label = { Text("Nội dung bản sao lưu") }, minLines = 3)
                OutlinedTextField(pass, { pass = it }, label = { Text("Mật khẩu") }, singleLine = true, visualTransformation = PasswordVisualTransformation())
            }
        },
        confirmButton = { TextButton(enabled = text.isNotBlank() && pass.isNotEmpty(), onClick = { onImport(text, pass) }) { Text("Khôi phục") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Hủy") } },
    )
}
