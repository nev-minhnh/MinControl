package io.github.nevminhnh.mincontrol.master.ui.setup

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.relocation.bringIntoViewRequester
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import io.github.nevminhnh.mincontrol.master.data.api.userMessage
import io.github.nevminhnh.mincontrol.master.graph
import io.github.nevminhnh.mincontrol.master.security.KeySetupException
import io.github.nevminhnh.mincontrol.master.security.SealKeyBackup
import io.github.nevminhnh.mincontrol.master.ui.components.IconCircle
import io.github.nevminhnh.mincontrol.master.ui.components.McCard
import io.github.nevminhnh.mincontrol.master.ui.components.PrimaryButton
import io.github.nevminhnh.mincontrol.master.ui.theme.Background
import io.github.nevminhnh.mincontrol.master.ui.theme.DangerText
import io.github.nevminhnh.mincontrol.master.ui.theme.Primary
import io.github.nevminhnh.mincontrol.master.ui.theme.PrimaryContainer
import io.github.nevminhnh.mincontrol.master.ui.theme.TextSecondary
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Scrolls the field into view once the IME has finished animating (B7: keyboard covered the name field). */
@OptIn(androidx.compose.foundation.ExperimentalFoundationApi::class)
@Composable
private fun Modifier.scrollOnFocus(): Modifier {
    val requester = remember { androidx.compose.foundation.relocation.BringIntoViewRequester() }
    val scope = rememberCoroutineScope()
    return this.bringIntoViewRequester(requester).onFocusChanged { if (it.isFocused) scope.launch { kotlinx.coroutines.delay(350); requester.bringIntoView() } }
}

/** First run: server URL + bootstrap secret -> generate Keystore keys -> POST /v1/master/register. */
@Composable
fun SetupScreen() {
    val graph = LocalContext.current.graph
    val scope = rememberCoroutineScope()
    var server by remember { mutableStateOf(graph.settings.serverUrl ?: "https://") }
    var secret by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    var restore by remember { mutableStateOf(false) }
    var backup by remember { mutableStateOf("") }
    var pass by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    Column(
        Modifier.fillMaxSize().background(Background).statusBarsPadding().navigationBarsPadding().imePadding().verticalScroll(rememberScrollState())
            .padding(start = 16.dp, end = 16.dp, top = 24.dp, bottom = 96.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        IconCircle(Icons.Outlined.Shield, PrimaryContainer, Primary, size = 56.dp, iconSize = 28.dp)
        Text("Thiết lập MinControl", style = MaterialTheme.typography.titleLarge)
        Text(
            "Điện thoại này sẽ giữ khóa điều khiển. Mọi lệnh khóa máy, thêm giờ và quy tắc đều được ký bằng vân tay của anh.",
            style = MaterialTheme.typography.bodyMedium, color = TextSecondary,
        )
        McCard(spacing = 12.dp) {
            OutlinedTextField(server, { server = it.trim() }, label = { Text("Địa chỉ máy chủ") }, singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri), modifier = Modifier.fillMaxWidth().scrollOnFocus())
            OutlinedTextField(secret, { secret = it }, label = { Text("Mã khởi tạo (bootstrap secret)") }, singleLine = true,
                visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth().scrollOnFocus())
            OutlinedTextField(name, { name = it.take(30) }, label = { Text("Tên của anh/chị (hiển thị lời chào)") }, singleLine = true,
                modifier = Modifier.fillMaxWidth().scrollOnFocus())
        }
        TextButton(onClick = { restore = !restore }) {
            Text(if (restore) "Không khôi phục" else "Khôi phục khóa ảnh màn hình từ bản sao lưu")
        }
        if (restore) {
            McCard(spacing = 12.dp) {
                OutlinedTextField(backup, { backup = it }, label = { Text("Nội dung bản sao lưu") }, minLines = 3, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(pass, { pass = it }, label = { Text("Mật khẩu sao lưu") }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth())
            }
        }
        error?.let { Text(it, color = DangerText, style = MaterialTheme.typography.bodySmall) }
        if (busy) {
            CircularProgressIndicator(color = Primary)
        } else {
            PrimaryButton(
                "Đăng ký điện thoại này",
                onClick = {
                    error = null
                    if (!server.startsWith("https://") && !server.startsWith("http://")) { error = "Địa chỉ phải bắt đầu bằng https://"; return@PrimaryButton }
                    if (secret.isBlank()) { error = "Nhập mã khởi tạo."; return@PrimaryButton }
                    busy = true
                    scope.launch {
                        try {
                            if (restore && backup.isNotBlank()) {
                                withContext(Dispatchers.Default) { graph.sealKeys.import(backup, pass.toCharArray()) }
                            }
                            graph.repo.register(server.trimEnd('/'), secret)
                            graph.settings.serverUrl = server.trimEnd('/')
                            if (name.isNotBlank()) graph.settings.parentName = name.trim()
                            graph.settings.setRegistered(true)
                            graph.push.syncToken()
                        } catch (e: KeySetupException) {
                            error = "Không tạo được khóa: hãy bật khóa màn hình (vân tay / mã PIN) rồi thử lại."
                        } catch (e: SealKeyBackup.BadPassphrase) {
                            error = "Sai mật khẩu sao lưu."
                        } catch (e: Exception) {
                            error = e.userMessage()
                        } finally {
                            busy = false
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth(), height = 56.dp, radius = 16.dp,
            )
        }
    }
}
