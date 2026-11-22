package io.github.nevminhnh.mincontrol.master.ui.setup

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
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
import androidx.compose.material.icons.outlined.QrCodeScanner
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import io.github.nevminhnh.mincontrol.master.data.api.userMessage
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import io.github.nevminhnh.mincontrol.master.security.BiometricCancelledException
import io.github.nevminhnh.mincontrol.master.ui.pairing.AfterRegister
import io.github.nevminhnh.mincontrol.master.ui.pairing.Fingerprint
import io.github.nevminhnh.mincontrol.master.ui.pairing.PairLink
import io.github.nevminhnh.mincontrol.master.ui.pairing.PairPayload
import io.github.nevminhnh.mincontrol.master.ui.pairing.PairRoute
import io.github.nevminhnh.mincontrol.master.ui.pairing.PairRouting
import io.github.nevminhnh.mincontrol.master.ui.pairing.PairingRegister
import io.github.nevminhnh.mincontrol.master.ui.rememberActivity
import io.github.nevminhnh.mincontrol.master.ui.theme.Mono
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
    var manual by remember { mutableStateOf(false) }
    val context = LocalContext.current
    val activity = rememberActivity()

    fun doRegister(srv: String, sec: String) {
        error = null
        if (!srv.startsWith("https://") && !srv.startsWith("http://")) { error = "Địa chỉ phải bắt đầu bằng https://"; return }
        if (sec.isBlank()) { error = "Nhập mã khởi tạo."; return }
        busy = true
        scope.launch {
            try {
                if (restore && backup.isNotBlank()) {
                    withContext(Dispatchers.Default) { graph.sealKeys.import(backup, pass.toCharArray()) }
                }
                graph.repo.register(srv.trimEnd('/'), sec)
                graph.settings.serverUrl = srv.trimEnd('/')
                if (name.isNotBlank()) graph.settings.parentName = name.trim()
                SetupLink.justRegistered = true
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
    }

    fun apply(p: SetupPayload) {
        server = p.serverUrl; secret = p.secret
        doRegister(p.serverUrl, p.secret)
    }

    // First-run flow state (API.md 12).
    var secondary by remember { mutableStateOf(false) }
    var pairing by remember { mutableStateOf<PairPayload?>(null) }

    fun handlePair(p: PairPayload) {
        when (PairRouting.route(registered = false, p)) {
            is PairRoute.FirstRun -> { error = null; pairing = p }
            PairRoute.UpdateInstaller -> error = PairRouting.UPDATE_INSTALLER_MESSAGE
            PairRoute.Approve -> Unit // not reachable here: this screen is only shown when not registered
        }
    }

    fun registerWithClaim(p: PairPayload) {
        val url = p.serverUrl ?: run { error = PairRouting.UPDATE_INSTALLER_MESSAGE; return }
        error = null
        busy = true
        scope.launch {
            try {
                val deviceId = graph.repo.registerWithClaim(activity, url, p.claimId)
                graph.settings.serverUrl = url
                PairLink.afterRegister.value = AfterRegister(p.claimId, deviceId)
                graph.settings.setRegistered(true)
                graph.push.syncToken()
            } catch (e: BiometricCancelledException) {
                // user cancelled the fingerprint prompt: stay on the confirmation screen
            } catch (e: KeySetupException) {
                error = "Không tạo được khóa: hãy bật khóa màn hình (vân tay / mã PIN) rồi thử lại."
            } catch (e: Exception) {
                if (PairingRegister.isMasterExists(e)) pairing = null
                error = e.userMessage()
            } finally {
                busy = false
            }
        }
    }

    // Deep link (mincontrol://setup?...) or scan result: fill and register immediately.
    val pending by SetupLink.pending.collectAsState()
    LaunchedEffect(pending) {
        pending?.let { SetupLink.pending.value = null; secondary = true; if (!busy) apply(it) }
    }
    // Deep link mincontrol://pair?... from the camera app on a phone that is not set up yet.
    val pendingPair by PairLink.pending.collectAsState()
    LaunchedEffect(pendingPair) {
        pendingPair?.let { PairLink.pending.value = null; if (!busy) handlePair(it) }
    }

    fun scan() {
        error = null
        val opts = GmsBarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build()
        GmsBarcodeScanning.getClient(context, opts).startScan()
            .addOnSuccessListener { code ->
                val setup = SetupLink.parse(code.rawValue)
                val pair = PairLink.parse(code.rawValue)
                when {
                    setup != null -> { secondary = true; apply(setup) }
                    pair != null -> handlePair(pair)
                    else -> error = "Mã QR không phải mã MinControl. Hãy quét mã QR đang hiện trên màn hình máy tính của con."
                }
            }
            .addOnFailureListener { e ->
                // Cancel is silent; anything else (e.g. Play services missing) points to the secondary flow.
                if (e !is com.google.android.gms.common.api.ApiException || e.statusCode != 16) {
                    error = "Không mở được trình quét QR. Hãy thử lại hoặc chọn \"Đổi điện thoại / khôi phục\"."
                }
            }
    }

    Column(
        Modifier.fillMaxSize().background(Background).statusBarsPadding().navigationBarsPadding().imePadding().verticalScroll(rememberScrollState())
            .padding(start = 16.dp, end = 16.dp, top = 24.dp, bottom = 96.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        IconCircle(Icons.Outlined.Shield, PrimaryContainer, Primary, size = 56.dp, iconSize = 28.dp)
        val p = pairing
        if (p != null) {
            Text("Kiểm tra mã khóa", style = MaterialTheme.typography.titleLarge)
            McCard(spacing = 8.dp) {
                Text("Mã khóa của máy tính trong QR", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                Text(Fingerprint.format(p.fp) ?: p.fp, fontFamily = Mono, fontSize = 22.sp, fontWeight = FontWeight.SemiBold, letterSpacing = 2.sp)
                Text("Hãy chắc chắn mã này giống hệt mã đang hiện trên màn hình máy tính. Nếu khác, bấm Hủy.",
                    style = MaterialTheme.typography.bodySmall, color = TextSecondary)
            }
            error?.let { Text(it, color = DangerText, style = MaterialTheme.typography.bodySmall) }
            if (busy) CircularProgressIndicator(color = Primary) else {
                PrimaryButton("Mã khớp, tiếp tục", onClick = { registerWithClaim(p) }, modifier = Modifier.fillMaxWidth(), height = 56.dp, radius = 16.dp, icon = Icons.Outlined.Shield)
                TextButton(onClick = { pairing = null; error = null }, modifier = Modifier.fillMaxWidth()) { Text("Hủy") }
            }
        } else if (!secondary) {
            Text("Thiết lập MinControl", style = MaterialTheme.typography.titleLarge)
            Text("Chạy MinControl-Setup trên máy tính của con, rồi quét mã QR hiện trên màn hình.",
                style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
            error?.let { Text(it, color = DangerText, style = MaterialTheme.typography.bodySmall) }
            if (busy) CircularProgressIndicator(color = Primary) else {
                PrimaryButton("Quét mã trên máy tính", onClick = { scan() }, modifier = Modifier.fillMaxWidth(), height = 56.dp, radius = 16.dp, icon = Icons.Outlined.QrCodeScanner)
                TextButton(onClick = { secondary = true; error = null }, modifier = Modifier.fillMaxWidth()) {
                    Text("Đổi điện thoại / khôi phục", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                }
            }
        } else {
            Text("Đổi điện thoại / khôi phục", style = MaterialTheme.typography.titleLarge)
            Text(
                "Dùng khi máy chủ đã có điện thoại quản lý. Quét mã thiết lập (setup-qr.png) hoặc nhập địa chỉ máy chủ và mã khởi tạo.",
                style = MaterialTheme.typography.bodyMedium, color = TextSecondary,
            )
            if (!manual) {
                if (!busy) {
                    PrimaryButton("Quét mã thiết lập", onClick = { scan() }, modifier = Modifier.fillMaxWidth(), height = 56.dp, radius = 16.dp, icon = Icons.Outlined.QrCodeScanner)
                    OutlinedButton(onClick = { manual = true }, modifier = Modifier.fillMaxWidth().height(48.dp)) { Text("Nhập tay") }
                    OutlinedTextField(name, { name = it.take(30) }, label = { Text("Tên của anh/chị (tùy chọn)") }, singleLine = true,
                        modifier = Modifier.fillMaxWidth().scrollOnFocus())
                }
            } else {
                McCard(spacing = 12.dp) {
                    OutlinedTextField(server, { server = it.trim() }, label = { Text("Địa chỉ máy chủ") }, singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri), modifier = Modifier.fillMaxWidth().scrollOnFocus())
                    OutlinedTextField(secret, { secret = it }, label = { Text("Mã khởi tạo (bootstrap secret)") }, singleLine = true,
                        visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth().scrollOnFocus())
                    OutlinedTextField(name, { name = it.take(30) }, label = { Text("Tên của anh/chị (hiển thị lời chào)") }, singleLine = true,
                        modifier = Modifier.fillMaxWidth().scrollOnFocus())
                }
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
                if (manual) {
                    PrimaryButton("Đăng ký điện thoại này", onClick = { doRegister(server, secret) }, modifier = Modifier.fillMaxWidth(), height = 56.dp, radius = 16.dp)
                    TextButton(onClick = { manual = false }, modifier = Modifier.fillMaxWidth()) { Text("Quay lại quét mã QR") }
                }
                TextButton(onClick = { secondary = false; manual = false; error = null }, modifier = Modifier.fillMaxWidth()) { Text("Quay lại") }
            }
        }
    }
}
