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
import io.github.nevminhnh.mincontrol.master.data.api.ApiException
import io.github.nevminhnh.mincontrol.master.transfer.PendingTransfer
import io.github.nevminhnh.mincontrol.master.transfer.TransferLink
import io.github.nevminhnh.mincontrol.master.transfer.TransferPayload
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
        if (sec.isBlank()) { error = "Nhập mã khôi phục."; return }
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

    // Phone transfer, new phone side (API.md 13).
    var transferOffer by remember { mutableStateOf<TransferPayload?>(null) }
    var transferPending by remember { mutableStateOf(graph.transfers.pending()) }
    var transferProgress by remember { mutableStateOf<String?>(null) }
    var transferResult by remember { mutableStateOf<String?>(null) }

    fun claimTransfer(t: TransferPayload) {
        error = null
        busy = true
        scope.launch {
            try {
                transferPending = graph.transfers.claim(activity, t)
                transferOffer = null
            } catch (e: BiometricCancelledException) {
                // stay on the offer screen
            } catch (e: KeySetupException) {
                error = "Không tạo được khóa: hãy bật khóa màn hình (vân tay / mã PIN) rồi thử lại."
            } catch (e: Exception) {
                error = if (e is ApiException.Http && (e.status == 404 || e.status == 410)) "Mã chuyển máy đã hết hạn hoặc đã được dùng. Tạo mã mới trên điện thoại cũ."
                else e.userMessage()
            } finally {
                busy = false
            }
        }
    }

    // Poll until the old phone completes, then import the old seal key and re-sign every policy with the new key.
    LaunchedEffect(transferPending) {
        val p = transferPending ?: return@LaunchedEffect
        if (transferResult != null) return@LaunchedEffect
        while (true) {
            kotlinx.coroutines.delay(2000)
            val st = try {
                graph.transfers.poll(p)
            } catch (e: ApiException.Http) {
                if (e.status == 404 || e.status == 410) {
                    graph.transfers.clearPending(); transferPending = null
                    error = "Chuyển máy đã hết hạn hoặc bị hủy. Tạo mã mới trên điện thoại cũ."
                    return@LaunchedEffect
                }
                continue
            } catch (e: Exception) {
                continue
            }
            when (st.status) {
                "done" -> {
                    try {
                        graph.transfers.finish(p, st)
                    } catch (e: Exception) {
                        error = "Không mở được khóa ảnh cũ (${e.message}). Ảnh chụp cũ có thể không xem được."
                    }
                    graph.settings.serverUrl = p.serverUrl
                    transferProgress = "Đang cập nhật quy tắc cho các máy…"
                    val r = runCatching { graph.transfers.republishPolicies(activity) { transferProgress = it } }
                    transferProgress = null
                    transferResult = r.map { it.message }.getOrElse { "Chưa cập nhật được quy tắc: ${it.userMessage()} Mở Quy tắc và bấm Áp dụng lại." }
                    return@LaunchedEffect
                }
                "expired", "rejected", "cancelled", "failed" -> {
                    graph.transfers.clearPending(); transferPending = null
                    error = "Chuyển máy đã hết hạn hoặc bị hủy. Tạo mã mới trên điện thoại cũ."
                    return@LaunchedEffect
                }
            }
        }
    }

    fun enterApp() {
        SetupLink.justRegistered = false
        graph.settings.setRegistered(true)
        graph.push.syncToken()
    }

    val pendingTransferLink by TransferLink.pending.collectAsState()
    LaunchedEffect(pendingTransferLink) {
        pendingTransferLink?.let { TransferLink.pending.value = null; if (!busy && transferPending == null) { error = null; transferOffer = it } }
    }

    fun scan() {
        error = null
        val opts = GmsBarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build()
        GmsBarcodeScanning.getClient(context, opts).startScan()
            .addOnSuccessListener { code ->
                val setup = SetupLink.parse(code.rawValue)
                val pair = PairLink.parse(code.rawValue)
                val transfer = TransferLink.parse(code.rawValue)
                when {
                    transfer != null -> { secondary = false; transferOffer = transfer }
                    setup != null -> { secondary = true; apply(setup) }
                    pair != null -> handlePair(pair)
                    else -> error = "Mã QR không phải mã MinControl. Hãy quét mã QR đang hiện trên màn hình máy tính của con."
                }
            }
            .addOnFailureListener { e ->
                // Cancel is silent; anything else (e.g. Play services missing) points to the secondary flow.
                if (e !is com.google.android.gms.common.api.ApiException || e.statusCode != 16) {
                    error = "Không mở được trình quét QR. Hãy thử lại hoặc chọn \"Mất điện thoại? Dùng mã khôi phục\"."
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
        val tp = transferPending
        val offer = transferOffer
        if (tp != null || transferResult != null) {
            Text("Nhận quyền quản lý", style = MaterialTheme.typography.titleLarge)
            if (tp != null) {
                McCard(spacing = 8.dp) {
                    Text("Mã của điện thoại mới", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                    Text(tp.fingerprint, fontFamily = Mono, fontSize = 24.sp, fontWeight = FontWeight.SemiBold, letterSpacing = 2.sp)
                    Text("Mã của điện thoại mới: ${tp.fingerprint} — so với điện thoại cũ", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                }
            }
            error?.let { Text(it, color = DangerText, style = MaterialTheme.typography.bodySmall) }
            val result = transferResult
            when {
                result != null -> {
                    Text("Đã nhận quyền quản lý.", style = MaterialTheme.typography.titleMedium)
                    Text(result, style = MaterialTheme.typography.bodyMedium)
                    PrimaryButton("Vào Tổng quan", onClick = { enterApp() }, modifier = Modifier.fillMaxWidth(), height = 56.dp, radius = 16.dp)
                }
                transferProgress != null -> {
                    CircularProgressIndicator(color = Primary)
                    Text(transferProgress!!, style = MaterialTheme.typography.bodyMedium)
                    Text("Xác nhận vân tay cho từng máy tính để ký lại quy tắc bằng khóa mới.", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                }
                else -> {
                    CircularProgressIndicator(color = Primary)
                    Text("Trên điện thoại cũ, kiểm tra mã giống hệt rồi bấm \"Khớp, chuyển quyền\". Đang chờ…",
                        style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                    TextButton(onClick = { graph.transfers.clearPending(); transferPending = null; error = null }, modifier = Modifier.fillMaxWidth()) { Text("Hủy") }
                }
            }
        } else if (offer != null) {
            Text("Chuyển từ điện thoại cũ", style = MaterialTheme.typography.titleLarge)
            Text("Điện thoại này sẽ nhận quyền quản lý từ điện thoại cũ. Các máy tính không cần ghép nối lại.\nMáy chủ: ${offer.serverUrl}",
                style = MaterialTheme.typography.bodyMedium, color = TextSecondary)
            error?.let { Text(it, color = DangerText, style = MaterialTheme.typography.bodySmall) }
            if (busy) CircularProgressIndicator(color = Primary) else {
                PrimaryButton("Tiếp tục", onClick = { claimTransfer(offer) }, modifier = Modifier.fillMaxWidth(), height = 56.dp, radius = 16.dp, icon = Icons.Outlined.Shield)
                TextButton(onClick = { transferOffer = null; error = null }, modifier = Modifier.fillMaxWidth()) { Text("Hủy") }
            }
        } else if (p != null) {
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
                Text("Đổi điện thoại? Trên điện thoại cũ vào Cài đặt → \"Chuyển sang điện thoại mới\" rồi quét mã QR hiện ở đó.",
                    style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                TextButton(onClick = { secondary = true; error = null }, modifier = Modifier.fillMaxWidth()) {
                    Text("Mất điện thoại? Dùng mã khôi phục", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                }
            }
        } else {
            Text("Mất điện thoại? Dùng mã khôi phục", style = MaterialTheme.typography.titleLarge)
            Text(
                "Quét mã khôi phục (file recovery-qr.png, tạo khi dựng máy chủ) hoặc nhập địa chỉ máy chủ và mã khôi phục.",
                style = MaterialTheme.typography.bodyMedium, color = TextSecondary,
            )
            McCard(spacing = 4.dp) {
                Text("Lưu ý", style = MaterialTheme.typography.titleSmall, color = DangerText)
                Text("Điện thoại cũ sẽ mất quyền, và MỌI máy tính sẽ phải ghép nối lại (trên máy tính: \"Kết nối MinControl với điện thoại\" → \"Ghép nối lại\"). " +
                    "Mã khôi phục chỉ dùng được một lần. Nếu còn điện thoại cũ, hãy dùng \"Chuyển sang điện thoại mới\" trên điện thoại cũ.",
                    style = MaterialTheme.typography.bodySmall, color = TextSecondary)
            }
            if (!manual) {
                if (!busy) {
                    PrimaryButton("Quét mã khôi phục", onClick = { scan() }, modifier = Modifier.fillMaxWidth(), height = 56.dp, radius = 16.dp, icon = Icons.Outlined.QrCodeScanner)
                    OutlinedButton(onClick = { manual = true }, modifier = Modifier.fillMaxWidth().height(48.dp)) { Text("Nhập tay") }
                    OutlinedTextField(name, { name = it.take(30) }, label = { Text("Tên của anh/chị (tùy chọn)") }, singleLine = true,
                        modifier = Modifier.fillMaxWidth().scrollOnFocus())
                }
            } else {
                McCard(spacing = 12.dp) {
                    OutlinedTextField(server, { server = it.trim() }, label = { Text("Địa chỉ máy chủ") }, singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri), modifier = Modifier.fillMaxWidth().scrollOnFocus())
                    OutlinedTextField(secret, { secret = it }, label = { Text("Mã khôi phục") }, singleLine = true,
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
