package io.github.nevminhnh.mincontrol.master.ui.pairing

import android.app.Application
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.AccessTime
import androidx.compose.material.icons.outlined.QrCodeScanner
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import io.github.nevminhnh.mincontrol.master.data.api.userMessage
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import io.github.nevminhnh.mincontrol.master.data.protocol.ClaimInfo
import io.github.nevminhnh.mincontrol.master.data.protocol.DeviceInfo
import io.github.nevminhnh.mincontrol.master.data.protocol.DeviceUser
import io.github.nevminhnh.mincontrol.master.ui.theme.DangerText
import io.github.nevminhnh.mincontrol.master.data.protocol.PairingCode
import io.github.nevminhnh.mincontrol.master.graph
import io.github.nevminhnh.mincontrol.master.policy.PolicyDefaults
import io.github.nevminhnh.mincontrol.master.security.BiometricCancelledException
import io.github.nevminhnh.mincontrol.master.security.KeyRole
import io.github.nevminhnh.mincontrol.master.security.SigFormat
import io.github.nevminhnh.mincontrol.master.ui.Fmt
import io.github.nevminhnh.mincontrol.master.ui.components.BackHeader
import io.github.nevminhnh.mincontrol.master.ui.components.IconCircle
import io.github.nevminhnh.mincontrol.master.ui.components.McCard
import io.github.nevminhnh.mincontrol.master.ui.components.PrimaryButton
import io.github.nevminhnh.mincontrol.master.ui.components.SecondaryButton
import io.github.nevminhnh.mincontrol.master.ui.rememberActivity
import io.github.nevminhnh.mincontrol.master.ui.theme.Background
import io.github.nevminhnh.mincontrol.master.ui.theme.CodeBg
import io.github.nevminhnh.mincontrol.master.ui.theme.Mono
import io.github.nevminhnh.mincontrol.master.ui.theme.Primary
import io.github.nevminhnh.mincontrol.master.ui.theme.PrimaryContainer
import io.github.nevminhnh.mincontrol.master.ui.theme.Success
import io.github.nevminhnh.mincontrol.master.ui.theme.SuccessContainer
import io.github.nevminhnh.mincontrol.master.ui.theme.TextBody
import io.github.nevminhnh.mincontrol.master.ui.theme.TextPrimary
import io.github.nevminhnh.mincontrol.master.ui.theme.TextSecondary
import io.github.nevminhnh.mincontrol.master.ui.theme.WarningBg
import io.github.nevminhnh.mincontrol.master.ui.theme.WarningIcon
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.time.Duration
import java.time.Instant

/** Screen stages of the "Thêm máy tính" flow. */
sealed interface PairStage {
    data object Home : PairStage
    data object Loading : PairStage
    /** [expectedFp] is the QR `f` (null for manual code entry, where the parent compares by eye). */
    data class Confirm(val claimId: String, val claim: ClaimInfo, val expectedFp: String?) : PairStage
    /** QR fingerprint differs from the server's claim: hard error, no approve button. */
    data class Mismatch(val hostname: String) : PairStage
    data object Legacy : PairStage
}

class PairingViewModel(app: Application) : AndroidViewModel(app) {
    private val graph = app.graph
    val stage = MutableStateFlow<PairStage>(PairStage.Home)
    val code = MutableStateFlow<PairingCode?>(null)
    val newDevice = MutableStateFlow<DeviceInfo?>(null)
    val deviceFp = MutableStateFlow<String?>(null)
    val message = MutableStateFlow<String?>(null)
    val applying = MutableStateFlow(false)
    val approving = MutableStateFlow(false)
    val done = MutableStateFlow(false)
    val fingerprint: String = runCatching { SigFormat.fingerprint(graph.keys.publicKey(KeyRole.SIGN).keyId) }.getOrDefault("—")
    private var known: Set<String>? = null
    private var poll: Job? = null

    init {
        PairLink.pending.value?.let { PairLink.pending.value = null; openLink(it) }
    }

    fun openLink(p: PairPayload) {
        stage.value = PairStage.Loading
        viewModelScope.launch {
            try {
                val c = graph.repo.claim(p.claimId)
                stage.value = if (Fingerprint.matches(c.fp, p.fp)) PairStage.Confirm(p.claimId, c, p.fp)
                else PairStage.Mismatch(c.hostname)
            } catch (e: Exception) {
                message.value = e.userMessage(); stage.value = PairStage.Home
            }
        }
    }

    fun lookupCode(raw: String) {
        val code8 = ClaimCode.normalize(raw)
        if (code8 == null) { message.value = "Mã gồm 8 ký tự (chữ và số)."; return }
        stage.value = PairStage.Loading
        viewModelScope.launch {
            try {
                val c = graph.repo.claimByCode(code8)
                val id = c.claimId
                if (id.isNullOrBlank()) { message.value = "Không tìm thấy mã này."; stage.value = PairStage.Home }
                else stage.value = PairStage.Confirm(id, c, null)
            } catch (e: Exception) {
                message.value = e.userMessage(); stage.value = PairStage.Home
            }
        }
    }

    /** Approves the claim (biometric `sign` key), then moves on to choosing managed users. */
    fun approve(activity: FragmentActivity, s: PairStage.Confirm) {
        if (approving.value) return
        approving.value = true
        viewModelScope.launch {
            try {
                val deviceId = graph.repo.approveClaim(activity, s.claimId, s.claim.hostname)
                val fromList = runCatching { graph.repo.refreshDevices() }.getOrNull()?.firstOrNull { it.deviceId == deviceId }
                deviceFp.value = Fingerprint.format(s.claim.fp)
                newDevice.value = fromList ?: DeviceInfo(
                    deviceId = deviceId, hostname = s.claim.hostname,
                    users = s.claim.localUsers.map { DeviceUser(sid = it.sid, name = it.name, isAdmin = it.isAdmin) },
                )
            } catch (e: BiometricCancelledException) {
            } catch (e: Exception) {
                message.value = e.userMessage()
            } finally {
                approving.value = false
            }
        }
    }

    fun reject(s: PairStage.Confirm) {
        viewModelScope.launch { runCatching { graph.repo.rejectClaim(s.claimId) } }
        message.value = "Đã từ chối máy này"
        stage.value = PairStage.Home
    }

    fun backHome() { stage.value = PairStage.Home }

    fun startLegacy() { stage.value = PairStage.Legacy; newCode() }

    fun newCode() = viewModelScope.launch {
        try {
            if (known == null) known = graph.repo.refreshDevices().map { it.deviceId }.toSet()
            code.value = graph.repo.createPairingCode()
            startPolling()
        } catch (e: Exception) {
            message.value = e.userMessage()
        }
    }

    private fun startPolling() {
        if (poll?.isActive == true) return
        poll = viewModelScope.launch {
            while (isActive && newDevice.value == null) {
                delay(3_000)
                val list = runCatching { graph.repo.refreshDevices() }.getOrNull() ?: continue
                val before = known ?: emptySet()
                list.firstOrNull { it.deviceId !in before }?.let { newDevice.value = it }
            }
        }
    }

    /** Builds policy v1 for the chosen users, signs it (biometric) and uploads it. */
    fun apply(activity: FragmentActivity, chosen: Map<String, String>) = viewModelScope.launch {
        val dev = newDevice.value ?: return@launch
        if (chosen.isEmpty()) { message.value = "Hãy chọn ít nhất một tài khoản."; return@launch }
        applying.value = true
        try {
            val policy = PolicyDefaults.policy(chosen, version = 1)
            graph.repo.applyPolicy(activity, dev.deviceId, policy, "Áp dụng quy tắc cho ${dev.hostname}")
            graph.repo.refreshDevices()
            done.value = true
        } catch (e: BiometricCancelledException) {
        } catch (e: Exception) {
            message.value = e.userMessage()
        } finally {
            applying.value = false
        }
    }
}

private fun displayCode(code: String) = code.replace("-", "").let { if (it.length == 8) it.substring(0, 4) + "-" + it.substring(4) else it }

@Composable
fun PairingScreen(onBack: () -> Unit, vm: PairingViewModel = viewModel()) {
    val ctx = LocalContext.current
    val activity = rememberActivity()
    val stage by vm.stage.collectAsState()
    val code by vm.code.collectAsState()
    val device by vm.newDevice.collectAsState()
    val deviceFp by vm.deviceFp.collectAsState()
    val applying by vm.applying.collectAsState()
    val approving by vm.approving.collectAsState()
    val done by vm.done.collectAsState()
    val message by vm.message.collectAsState()
    val snackbar = remember { SnackbarHostState() }
    var now by remember { mutableStateOf(Instant.now()) }
    LaunchedEffect(Unit) { while (true) { now = Instant.now(); delay(1_000) } }
    LaunchedEffect(message) { message?.let { snackbar.showSnackbar(it); vm.message.value = null } }
    LaunchedEffect(done) { if (done) onBack() }
    // A deep link that arrives while this screen is already open.
    val pendingLink by PairLink.pending.collectAsState()
    LaunchedEffect(pendingLink) { pendingLink?.let { PairLink.pending.value = null; vm.openLink(it) } }

    fun scan() {
        val opts = GmsBarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build()
        GmsBarcodeScanning.getClient(ctx, opts).startScan()
            .addOnSuccessListener { c ->
                val p = PairLink.parse(c.rawValue)
                if (p != null) vm.openLink(p) else vm.message.value = "Mã QR không phải mã ghép nối MinControl."
            }
            .addOnFailureListener { e ->
                if (e !is com.google.android.gms.common.api.ApiException || e.statusCode != 16) {
                    vm.message.value = "Không mở được trình quét QR. Hãy dùng \"Nhập mã\"."
                }
            }
    }

    Box(Modifier.fillMaxSize().background(Background)) {
        Column(Modifier.fillMaxSize().statusBarsPadding()) {
            BackHeader("Thêm máy tính", { if (stage is PairStage.Home || device != null) onBack() else vm.backHome() },
                Modifier.padding(start = 8.dp, end = 16.dp, top = 16.dp, bottom = 8.dp))
            Column(
                Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 24.dp),
                verticalArrangement = Arrangement.spacedBy(24.dp),
            ) {
                val dev = device
                val st = stage
                if (dev != null) {
                    ChooseUsers(dev, applying, deviceFp?.let { "Mã khóa máy: $it" } ?: "Mã khóa phải là ${vm.fingerprint}") { vm.apply(activity, it) }
                } else when (st) {
                    PairStage.Home -> HomeStage(onScan = { scan() }, onCode = { vm.lookupCode(it) }, onLegacy = { vm.startLegacy() })
                    PairStage.Loading -> Box(Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) { CircularProgressIndicator(color = Primary) }
                    is PairStage.Confirm -> ConfirmStage(st, approving, onApprove = { vm.approve(activity, st) }, onReject = { vm.reject(st) })
                    is PairStage.Mismatch -> MismatchStage(st.hostname, onBack = { vm.backHome() })
                    PairStage.Legacy -> {
                        CodeCard(code, now, onNew = { vm.newCode() }, onCopy = {
                            code?.let {
                                (ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager)
                                    .setPrimaryClip(ClipData.newPlainText("MinControl", displayCode(it.code)))
                                vm.message.value = "Đã sao chép mã."
                            }
                        })
                        Steps(code?.let { displayCode(it.code) } ?: "XXXX-XXXX")
                        FingerprintCard(vm.fingerprint)
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center, verticalAlignment = Alignment.CenterVertically) {
                            Box(Modifier.size(16.dp).clip(CircleShape).background(Primary.copy(alpha = 0.15f)), contentAlignment = Alignment.Center) {
                                Box(Modifier.size(8.dp).clip(CircleShape).background(Primary))
                            }
                            Spacer(Modifier.size(8.dp))
                            Text("Đang chờ máy tính kết nối…", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                        }
                    }
                }
            }
        }
        SnackbarHost(snackbar, Modifier.align(Alignment.BottomCenter).padding(16.dp))
    }
}

@Composable
private fun HomeStage(onScan: () -> Unit, onCode: (String) -> Unit, onLegacy: () -> Unit) {
    var manual by remember { mutableStateOf(false) }
    var codeText by remember { mutableStateOf("") }
    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
        McCard(elevated = true, spacing = 12.dp) {
            Text("Trên máy tính của con", style = MaterialTheme.typography.titleMedium)
            Text(
                "Chạy trình cài MinControl: máy sẽ hiện một mã QR. Quét mã đó bằng điện thoại này, kiểm tra tên máy rồi cho phép. Không cần gõ gì cả.",
                style = MaterialTheme.typography.bodyMedium, color = TextBody,
            )
        }
        PrimaryButton("Quét mã trên máy tính", onScan, Modifier.fillMaxWidth(), height = 56.dp, radius = 16.dp, icon = Icons.Outlined.QrCodeScanner)
        if (!manual) {
            SecondaryButton("Nhập mã", { manual = true }, Modifier.fillMaxWidth())
        } else {
            McCard(radius = 20.dp, spacing = 12.dp) {
                Text("Nhập mã 8 ký tự hiện nhỏ dưới mã QR trên máy tính.", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                OutlinedTextField(
                    value = codeText, onValueChange = { codeText = it.take(9).uppercase() }, singleLine = true,
                    label = { Text("Mã trên máy tính") },
                    textStyle = androidx.compose.ui.text.TextStyle(fontFamily = Mono, fontSize = 20.sp, letterSpacing = 2.sp),
                    modifier = Modifier.fillMaxWidth(),
                )
                PrimaryButton("Tìm máy", { onCode(codeText) }, Modifier.fillMaxWidth(), enabled = ClaimCode.normalize(codeText) != null)
            }
        }
        androidx.compose.material3.TextButton(onClick = onLegacy, modifier = Modifier.fillMaxWidth()) {
            Text("Cách cũ (dòng lệnh)", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
        }
    }
}

@Composable
private fun ConfirmStage(s: PairStage.Confirm, approving: Boolean, onApprove: () -> Unit, onReject: () -> Unit) {
    val fp = Fingerprint.format(s.claim.fp) ?: s.claim.fp
    McCard(elevated = true, spacing = 12.dp) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            IconCircle(Icons.Outlined.Shield, PrimaryContainer, Primary)
            Column {
                Text(s.claim.hostname.ifBlank { "Máy tính mới" }, style = MaterialTheme.typography.titleMedium)
                if (s.claim.osVersion.isNotBlank()) Text(osDisplay(s.claim.osVersion), style = MaterialTheme.typography.bodySmall, color = TextSecondary)
            }
        }
        Text("Tài khoản trên máy", style = MaterialTheme.typography.labelLarge, color = TextSecondary)
        if (s.claim.localUsers.isEmpty()) Text("Máy chưa báo danh sách tài khoản.", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
        s.claim.localUsers.forEach { u ->
            Text(u.name + if (u.isAdmin) " (admin)" else "", style = MaterialTheme.typography.bodyMedium, color = TextPrimary)
        }
    }
    McCard(radius = 20.dp, padding = androidx.compose.foundation.layout.PaddingValues(16.dp)) {
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("Mã khóa của máy tính", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
            Text(fp, fontFamily = Mono, fontSize = 22.sp, fontWeight = FontWeight.SemiBold, letterSpacing = 2.sp)
            Text(
                if (s.expectedFp != null) "Đã khớp với mã QR. Hãy chắc chắn mã này cũng hiện trên màn hình máy tính."
                else "Hãy so sánh với mã đang hiện trên màn hình máy tính. Chỉ cho phép khi hai mã giống hệt nhau.",
                style = MaterialTheme.typography.bodySmall, color = TextSecondary,
            )
        }
    }
    if (approving) {
        Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) { CircularProgressIndicator(color = Primary) }
    } else {
        PrimaryButton("Cho phép máy này", onApprove, Modifier.fillMaxWidth(), height = 56.dp, radius = 16.dp, icon = Icons.Outlined.Shield)
        SecondaryButton("Từ chối", onReject, Modifier.fillMaxWidth())
    }
}

@Composable
private fun MismatchStage(hostname: String, onBack: () -> Unit) {
    McCard(elevated = true, spacing = 12.dp) {
        Text("Mã khóa không khớp", style = MaterialTheme.typography.titleMedium, color = DangerText)
        Text(
            "Mã khóa trên máy chủ cho ${hostname.ifBlank { "máy này" }} khác với mã trong QR. Có thể QR đã bị thay thế. " +
                "Không cho phép máy này; hãy tạo lại mã QR trên máy tính rồi quét lại.",
            style = MaterialTheme.typography.bodyMedium, color = TextBody,
        )
    }
    SecondaryButton("Quay lại", onBack, Modifier.fillMaxWidth())
}

@Composable
private fun CodeCard(code: PairingCode?, now: Instant, onNew: () -> Unit, onCopy: () -> Unit) {
    McCard(elevated = true, padding = androidx.compose.foundation.layout.PaddingValues(24.dp), spacing = 16.dp) {
        Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Text("Mã ghép nối · dùng một lần", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
            if (code == null) {
                CircularProgressIndicator(color = Primary)
            } else {
                Text(displayCode(code.code), fontFamily = Mono, fontSize = 32.sp, fontWeight = FontWeight.SemiBold, letterSpacing = 4.sp)
                val left = Fmt.parse(code.expiresAt)?.let { Duration.between(now, it).seconds } ?: 0
                Row(
                    Modifier.clip(RoundedCornerShape(12.dp)).background(WarningBg).padding(horizontal = 12.dp, vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Icon(Icons.Outlined.AccessTime, null, tint = WarningIcon, modifier = Modifier.size(16.dp))
                    Text(
                        if (left > 0) "Hết hạn sau %d:%02d".format(left / 60, left % 60) else "Mã đã hết hạn",
                        style = MaterialTheme.typography.bodySmall.copy(fontFeatureSettings = "tnum"), color = WarningIcon,
                    )
                }
            }
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                SecondaryButton("Tạo mã mới", onNew, Modifier.weight(1f))
                PrimaryButton("Sao chép mã", onCopy, Modifier.weight(1f), enabled = code != null)
            }
        }
    }
}

@Composable
private fun Steps(code: String) {
    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text("Trên máy tính của con", style = MaterialTheme.typography.titleMedium)
        Step(1) {
            Text(buildAnnotatedString {
                append("Đăng nhập bằng tài khoản ")
                withStyle(SpanStyle(color = TextPrimary, fontWeight = FontWeight.SemiBold)) { append("admin") }
                append(" và chạy trình cài MinControl.")
            }, style = MaterialTheme.typography.bodyMedium, color = TextBody)
        }
        Step(2) {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text("Mở PowerShell (Admin) và chạy", style = MaterialTheme.typography.bodyMedium, color = TextBody)
                Text(
                    "MinControl.Setup enroll $code", fontFamily = Mono, fontSize = 13.sp,
                    modifier = Modifier.clip(RoundedCornerShape(6.dp)).background(CodeBg).padding(horizontal = 6.dp, vertical = 2.dp),
                )
            }
        }
        Step(3) {
            Text("Kiểm tra mã khóa hiện trên máy trùng với mã bên dưới, rồi chọn tài khoản cần quản lý.",
                style = MaterialTheme.typography.bodyMedium, color = TextBody)
        }
    }
}

@Composable
private fun Step(n: Int, content: @Composable () -> Unit) {
    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Box(Modifier.size(28.dp).clip(CircleShape).background(PrimaryContainer), contentAlignment = Alignment.Center) {
            Text("$n", style = MaterialTheme.typography.titleSmall, color = Primary)
        }
        Box(Modifier.weight(1f)) { content() }
    }
}

@Composable
private fun FingerprintCard(fp: String) {
    McCard(radius = 20.dp, padding = androidx.compose.foundation.layout.PaddingValues(16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            IconCircle(Icons.Outlined.Shield, SuccessContainer, Success)
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text("Mã khóa điều khiển của điện thoại này", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                Text(fp, fontFamily = Mono, fontSize = 15.sp, fontWeight = FontWeight.SemiBold, letterSpacing = 1.sp)
            }
        }
    }
}

@Composable
private fun ChooseUsers(dev: DeviceInfo, applying: Boolean, fingerprintNote: String, onApply: (Map<String, String>) -> Unit) {
    val checked = remember(dev.deviceId) { mutableStateMapOf<String, Boolean>().apply { dev.users.forEach { put(it.sid, !it.isAdmin) } } }
    val labels = remember(dev.deviceId) { mutableStateMapOf<String, String>().apply { dev.users.forEach { put(it.sid, it.label ?: it.name) } } }
    McCard(elevated = true, spacing = 8.dp) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            IconCircle(Icons.Outlined.Shield, SuccessContainer, Success)
            Column {
                Text("${dev.hostname} đã kết nối", style = MaterialTheme.typography.titleMedium)
                Text(fingerprintNote, style = MaterialTheme.typography.bodySmall, color = TextSecondary)
            }
        }
    }
    Text("Chọn tài khoản cần quản lý", style = MaterialTheme.typography.titleMedium)
    McCard(radius = 20.dp, padding = androidx.compose.foundation.layout.PaddingValues(horizontal = 16.dp, vertical = 8.dp), spacing = 8.dp) {
        dev.users.forEach { u ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(
                    checked = checked[u.sid] == true && !u.isAdmin, enabled = !u.isAdmin,
                    onCheckedChange = { checked[u.sid] = it },
                    colors = CheckboxDefaults.colors(checkedColor = Primary),
                )
                Column(Modifier.weight(1f)) {
                    Text(u.name, style = MaterialTheme.typography.bodyMedium, color = if (u.isAdmin) TextSecondary else TextPrimary)
                    if (u.isAdmin) Text("Tài khoản admin — không thể quản lý", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                }
            }
            if (!u.isAdmin && checked[u.sid] == true) {
                OutlinedTextField(
                    value = labels[u.sid] ?: "", onValueChange = { labels[u.sid] = it.take(40) },
                    label = { Text("Tên hiển thị") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth().padding(start = 48.dp, bottom = 8.dp),
                )
            }
        }
        if (dev.users.isEmpty()) Text("Máy chưa báo danh sách tài khoản.", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
    }
    Text("Quy tắc mặc định: 2 giờ ngày thường, 3 giờ cuối tuần, game 1 giờ, chặn web người lớn/cờ bạc/VPN. Có thể sửa ở tab Quy tắc.",
        style = MaterialTheme.typography.bodySmall, color = TextSecondary)
    if (applying) {
        CircularProgressIndicator(color = Primary, modifier = Modifier.height(48.dp))
    } else {
        PrimaryButton(
            "Ký & áp dụng bằng vân tay",
            onClick = {
                onApply(dev.users.filter { !it.isAdmin && checked[it.sid] == true }.associate { it.sid to (labels[it.sid]?.ifBlank { null } ?: it.name) })
            },
            modifier = Modifier.fillMaxWidth(), height = 56.dp, radius = 16.dp,
            icon = Icons.Outlined.Shield,
        )
    }
}
