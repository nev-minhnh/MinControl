package io.github.nevminhnh.mincontrol.master.ui.transfer

import android.graphics.Bitmap
import android.graphics.Color as AColor
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.PhoneAndroid
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import io.github.nevminhnh.mincontrol.master.data.api.userMessage
import io.github.nevminhnh.mincontrol.master.data.protocol.CreateTransferResponse
import io.github.nevminhnh.mincontrol.master.data.protocol.TransferStatus
import io.github.nevminhnh.mincontrol.master.graph
import io.github.nevminhnh.mincontrol.master.security.BiometricCancelledException
import io.github.nevminhnh.mincontrol.master.transfer.TransferLink
import io.github.nevminhnh.mincontrol.master.transfer.TransferProtocol
import io.github.nevminhnh.mincontrol.master.ui.components.BackHeader
import io.github.nevminhnh.mincontrol.master.ui.components.IconCircle
import io.github.nevminhnh.mincontrol.master.ui.components.McCard
import io.github.nevminhnh.mincontrol.master.ui.components.PrimaryButton
import io.github.nevminhnh.mincontrol.master.ui.rememberActivity
import io.github.nevminhnh.mincontrol.master.ui.theme.Background
import io.github.nevminhnh.mincontrol.master.ui.theme.DangerText
import io.github.nevminhnh.mincontrol.master.ui.theme.Mono
import io.github.nevminhnh.mincontrol.master.ui.theme.Primary
import io.github.nevminhnh.mincontrol.master.ui.theme.PrimaryContainer
import io.github.nevminhnh.mincontrol.master.ui.theme.TextSecondary
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

private sealed interface Step {
    data object Intro : Step
    data class Qr(val created: CreateTransferResponse, val link: String) : Step
    data class Claimed(val transferId: String, val status: TransferStatus, val fp: String) : Step
    data class Working(val text: String) : Step
    data object Done : Step
}

/** Old phone side of API.md 13: QR made on this phone -> new phone claims -> fingerprint check -> sign + complete -> wipe. */
@Composable
fun TransferScreen(onBack: () -> Unit) {
    val graph = LocalContext.current.graph
    val activity = rememberActivity()
    val scope = rememberCoroutineScope()
    var step by remember { mutableStateOf<Step>(Step.Intro) }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    fun finishAndLeave() {
        graph.settings.setRegistered(false)
    }

    BackHandler(enabled = step is Step.Working || step == Step.Done) { if (step == Step.Done) finishAndLeave() }

    fun create() {
        error = null; busy = true
        scope.launch {
            try {
                val created = graph.transfers.start(activity)
                val url = graph.settings.serverUrl ?: error("no server")
                step = Step.Qr(created, TransferLink.build(url, created.token))
            } catch (e: BiometricCancelledException) {
                // stay on intro
            } catch (e: Exception) {
                error = e.userMessage()
            } finally {
                busy = false
            }
        }
    }

    fun confirm(c: Step.Claimed) {
        error = null
        scope.launch {
            try {
                graph.transfers.complete(activity, c.transferId, c.status) { step = Step.Working(it) }
                step = Step.Done
            } catch (e: BiometricCancelledException) {
                step = c; error = "Đã hủy xác nhận. Bấm lại để chuyển."
            } catch (e: Exception) {
                step = c; error = e.userMessage()
            }
        }
    }

    Box(Modifier.fillMaxSize().background(if (step is Step.Qr) Color.White else Background)) {
        Column(Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding()) {
            if (step !is Step.Working && step != Step.Done) {
                BackHeader("Chuyển sang điện thoại mới", onBack, Modifier.padding(start = 8.dp, end = 16.dp, top = 16.dp, bottom = 8.dp))
            }
            Column(
                Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(horizontal = 16.dp, vertical = 16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                when (val s = step) {
                    Step.Intro -> {
                        IconCircle(Icons.Outlined.PhoneAndroid, PrimaryContainer, Primary, size = 56.dp, iconSize = 28.dp)
                        Text("Chuyển quyền quản lý sang điện thoại mới", style = MaterialTheme.typography.titleLarge, textAlign = TextAlign.Center)
                        Text(
                            "1. Cài MinControl trên điện thoại mới và mở \"Quét mã trên máy tính\".\n" +
                                "2. Bấm nút dưới đây, xác nhận vân tay, điện thoại này sẽ hiện mã QR (10 phút).\n" +
                                "3. So mã khóa trên hai điện thoại rồi xác nhận.\n\n" +
                                "Các máy tính KHÔNG cần ghép nối lại. Sau khi chuyển, điện thoại này không còn quyền quản lý.",
                            style = MaterialTheme.typography.bodyMedium, color = TextSecondary,
                        )
                        error?.let { Text(it, color = DangerText, style = MaterialTheme.typography.bodySmall) }
                        if (busy) CircularProgressIndicator(color = Primary)
                        else PrimaryButton("Tạo mã chuyển máy", onClick = { create() }, modifier = Modifier.fillMaxWidth(), height = 56.dp, radius = 16.dp, icon = Icons.Outlined.Shield)
                    }
                    is Step.Qr -> QrStep(s, onClaimed = { st ->
                        val fp = runCatching { TransferProtocol.claimedFingerprint(st.newKeys, st.fp) }
                        fp.onSuccess { step = Step.Claimed(s.created.transferId, st, it) }
                            .onFailure { error = "Mã khóa của điện thoại mới không hợp lệ. Hãy tạo mã mới."; step = Step.Intro }
                    }, onExpired = { error = "Mã đã hết hạn. Tạo mã mới."; step = Step.Intro }, onError = { error = it })
                    is Step.Claimed -> {
                        IconCircle(Icons.Outlined.Shield, PrimaryContainer, Primary, size = 56.dp, iconSize = 28.dp)
                        Text("Điện thoại mới đã quét mã", style = MaterialTheme.typography.titleLarge)
                        McCard(spacing = 8.dp) {
                            Text("Mã của điện thoại mới", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                            Text(s.fp, fontFamily = Mono, fontSize = 24.sp, fontWeight = FontWeight.SemiBold, letterSpacing = 2.sp)
                        }
                        Text("Khớp với điện thoại mới?", style = MaterialTheme.typography.titleMedium)
                        Text("Chỉ xác nhận khi mã này giống hệt mã đang hiện trên điện thoại mới. Bạn sẽ cần xác nhận vân tay cho từng máy tính.",
                            style = MaterialTheme.typography.bodySmall, color = TextSecondary, textAlign = TextAlign.Center)
                        error?.let { Text(it, color = DangerText, style = MaterialTheme.typography.bodySmall) }
                        PrimaryButton("Khớp, chuyển quyền", onClick = { confirm(s) }, modifier = Modifier.fillMaxWidth(), height = 56.dp, radius = 16.dp, icon = Icons.Outlined.Shield)
                        TextButton(onClick = { error = null; step = Step.Intro }, modifier = Modifier.fillMaxWidth()) { Text("Không khớp, hủy", color = DangerText) }
                    }
                    is Step.Working -> {
                        CircularProgressIndicator(color = Primary)
                        Text(s.text, style = MaterialTheme.typography.bodyMedium, textAlign = TextAlign.Center)
                    }
                    Step.Done -> {
                        IconCircle(Icons.Outlined.Shield, PrimaryContainer, Primary, size = 56.dp, iconSize = 28.dp)
                        Text("Đã chuyển. Điện thoại này không còn quyền quản lý.", style = MaterialTheme.typography.titleLarge, textAlign = TextAlign.Center)
                        PrimaryButton("Xong", onClick = { finishAndLeave() }, modifier = Modifier.fillMaxWidth(), height = 56.dp, radius = 16.dp)
                    }
                }
            }
        }
    }
}

@Composable
private fun QrStep(s: Step.Qr, onClaimed: (TransferStatus) -> Unit, onExpired: () -> Unit, onError: (String) -> Unit) {
    val graph = LocalContext.current.graph
    val bitmap = remember(s.link) { qrBitmap(s.link) }
    var left by remember { mutableLongStateOf(TransferProtocol.secondsLeft(s.created.expiresAt) ?: 600L) }
    var pollError by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(s) {
        val deadline = System.currentTimeMillis() + left * 1000
        launch {
            while (true) {
                left = maxOf(0L, (deadline - System.currentTimeMillis()) / 1000)
                if (left == 0L) { onExpired(); return@launch }
                delay(1000)
            }
        }
        while (true) {
            delay(2000)
            try {
                val st = graph.transfers.status(s.created.transferId)
                pollError = null
                when (st.status) {
                    "claimed" -> { onClaimed(st); return@LaunchedEffect }
                    "expired", "cancelled", "failed" -> { onExpired(); return@LaunchedEffect }
                }
            } catch (e: Exception) {
                pollError = e.userMessage()
            }
        }
    }

    Text("Quét mã này bằng điện thoại mới", style = MaterialTheme.typography.titleLarge, color = Color.Black, textAlign = TextAlign.Center)
    Image(bitmap, contentDescription = "Mã QR chuyển máy", filterQuality = FilterQuality.None,
        modifier = Modifier.fillMaxWidth().aspectRatio(1f))
    Text("Còn ${TransferProtocol.countdown(left)}", fontFamily = Mono, fontSize = 22.sp, color = Color.Black)
    Text("Trên điện thoại mới: mở MinControl → \"Quét mã trên máy tính\". Đang chờ điện thoại mới…",
        style = MaterialTheme.typography.bodySmall, color = Color.DarkGray, textAlign = TextAlign.Center)
    pollError?.let { Text(it, color = DangerText, style = MaterialTheme.typography.bodySmall) }
}

/** Black-on-white QR (ECC M, quiet zone 2 modules), one pixel per module; scaled up without filtering. */
private fun qrBitmap(text: String): ImageBitmap {
    val m = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0,
        mapOf(EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M, EncodeHintType.MARGIN to 2))
    val px = IntArray(m.width * m.height) { i -> if (m.get(i % m.width, i / m.width)) AColor.BLACK else AColor.WHITE }
    return Bitmap.createBitmap(px, m.width, m.height, Bitmap.Config.ARGB_8888).asImageBitmap()
}
