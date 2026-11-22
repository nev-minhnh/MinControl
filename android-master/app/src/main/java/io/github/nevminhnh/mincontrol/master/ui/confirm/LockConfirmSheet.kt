package io.github.nevminhnh.mincontrol.master.ui.confirm

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Check
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.BottomSheetDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import io.github.nevminhnh.mincontrol.master.data.api.userMessage
import io.github.nevminhnh.mincontrol.master.security.BiometricCancelledException
import io.github.nevminhnh.mincontrol.master.ui.Fmt
import io.github.nevminhnh.mincontrol.master.ui.components.FilterChip
import io.github.nevminhnh.mincontrol.master.ui.components.IconCircle
import io.github.nevminhnh.mincontrol.master.ui.components.PrimaryButton
import io.github.nevminhnh.mincontrol.master.ui.theme.Danger
import io.github.nevminhnh.mincontrol.master.ui.theme.DangerContainer
import io.github.nevminhnh.mincontrol.master.ui.theme.DangerText
import io.github.nevminhnh.mincontrol.master.ui.theme.Handle
import io.github.nevminhnh.mincontrol.master.ui.theme.Primary
import io.github.nevminhnh.mincontrol.master.ui.theme.Success
import io.github.nevminhnh.mincontrol.master.ui.theme.SuccessContainer
import io.github.nevminhnh.mincontrol.master.ui.theme.SuccessDot
import io.github.nevminhnh.mincontrol.master.ui.theme.Surface
import io.github.nevminhnh.mincontrol.master.ui.theme.TextBody
import io.github.nevminhnh.mincontrol.master.ui.theme.TextPrimary
import io.github.nevminhnh.mincontrol.master.ui.theme.TextSecondary
import kotlinx.coroutines.launch
import java.time.Instant
import java.time.LocalTime
import java.time.ZoneId
import java.time.ZonedDateTime

enum class LockUntil(val label: String) {
    MANUAL("Đến khi tôi mở"), HOUR("1 giờ"), MORNING("Đến 7:00 sáng");

    fun until(now: ZonedDateTime = ZonedDateTime.now()): Instant? = when (this) {
        MANUAL -> null
        HOUR -> now.plusHours(1).toInstant()
        MORNING -> {
            val seven = now.with(LocalTime.of(7, 0)).withSecond(0).withNano(0)
            (if (seven.isAfter(now)) seven else seven.plusDays(1)).toInstant()
        }
    }

    fun describe(until: Instant?): String = when (this) {
        MANUAL -> "cho tới khi anh mở khóa"
        HOUR -> "đến ${until?.let(Fmt::time) ?: ""}"
        MORNING -> {
            val z = until?.atZone(ZoneId.systemDefault())
            if (z != null && z.toLocalDate() != ZonedDateTime.now().toLocalDate()) "đến 7:00 sáng mai" else "đến 7:00 sáng"
        }
    }
}

/** Outcome of a lock request shown in the success state. */
data class LockResult(val delivered: Boolean, val at: Instant, val until: Instant?, val option: LockUntil)

/**
 * "Xác nhận khóa" bottom sheet (Confirm.dc.html): lock-until chips, biometric confirm, success state with undo.
 * [targetName] = child label ("Bin") or "tất cả máy"; [hostLabel] = "PC-Bin".
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun LockConfirmSheet(
    targetName: String,
    hostLabel: String,
    graceSec: Int,
    onDismiss: () -> Unit,
    onLock: suspend (Instant?) -> Boolean,
    onUnlock: (suspend () -> Unit)?,
) {
    val sheet = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val scope = rememberCoroutineScope()
    var picked by remember { mutableStateOf(LockUntil.MORNING) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var result by remember { mutableStateOf<LockResult?>(null) }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheet,
        containerColor = Surface,
        shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp),
        dragHandle = { BottomSheetDefaults.DragHandle(color = Handle, width = 40.dp, height = 4.dp) },
    ) {
        val r = result
        if (r == null) {
            Column(
                Modifier.fillMaxWidth().padding(start = 24.dp, end = 24.dp, bottom = 32.dp).navigationBarsPadding(),
                verticalArrangement = Arrangement.spacedBy(24.dp),
            ) {
                Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    IconCircle(Icons.Outlined.Lock, DangerContainer, DangerText, size = 64.dp, iconSize = 28.dp)
                    Text("Khóa máy của $targetName?", style = MaterialTheme.typography.titleLarge, textAlign = TextAlign.Center)
                    Text(
                        "$targetName sẽ thấy thông báo và bị đăng xuất sau $graceSec giây. Không đăng nhập lại được cho tới khi hết hạn khóa.",
                        style = MaterialTheme.typography.bodyMedium, color = TextBody, textAlign = TextAlign.Center,
                    )
                }
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("Khóa đến", style = MaterialTheme.typography.titleSmall, color = TextBody)
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        LockUntil.entries.forEach { o -> FilterChip(o.label, picked == o, { picked = o }, height = 44.dp, large = true) }
                    }
                }
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (busy) {
                        Row(Modifier.fillMaxWidth().height(56.dp), horizontalArrangement = Arrangement.Center, verticalAlignment = Alignment.CenterVertically) {
                            CircularProgressIndicator(color = Danger, modifier = Modifier.size(28.dp))
                        }
                    } else {
                        PrimaryButton(
                            "Xác nhận bằng vân tay",
                            onClick = {
                                error = null
                                busy = true
                                scope.launch {
                                    val until = picked.until()
                                    try {
                                        val delivered = onLock(until)
                                        result = LockResult(delivered, Instant.now(), until, picked)
                                    } catch (e: BiometricCancelledException) {
                                        // user cancelled: stay on the sheet
                                    } catch (e: Exception) {
                                        error = e.userMessage()
                                    } finally {
                                        busy = false
                                    }
                                }
                            },
                            modifier = Modifier.fillMaxWidth().shadow(8.dp, RoundedCornerShape(16.dp), spotColor = Danger),
                            height = 56.dp, radius = 16.dp, color = Danger, icon = Icons.Outlined.Fingerprint,
                        )
                    }
                    error?.let { Text(it, color = DangerText, style = MaterialTheme.typography.bodySmall, modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Center) }
                    TextButton(onClick = onDismiss, modifier = Modifier.fillMaxWidth().height(48.dp)) {
                        Text("Hủy", style = MaterialTheme.typography.labelLarge, color = TextBody)
                    }
                }
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center, verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Outlined.Shield, null, tint = TextSecondary, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Lệnh được ký bằng khóa trong điện thoại này", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                }
            }
        } else {
            Column(
                Modifier.fillMaxWidth().padding(start = 24.dp, end = 24.dp, top = 24.dp, bottom = 32.dp).navigationBarsPadding(),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Box(Modifier.size(104.dp).background(SuccessDot.copy(alpha = 0.08f), CircleShape), contentAlignment = Alignment.Center) {
                    Box(Modifier.size(80.dp).background(SuccessContainer, CircleShape), contentAlignment = Alignment.Center) {
                        Icon(Icons.Outlined.Check, null, tint = Success, modifier = Modifier.size(36.dp))
                    }
                }
                Text("Đã khóa máy $hostLabel", style = MaterialTheme.typography.titleLarge, textAlign = TextAlign.Center)
                val received = if (r.delivered) "Máy nhận lệnh lúc ${Fmt.time(r.at)}." else "Máy đang offline, lệnh sẽ được thực hiện khi máy online lại."
                Text(
                    "$received $targetName sẽ được đăng xuất sau $graceSec giây và bị khóa ${r.option.describe(r.until)}.",
                    style = MaterialTheme.typography.bodyMedium, color = TextBody, textAlign = TextAlign.Center,
                )
                Column(Modifier.fillMaxWidth().padding(top = 8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    PrimaryButton("Về tổng quan", onClick = onDismiss, modifier = Modifier.fillMaxWidth(), height = 56.dp, radius = 16.dp, color = TextPrimary)
                    if (onUnlock != null) {
                        TextButton(
                            onClick = {
                                scope.launch {
                                    try { onUnlock(); result = null } catch (e: BiometricCancelledException) { } catch (e: Exception) { error = e.userMessage(); result = null }
                                }
                            },
                            modifier = Modifier.fillMaxWidth().height(48.dp),
                        ) { Text("Mở khóa ngay", style = MaterialTheme.typography.labelLarge, color = Primary) }
                    }
                }
            }
        }
    }
}
