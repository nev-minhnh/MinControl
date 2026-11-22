package io.github.nevminhnh.mincontrol.master.ui.confirm

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material.icons.outlined.LockOpen
import androidx.compose.material3.BottomSheetDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
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
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import io.github.nevminhnh.mincontrol.master.data.api.userMessage
import io.github.nevminhnh.mincontrol.master.security.BiometricCancelledException
import io.github.nevminhnh.mincontrol.master.ui.components.IconCircle
import io.github.nevminhnh.mincontrol.master.ui.components.PrimaryButton
import io.github.nevminhnh.mincontrol.master.ui.theme.DangerText
import io.github.nevminhnh.mincontrol.master.ui.theme.Handle
import io.github.nevminhnh.mincontrol.master.ui.theme.Primary
import io.github.nevminhnh.mincontrol.master.ui.theme.PrimaryContainer
import io.github.nevminhnh.mincontrol.master.ui.theme.Surface
import io.github.nevminhnh.mincontrol.master.ui.theme.TextBody
import kotlinx.coroutines.launch

/** "Mở khóa máy của X?" confirmation before the biometric prompt (mirrors LockConfirmSheet). */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun UnlockConfirmSheet(targetName: String, onDismiss: () -> Unit, onConfirm: suspend () -> Unit) {
    val sheet = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    ModalBottomSheet(
        onDismissRequest = onDismiss, sheetState = sheet, containerColor = Surface,
        shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp),
        dragHandle = { BottomSheetDefaults.DragHandle(color = Handle, width = 40.dp, height = 4.dp) },
    ) {
        Column(
            Modifier.fillMaxWidth().padding(start = 24.dp, end = 24.dp, bottom = 32.dp).navigationBarsPadding(),
            verticalArrangement = Arrangement.spacedBy(24.dp),
        ) {
            Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(12.dp)) {
                IconCircle(Icons.Outlined.LockOpen, PrimaryContainer, Primary, size = 64.dp, iconSize = 28.dp)
                Text("Mở khóa máy của $targetName?", style = MaterialTheme.typography.titleLarge, textAlign = TextAlign.Center)
                Text(
                    "$targetName sẽ đăng nhập lại và dùng máy được ngay.",
                    style = MaterialTheme.typography.bodyMedium, color = TextBody, textAlign = TextAlign.Center,
                )
            }
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (busy) {
                    Row(Modifier.fillMaxWidth().height(56.dp), horizontalArrangement = Arrangement.Center, verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(color = Primary, modifier = Modifier.size(28.dp))
                    }
                } else {
                    PrimaryButton(
                        "Xác nhận bằng vân tay",
                        onClick = {
                            error = null; busy = true
                            scope.launch {
                                try { onConfirm(); onDismiss() }
                                catch (e: BiometricCancelledException) { /* stay on the sheet */ }
                                catch (e: Exception) { error = e.userMessage() }
                                finally { busy = false }
                            }
                        },
                        modifier = Modifier.fillMaxWidth(), height = 56.dp, radius = 16.dp, icon = Icons.Outlined.Fingerprint,
                    )
                }
                error?.let { Text(it, color = DangerText, style = MaterialTheme.typography.bodySmall, modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Center) }
                TextButton(onClick = onDismiss, modifier = Modifier.fillMaxWidth().height(48.dp)) {
                    Text("Hủy", style = MaterialTheme.typography.labelLarge, color = TextBody)
                }
            }
        }
    }
}
