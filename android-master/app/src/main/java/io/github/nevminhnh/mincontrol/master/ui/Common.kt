package io.github.nevminhnh.mincontrol.master.ui

import android.content.Context
import android.content.ContextWrapper
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ExpandMore
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import io.github.nevminhnh.mincontrol.master.data.Child
import io.github.nevminhnh.mincontrol.master.data.ChildKey
import io.github.nevminhnh.mincontrol.master.ui.components.FilterChip
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.itemsIndexed
import io.github.nevminhnh.mincontrol.master.ui.theme.TextPrimary

tailrec fun Context.findFragmentActivity(): FragmentActivity = when (this) {
    is FragmentActivity -> this
    is ContextWrapper -> baseContext.findFragmentActivity()
    else -> error("not hosted in a FragmentActivity")
}

@Composable
fun rememberActivity(): FragmentActivity {
    val ctx = LocalContext.current
    return remember(ctx) { ctx.findFragmentActivity() }
}

/** Picks the selected child, falling back to the first one. */
fun List<Child>.pick(key: ChildKey?): Child? = firstOrNull { it.key == key } ?: firstOrNull()

/** Chip labels: "label", or "label · hostname" when two children share a label. Pure (unit-tested). */
fun switcherLabels(children: List<Child>): List<String> =
    children.map { if (children.count { c -> c.label == it.label } > 1) "${it.label} · ${it.hostname}" else it.label }

/**
 * Child/device switcher: its own full-width, horizontally scrollable row of chips (never shares a Row with the
 * screen title, so the title cannot be squeezed). Hidden when there is only one child.
 */
@Composable
fun ChildSwitcher(children: List<Child>, selected: Child?, onSelect: (Child) -> Unit, modifier: Modifier = Modifier) {
    if (children.size <= 1) return
    val labels = switcherLabels(children)
    LazyRow(
        modifier.fillMaxWidth(),
        contentPadding = PaddingValues(horizontal = 16.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        itemsIndexed(children, key = { _, c -> "${c.deviceId}/${c.sid}" }) { i, c ->
            FilterChip(labels[i], c.key == selected?.key, { onSelect(c) })
        }
    }
}
