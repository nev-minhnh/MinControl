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
import io.github.nevminhnh.mincontrol.master.ui.components.SegmentedTabs
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

/**
 * Child switcher: a segmented control (Policy.dc.html header) for up to 3 children, otherwise a dropdown.
 */
@Composable
fun ChildSwitcher(children: List<Child>, selected: Child?, onSelect: (Child) -> Unit, modifier: Modifier = Modifier) {
    if (children.size <= 1) return
    val labels = children.map { if (children.count { c -> c.label == it.label } > 1) "${it.label} · ${it.hostname}" else it.label }
    if (children.size <= 3) {
        SegmentedTabs(labels, children.indexOf(selected).coerceAtLeast(0), { onSelect(children[it]) }, modifier, fill = false)
    } else {
        var open by remember { mutableStateOf(false) }
        Row(
            modifier,
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            androidx.compose.material3.TextButton(onClick = { open = true }) {
                Text(selected?.label ?: "", style = MaterialTheme.typography.titleSmall, color = TextPrimary)
                Icon(Icons.Outlined.ExpandMore, null, tint = TextPrimary, modifier = Modifier.size(18.dp))
            }
            DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
                children.forEachIndexed { i, c ->
                    DropdownMenuItem(text = { Text(labels[i]) }, onClick = { open = false; onSelect(c) })
                }
            }
        }
    }
}
