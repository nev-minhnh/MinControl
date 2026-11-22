package io.github.nevminhnh.mincontrol.master.ui.overview

import io.github.nevminhnh.mincontrol.master.data.protocol.UserState
import io.github.nevminhnh.mincontrol.master.ui.Fmt

/** What the Overview card's first quick action does, from DeviceState (B5). */
data class LockUi(val unlock: Boolean, val label: String, val untilText: String?) {
    companion object {
        fun of(st: UserState?): LockUi {
            val locked = st?.locked == true
            return LockUi(
                unlock = locked,
                label = if (locked) "Mở khóa" else "Khóa",
                untilText = if (locked) st?.lockedUntil?.takeIf { Fmt.parse(it) != null }?.let { "Khóa đến ${Fmt.time(it)}" } else null,
            )
        }
    }
}
