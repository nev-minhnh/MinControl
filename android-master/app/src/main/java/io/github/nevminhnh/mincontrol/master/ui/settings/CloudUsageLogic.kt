package io.github.nevminhnh.mincontrol.master.ui.settings

import io.github.nevminhnh.mincontrol.master.data.protocol.CloudUsage

/** Presentation of the Cloudflare free-tier meter (API.md 16). */
object CloudUsageLogic {
    const val RESET_NOTE = "Đặt lại lúc 7:00 sáng (giờ Việt Nam)"

    fun fraction(u: CloudUsage): Float =
        if (u.limit <= 0) 0f else (u.rowsWritten.toFloat() / u.limit).coerceIn(0f, 1f)

    fun label(u: CloudUsage): String = "${group(u.rowsWritten)} / ${group(u.limit)} dòng ghi"

    /** "100 000" with a plain space as thousands separator. */
    fun group(n: Long): String = n.toString().reversed().chunked(3).joinToString(" ").reversed()

    /** 0 = normal, 1 = >=70 %, 2 = >=90 %. */
    fun level(u: CloudUsage): Int = when {
        u.percent >= 90 || fraction(u) >= 0.9f -> 2
        u.percent >= 70 || fraction(u) >= 0.7f -> 1
        else -> 0
    }
}
