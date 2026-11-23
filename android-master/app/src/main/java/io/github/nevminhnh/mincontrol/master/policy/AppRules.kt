package io.github.nevminhnh.mincontrol.master.policy

import io.github.nevminhnh.mincontrol.master.data.protocol.AppMatch
import io.github.nevminhnh.mincontrol.master.data.protocol.AppRule
import io.github.nevminhnh.mincontrol.master.data.protocol.RuleAction
import io.github.nevminhnh.mincontrol.master.data.protocol.UserPolicy

/** Pure editing logic for `appRules` ("Chặn ứng dụng"). Rules are evaluated in order; the first match wins. */
object AppRules {
    private const val BS = '\\'
    const val ORDER_HELP = "Quy tắc được xét từ trên xuống dưới, quy tắc khớp đầu tiên sẽ được áp dụng. " +
        "Muốn cho phép một ứng dụng dù đã bị chặn chung, hãy đặt quy tắc “Cho phép” lên trên quy tắc “Chặn”."

    private val sha256Re = Regex("^[0-9a-f]{64}$")

    fun actionLabel(a: RuleAction) = if (a == RuleAction.BLOCK) "Chặn" else "Cho phép"

    /** Returns an error message (Vietnamese) or null when [m] satisfies `common.schema.json#/$defs/appMatch`. */
    fun matchError(m: AppMatch): String? {
        if (m.exe == null && m.path == null && m.publisher == null && m.sha256 == null && m.pathUnderUserWritable == null)
            return "Mẫu ứng dụng đang trống"
        for ((k, v) in listOf("exe" to m.exe, "path" to m.path, "publisher" to m.publisher)) {
            if (v != null && (v.isEmpty() || v.length > 260)) return "Mẫu $k phải dài 1–260 ký tự"
        }
        m.exe?.let { if (BS in it || '/' in it) return "Mẫu exe chỉ gồm tên tệp (vd: Minecraft*.exe), không có đường dẫn" }
        if (m.sha256 != null && !sha256Re.matches(m.sha256)) return "sha256 phải gồm 64 ký tự thập lục phân viết thường"
        if (m.pathUnderUserWritable == false) return "pathUnderUserWritable chỉ có thể là true"
        return null
    }

    fun errors(rules: List<AppRule>): List<String> = rules.flatMap { r ->
        listOfNotNull(matchError(r.match)) + r.except.orEmpty().mapNotNull { matchError(it) }
    }

    /** Normalises a hand-typed/picked match (trim, lower-case sha256) so it passes the schema. */
    fun clean(m: AppMatch) = m.copy(
        exe = m.exe?.trim()?.takeIf { it.isNotEmpty() }, path = m.path?.trim()?.takeIf { it.isNotEmpty() },
        publisher = m.publisher?.trim()?.takeIf { it.isNotEmpty() }, sha256 = m.sha256?.trim()?.lowercase()?.takeIf { it.isNotEmpty() },
    )

    /**
     * Adds one rule per match. A block rule goes before the first allow rule (so a general "allow" cannot shadow
     * it), an allow rule is appended. A rule with the same match replaces the old one (no contradictory duplicates).
     */
    fun add(rules: List<AppRule>, action: RuleAction, matches: List<AppMatch>): List<AppRule> {
        var out = rules
        for (raw in matches) {
            val m = clean(raw)
            if (out.any { it.action == action && it.match == m && it.except.isNullOrEmpty() }) continue
            out = out.filterNot { it.match == m && it.except.isNullOrEmpty() }
            val rule = AppRule(action, m)
            val at = if (action == RuleAction.BLOCK) out.indexOfFirst { it.action == RuleAction.ALLOW }.let { if (it < 0) out.size else it } else out.size
            out = out.toMutableList().also { it.add(at, rule) }
        }
        return out
    }

    fun remove(rules: List<AppRule>, index: Int): List<AppRule> = rules.filterIndexed { i, _ -> i != index }

    /** Moves the rule at [index] by [delta] (-1 up, +1 down); out-of-range moves are ignored. */
    fun move(rules: List<AppRule>, index: Int, delta: Int): List<AppRule> {
        val to = index + delta
        if (index !in rules.indices || to !in rules.indices) return rules
        val l = rules.toMutableList()
        l.add(to, l.removeAt(index))
        return l
    }

    /** Quick action ("Chặn ứng dụng này") for an executable name seen in usage/events. Null when [exe] is blank. */
    fun matchForExe(exe: String?): AppMatch? = exe?.trim()?.substringAfterLast(BS)?.substringAfterLast('/')?.takeIf { it.isNotEmpty() }?.let { AppMatch(exe = it) }

    fun isBlocked(rules: List<AppRule>, exe: String?): Boolean {
        val m = matchForExe(exe) ?: return false
        return rules.any { it.action == RuleAction.BLOCK && it.match.exe.equals(m.exe, ignoreCase = true) && it.except.isNullOrEmpty() }
    }

    fun blockExe(up: UserPolicy, exe: String): UserPolicy {
        val m = matchForExe(exe) ?: return up
        return up.copy(appRules = add(up.appRules, RuleAction.BLOCK, listOf(m)))
    }

    /** Removes every plain block rule whose exe pattern matches [exe]. */
    fun unblockExe(up: UserPolicy, exe: String): UserPolicy {
        val name = matchForExe(exe)?.exe ?: return up
        return up.copy(appRules = up.appRules.filterNot {
            it.action == RuleAction.BLOCK && it.except.isNullOrEmpty() && it.match.exe != null && BlockingV2.glob(it.match.exe, name)
        })
    }

    /** Adds an allow rule for [exe] (replacing a same-match block rule). */
    fun allowExe(up: UserPolicy, exe: String): UserPolicy {
        val m = matchForExe(exe) ?: return up
        return up.copy(appRules = add(up.appRules, RuleAction.ALLOW, listOf(m)))
    }

    fun describe(r: AppRule): String {
        val base = AppPicker.describe(r.match)
        return if (r.except.isNullOrEmpty()) base else "$base (trừ ${r.except.joinToString { AppPicker.describe(it) }})"
    }
}
