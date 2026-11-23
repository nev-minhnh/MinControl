package io.github.nevminhnh.mincontrol.master.policy

/** Plain-language explanations shown under the web settings (API.md §19). */
object PolicyHelp {
    /** [engines] = names from search-engines.json (falls back to a short built-in list). */
    fun safeSearch(engines: List<String>): String {
        val names = engines.take(6).joinToString(", ") + if (engines.size > 6) "…" else ""
        return "Làm gì: Google và Bing luôn ở chế độ Tìm kiếm an toàn — ẩn hình ảnh, video và trang người lớn trong kết quả tìm kiếm. " +
            "Khi bật, các công cụ tìm kiếm khác bị chặn để con không tìm cách né ($names). " +
            "Không làm: không chặn trang web khi con gõ thẳng địa chỉ (việc đó do “Danh mục chặn” lo), không lọc YouTube hay ứng dụng."
    }

    const val YOUTUBE = "Làm gì: bật Chế độ hạn chế của YouTube — ẩn video có nội dung người lớn, bạo lực hoặc gây sốc và ẩn bình luận. " +
        "“Nghiêm ngặt” lọc nhiều nhất, “Vừa phải” lọc ít hơn. " +
        "Không làm: không giới hạn thời gian xem, không chặn video giải trí, game hay video ngắn — con vẫn xem YouTube bình thường. " +
        "Muốn con không xem YouTube chút nào (vd. trong giờ học), hãy chặn hẳn dịch vụ YouTube ở mục “Dịch vụ”."

    const val CATEGORY_SOURCE = "Danh mục từ UT1 Blacklist (Đại học Toulouse Capitole, Pháp) – cập nhật hằng ngày"

    const val APPS_ALLOWED_HELP_BLOCKLIST = "Không bắt buộc. Dùng để tạo ngoại lệ, vd. chặn cả nhà phát hành nhưng vẫn cho một ứng dụng chạy."
    const val APPS_ALLOWED_HELP_ALLOWLIST = "Chỉ các ứng dụng này (và dịch vụ được phép) mới chạy được."
    const val APPS_BLOCKED_HELP_BLOCKLIST = "Các ứng dụng này không chạy được trên máy của con."
    const val APPS_BLOCKED_HELP_ALLOWLIST = "Chỉ cần khi muốn chặn một ứng dụng vẫn khớp danh sách được phép."
    const val GROUPS_HELP = "Nhóm dùng để giới hạn thời gian theo loại ứng dụng. Mặc định không giới hạn; bật công tắc để đặt giờ mỗi ngày."
}
