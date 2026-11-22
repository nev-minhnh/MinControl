// Script of blocked.html (no inline scripts under the MV3 CSP).
const params = new URLSearchParams(location.search);
const host = params.get('host') ?? '';
const reason = params.get('reason') ?? '';

const reasonText: Record<string, string> = {
  blocklist: 'Trang này nằm trong danh sách bị chặn.',
  allowlist_miss: 'Hiện chỉ các trang đã được bố mẹ cho phép mới mở được.',
  proxy: 'Trang này đã bị chặn theo cài đặt của bố mẹ.',
};

const hostEl = document.getElementById('host');
if (hostEl) hostEl.textContent = host || 'Trang web';
const reasonEl = document.getElementById('reason');
if (reasonEl) reasonEl.textContent = reasonText[reason] ?? reasonText['proxy'] ?? '';
document.getElementById('back')?.addEventListener('click', () => {
  if (history.length > 2) history.go(-2);
  else location.href = 'about:blank';
});
