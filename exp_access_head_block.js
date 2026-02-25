(function () {
  const ACCESS_BASE = "https://exp.vaonline.dpdns.org";
  const VERIFY_ENDPOINT = `${ACCESS_BASE}/token/verify`;
  const token = new URLSearchParams(location.search).get("access_token");
  document.documentElement.style.visibility = "hidden";

  function showError(message) {
    document.documentElement.innerHTML = "";
    document.body.style.margin = "0";
    document.body.style.fontFamily = "Noto Sans SC, sans-serif";
    document.body.innerHTML = `<div style=\"min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f6f7fb;color:#1f2937\"><div style=\"max-width:420px;padding:24px;text-align:center\"><h2>无法进入实验</h2><p style=\"color:#b42318\">${message}</p></div></div>`;
    document.documentElement.style.visibility = "visible";
  }

  async function verify() {
    if (!token) {
      showError("未检测到访问令牌，请从预约入口进入实验。");
      return;
    }
    try {
      const resp = await fetch(VERIFY_ENDPOINT, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token }),
      });
      if (!resp.ok) {
        const data = await resp.json().catch(() => ({}));
        showError(data.error || "访问令牌无效");
        return;
      }
      document.documentElement.style.visibility = "visible";
    } catch {
      showError("验证失败，请检查网络后重试。");
    }
  }

  verify();
})();
