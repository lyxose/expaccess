(function () {
  const ACCESS_BASE = "https://exp.vaonline.dpdns.org";
  const VERIFY_ENDPOINT = `${ACCESS_BASE}/token/verify`;
  const token = new URLSearchParams(location.search).get("access_token");

  const mask = document.createElement("div");
  mask.style.position = "fixed";
  mask.style.inset = "0";
  mask.style.background = "#f6f7fb";
  mask.style.color = "#1f2937";
  mask.style.display = "flex";
  mask.style.alignItems = "center";
  mask.style.justifyContent = "center";
  mask.style.zIndex = "999999";
  mask.style.fontFamily = "Noto Sans SC, sans-serif";
  mask.innerHTML = "<div style=\"text-align:center;max-width:420px;padding:24px\"><h2>正在验证实验访问</h2><p id=\"accessMsg\" style=\"color:#6b7280\">请稍候...</p></div>";
  document.addEventListener("DOMContentLoaded", () => document.body.appendChild(mask));

  async function verify() {
    if (!token) {
      update("未检测到访问令牌，请从预约入口进入实验。", true);
      return false;
    }
    try {
      const resp = await fetch(VERIFY_ENDPOINT, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token }),
      });
      if (!resp.ok) {
        const data = await resp.json().catch(() => ({}));
        update(data.error || "访问令牌无效", true);
        return false;
      }
      update("验证通过，正在进入实验...", false);
      return true;
    } catch {
      update("验证失败，请检查网络后重试。", true);
      return false;
    }
  }

  function update(text, isError) {
    const msg = document.getElementById("accessMsg");
    if (!msg) return;
    msg.textContent = text;
    msg.style.color = isError ? "#b42318" : "#2563eb";
  }

  window.addEventListener("load", async () => {
    const ok = await verify();
    if (ok) {
      setTimeout(() => mask.remove(), 200);
    }
  });
})();
