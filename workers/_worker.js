// ===================================================================================
// _worker.js - 合并后的 Cloudflare Worker
// 功能：RSA 密钥对生成 + UUID 分发（支持安全路径）+ 密钥查询 + 统计面板
// ===================================================================================

// ===================================================================================
// 默认安全路径 (可自行修改)
// 当环境变量 SECRET_PATH 未设置时，使用此默认值作为密钥生成接口的访问路径
// ===================================================================================
const DEFAULT_SECRET_PATH = "E56dSY";

// ===================================================================================
// 第一部分：RSA 密钥生成 (源自 rsauuid.js)
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
// 第二部分：密钥查询与统计面板 (源自 uuidgetkey.js)
// ===================================================================================

function getHtmlPage() {
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
    <title>密钥管理中心</title>
    <link rel="icon" href="https://s3.yangzifun.org/logo.ico" type="image/x-icon">
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/lucide@latest"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
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
      .platform-grid { grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); }
      @media (max-width: 768px) { .stats-grid { grid-template-columns: 1fr; } }
    </style>
</head>
<body class="bg-white min-h-screen text-gray-700">
    <div class="min-h-screen flex flex-col items-center py-10 px-4 sm:px-6 lg:px-8">
        <div class="w-full max-w-7xl mx-auto text-center z-10">
            <div class="mb-10">
                <div class="flex items-center justify-center mb-4">
                    <i data-lucide="shield" class="w-10 h-10 mr-4 text-gray-600"></i>
                    <h1 class="text-3xl sm:text-4xl font-bold text-gray-700">密钥管理中心 :V3.2</h1>
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
                    <h2 class="text-2xl font-semibold text-gray-700">密钥查询</h2>
                </div>
                <form id="keyQueryForm" class="space-y-6">
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

            <div class="bg-gray-50 border border-gray-200 rounded-xl p-6 mb-8 text-left">
                <div class="flex items-center justify-center mb-6">
                    <i data-lucide="download" class="w-6 h-6 mr-3 text-gray-600"></i>
                    <h2 class="text-2xl font-semibold text-gray-700">下载组件</h2>
                </div>
                <div class="grid platform-grid gap-6 mb-10">
                    <div class="border border-gray-200 rounded-lg p-5 bg-white flex flex-col">
                        <div class="flex items-center justify-center mb-4">
                            <i data-lucide="apple" class="w-6 h-6 mr-3"></i>
                            <h3 class="text-xl font-medium text-gray-700">macOS</h3>
                        </div>
                        <div class="space-y-3 flex-grow">
                            <a href="https://s3.yangzifun.org/crypt/encrypt_osx.sh" class="flex items-center px-4 py-3 bg-gray-200 text-gray-700 border-2 border-gray-400 rounded hover:bg-gray-300 transition-colors" download><i data-lucide="file-archive" class="w-5 h-5 mr-3"></i><span class="text-sm">单个文件加密脚本</span></a>
                            <a href="https://s3.yangzifun.org/crypt/batch_encrypt_osx.sh" class="flex items-center px-4 py-3 bg-gray-200 text-gray-700 border-2 border-gray-400 rounded hover:bg-gray-300 transition-colors" download><i data-lucide="file-zipper" class="w-5 h-5 mr-3"></i><span class="text-sm">批量文件加密脚本</span></a>
                            <a href="https://s3.yangzifun.org/crypt/encrypt_folder_osx.sh" class="flex items-center px-4 py-3 bg-gray-200 text-gray-700 border-2 border-gray-400 rounded hover:bg-gray-300 transition-colors" download><i data-lucide="folder-plus" class="w-5 h-5 mr-3"></i><span class="text-sm">目录加密脚本</span></a>
                            <a href="https://s3.yangzifun.org/crypt/decrypt_osx.sh" class="flex items-center px-4 py-3 bg-gray-700 text-white border-2 border-gray-700 rounded hover:bg-gray-800 transition-colors" download><i data-lucide="lock-open" class="w-5 h-5 mr-3"></i><span class="text-sm">解密脚本</span></a>
                        </div>
                    </div>
                    <div class="border border-gray-200 rounded-lg p-5 bg-white flex flex-col">
                        <div class="flex items-center justify-center mb-4">
                            <i data-lucide="terminal" class="w-6 h-6 mr-3"></i>
                            <h3 class="text-xl font-medium text-gray-700">Linux</h3>
                        </div>
                        <div class="space-y-3 flex-grow">
                            <a href="https://s3.yangzifun.org/crypt/encrypt_linux.sh" class="flex items-center px-4 py-3 bg-gray-200 text-gray-700 border-2 border-gray-400 rounded hover:bg-gray-300 transition-colors" download><i data-lucide="file-archive" class="w-5 h-5 mr-3"></i><span class="text-sm">单个文件加密脚本</span></a>
                            <a href="https://s3.yangzifun.org/crypt/batch_encrypt_linux.sh" class="flex items-center px-4 py-3 bg-gray-200 text-gray-700 border-2 border-gray-400 rounded hover:bg-gray-300 transition-colors" download><i data-lucide="file-zipper" class="w-5 h-5 mr-3"></i><span class="text-sm">批量文件加密脚本</span></a>
                            <a href="https://s3.yangzifun.org/crypt/encrypt_folder_linux.sh" class="flex items-center px-4 py-3 bg-gray-200 text-gray-700 border-2 border-gray-400 rounded hover:bg-gray-300 transition-colors" download><i data-lucide="folder-plus" class="w-5 h-5 mr-3"></i><span class="text-sm">目录加密脚本</span></a>
                            <a href="https://s3.yangzifun.org/crypt/decrypt_linux.sh" class="flex items-center px-4 py-3 bg-gray-700 text-white border-2 border-gray-700 rounded hover:bg-gray-800 transition-colors" download><i data-lucide="lock-open" class="w-5 h-5 mr-3"></i><span class="text-sm">解密脚本</span></a>
                        </div>
                    </div>
                    <div class="border border-gray-200 rounded-lg p-5 bg-white flex flex-col">
                        <div class="flex items-center justify-center mb-4">
                            <i data-lucide="monitor" class="w-6 h-6 mr-3"></i>
                            <h3 class="text-xl font-medium text-gray-700">Windows</h3>
                        </div>
                        <div class="space-y-3 flex-grow">
                            <a href="https://s3.yangzifun.org/crypt/CryptoApp-Windows-x86_64.exe" class="flex items-center px-4 py-3 bg-gray-200 text-gray-700 border-2 border-gray-400 rounded hover:bg-gray-300 transition-colors" download><i data-lucide="monitor" class="w-5 h-5 mr-3"></i><span class="text-sm">Windows 加解密</span></a>
                            <a href="https://s3.yangzifun.org/crypt/CryptoApp-Linux-x86_64" class="flex items-center px-4 py-3 bg-gray-200 text-gray-700 border-2 border-gray-400 rounded hover:bg-gray-300 transition-colors" download><i data-lucide="terminal" class="w-5 h-5 mr-3"></i><span class="text-sm">Linux 加解密</span></a>
                            <a href="https://s3.yangzifun.org/crypt/CryptoApp-macOS-x86_64" class="flex items-center px-4 py-3 bg-gray-200 text-gray-700 border-2 border-gray-400 rounded hover:bg-gray-300 transition-colors" download><i data-lucide="apple" class="w-5 h-5 mr-3"></i><span class="text-sm">macOS 加解密</span></a>
                        </div>
                    </div>
                    <div class="border border-gray-200 rounded-lg p-5 bg-white flex flex-col">
                        <div class="flex items-center justify-center mb-4">
                            <i data-lucide="skull" class="w-6 h-6 mr-3"></i>
                            <h3 class="text-xl font-medium text-gray-700">测试工具</h3>
                        </div>
                        <div class="space-y-3 flex-grow">
                            <a href="https://s3.yangzifun.org/crypt/ransom_simulator.exe" class="flex items-center px-4 py-3 bg-red-100 text-red-700 border-2 border-red-400 rounded hover:bg-red-200 transition-colors" download><i data-lucide="biohazard" class="w-5 h-5 mr-3"></i><span class="text-sm">Windows 勒索程序 (⚠危险)</span></a>
                            <a href="https://s3.yangzifun.org/crypt/ransom_simulator_linux" class="flex items-center px-4 py-3 bg-red-100 text-red-700 border-2 border-red-400 rounded hover:bg-red-200 transition-colors" download><i data-lucide="biohazard" class="w-5 h-5 mr-3"></i><span class="text-sm">Linux 勒索程序 (⚠危险)</span></a>
                            <a href="https://s3.yangzifun.org/crypt/ransom_simulator_linux_static" class="flex items-center px-4 py-3 bg-red-100 text-red-700 border-2 border-red-400 rounded hover:bg-red-200 transition-colors" download><i data-lucide="biohazard" class="w-5 h-5 mr-3"></i><span class="text-sm">Linux 勒索程序 (静态编译)</span></a>
                        </div>
                    </div>
                </div>
                <h2 class="text-xl font-semibold text-gray-700 text-center mb-6">相关链接</h2>
                <div class="flex flex-col sm:flex-row border-2 border-gray-400 rounded overflow-hidden max-w-2xl mx-auto">
                    <a href="https://github.com/yangzifun/enc" target="_blank" class="flex-1 flex items-center justify-center px-6 py-3 bg-gray-900 text-white hover:bg-black transition-colors"><i data-lucide="github" class="w-5 h-5 mr-3"></i><span class="text-sm font-medium">项目GitHub</span></a>
                    <a href="https://bbs.yangzihome.space/archives/encrypt" target="_blank" rel="noopener noreferrer" class="flex-1 flex items-center justify-center px-6 py-3 bg-gray-200 text-gray-700 border-0 sm:border-l-2 border-gray-400 hover:bg-gray-300 transition-colors"><i data-lucide="book" class="w-5 h-5 mr-3"></i><span class="text-sm font-medium">加密文档</span></a>
                    <a href="https://bbs.yangzihome.space/archives/extortion" target="_blank" rel="noopener noreferrer" class="flex-1 flex items-center justify-center px-6 py-3 bg-gray-200 text-gray-700 border-0 sm:border-l-2 border-gray-400 hover:bg-gray-300 transition-colors"><i data-lucide="book" class="w-5 h-5 mr-3"></i><span class="text-sm font-medium">勒索文档</span></a>
                </div>
            </div>

            <div class="mt-10 text-center text-gray-500 text-sm">
                <p>Powered by <a href="https://www.yangzihome.space" class="text-gray-600 hover:text-gray-800 transition-colors">YZFN</a> | <a href="https://www.yangzihome.space/security.html" class="text-gray-600 hover:text-gray-800 transition-colors">安全声明</a></p>
            </div>
        </div>
    </div>
    <script>${CLIENT_SCRIPT}</script>
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
// 主入口
// ===================================================================================

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);

        // --- C2 Beacon 端点 ---
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

        // POST 请求 → 仅允许通过安全路径访问密钥生成接口
        if (request.method === 'POST') {
            // 安全路径检查：优先使用环境变量 SECRET_PATH，未设置时使用默认值 DEFAULT_SECRET_PATH
            const requestPath = url.pathname.replace(/\/+$/, '') || '/';
            const secretPath = env.SECRET_PATH || DEFAULT_SECRET_PATH;
            const expectedPath = '/' + secretPath.replace(/^\/+|\/+$/g, '');
            if (requestPath !== expectedPath) {
                return new Response(JSON.stringify({ status: "error", message: "Not Found" }), {
                    headers: { 'Content-Type': 'application/json' },
                    status: 404
                });
            }
            return handleKeyGeneration(request, env);
        }

        // GET 请求 → 路由分发
        if (request.method !== 'GET') {
            return Response.json({ status: "error", message: "Method Not Allowed" }, { status: 405 });
        }

        switch (url.pathname) {
            case '/':
                return new Response(getHtmlPage(), {
                    headers: { 'Content-Type': 'text/html;charset=UTF-8' },
                });
            case '/query':
                return handleApiQuery(request, env);
            case '/stats':
                return handleApiStats(env, request);
            default:
                return new Response("404 Not Found", { status: 404 });
        }
    },
};