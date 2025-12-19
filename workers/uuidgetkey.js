/**
 * @file Cloudflare Worker for serving a key query tool.
 * @description This worker serves a static HTML page for querying RSA keys from a D1 database
 * and provides a JSON API endpoint for the query functionality.
 *
 * Code structure has been refactored for improved readability and maintainability.
 */

// ===================================================================================
// Front-End Asset Generation
// Rationale: Separating HTML, CSS, and client-side JS into distinct constants
// improves readability and makes front-end updates easier without sifting through backend logic.
// ===================================================================================

/**
 * Generates the full HTML page by combining structure, styles, and scripts.
 * @returns {string} The complete HTML document.
 */
function getHtmlPage() {
    const CSS_STYLES = `
      /* --- Base & Typography --- */
      html { font-size: 87.5%; }
      body, html { margin: 0; padding: 0; min-height: 100%; background-color: #fff; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
  
      /* --- Layout Containers --- */
      .container {
          width: 100%;
          min-height: 100vh;
          display: flex;
          flex-direction: column;
          justify-content: center;
          align-items: center;
          padding: 40px; 
          box-sizing: border-box;
      }
      .content-group {
          width: 100%;
          max-width: 1200px; 
          text-align: center;
          z-index: 10;
          box-sizing: border-box;
      }
  
      /* --- Header Elements --- */
      .profile-name { font-size: 2.2rem; color: #3d474d; margin-bottom: 10px; font-weight: bold;}
      .profile-quote { color: #89949B; margin-bottom: 27px; min-height: 1.2em; }
      
      /* --- Buttons & Navigation --- */
      .nav-grid { display: flex; flex-wrap: wrap; justify-content: center; gap: 8px; margin-bottom: 27px; }
      .nav-btn {
          padding: 8px 16px; text-align: center; background: #E8EBED; border: 2px solid #89949B;
          border-radius: 4px; color: #5a666d; text-decoration: none; font-weight: 500;
          font-size: 0.95rem; transition: all 0.3s; white-space: nowrap; cursor: pointer;
          display: inline-flex; align-items: center; justify-content: center;
      }
      .nav-btn:hover:not(:disabled) { background: #89949B; color: white; }
      .nav-btn:disabled { opacity: 0.6; cursor: not-allowed;}
      .nav-btn.primary { background-color: #5a666d; color: white; border-color: #5a666d;}
      .nav-btn.primary:hover:not(:disabled) { background-color: #3d474d; }
  
      /* --- Cards --- */
      .card {
          background: #f8f9fa; border: 1px solid #E8EBED; border-radius: 8px;
          padding: 24px; margin-bottom: 24px; text-align: left;
      }
      .card h2 { font-size: 1.5rem; color: #3d474d; margin-top: 0; margin-bottom: 20px; text-align: center;}
      .card h3 { font-size: 1.2rem; color: #3d474d; margin-top: 0; margin-bottom: 15px; display: flex; align-items: center; justify-content: center; gap: 10px; }
      
      /* --- Forms & Inputs --- */
      .form-group { margin-bottom: 16px; }
      .form-group label { display: block; color: #5a666d; font-weight: 500; margin-bottom: 8px; font-size: 0.9rem;}
      
      textarea, input[type="text"] {
          width: 100%; padding: 10px; border: 2px solid #89949B; border-radius: 4px;
          background: #fff; font-family: 'SF Mono', 'Courier New', monospace; font-size: 0.9rem;
          box-sizing: border-box; resize: vertical;
      }
      textarea:focus, input[type="text"]:focus { outline: none; border-color: #3d474d; }
      
      /* --- Info & Result Boxes --- */
      .info-box {
          background-color: #e8ebed; color: #5a666d; border-left: 4px solid #89949B;
          padding: 12px 16px; border-radius: 4px; font-size: 0.85rem; text-align: left;
          line-height: 1.5; margin: 16px 0;
      }
      .info-box strong { color: #3d474d; }
      .result-container { margin-top: 20px; }
      .result-container .info-box.error { border-color: #e74c3c; background-color: #fceded; color: #c0392b; }
      .result-container .info-box.success { border-color: #28a745; background-color: #eafaf1; color: #218838; }
      
      .key-buttons { display: flex; gap: 10px; margin-top: 10px; justify-content: flex-end; }
      
      /* MODIFIED: Styling for the connected buttons */
      .download-grid { 
          display: flex; /* Changed to flexbox for connected buttons */
          /* Removed grid-template-columns and gap for this specific layout */
          
          /* Control the overall width of the button bar and center it */
          max-width: 600px; /* Adjust this value to match your desired bar width in the image */
          margin: 0 auto; /* Centers the entire .download-grid container */
          
          /* Apply the main border and rounded corners to the container itself */
          border: 2px solid #89949B;
          border-radius: 4px;
          overflow: hidden; /* Crucial: Ensures children's sharp corners don't "poke out" from the container's rounded corners */
      }
      /* Override default .nav-btn styles for buttons within .download-grid */
      .download-grid .nav-btn {
          flex-grow: 1; /* Make both links take up equal space within the flex container */
          flex-basis: 0; /* Ensures equal distribution regardless of content */
          width: auto; /* Override previous fixed width or calculated width */
          border: none; /* Crucial: Remove individual borders from these specific buttons */
          border-radius: 0; /* Crucial: Remove individual rounded corners */
          /* Padding, color, background and transition from general .nav-btn still applies */
      }
  
      /* Add the vertical separator line between the two buttons */
      .download-grid .nav-btn:not(:first-child) {
          border-left: 2px solid #89949B; /* This creates the visible dividing line */
      }
  
      /* Specific button colors (now without border-color, as parent defines border) */
      .btn-danger { background-color: #d9534f; color: white; border-color: #d43f3a; }
      .btn-danger:hover:not(:disabled) { background-color: #c9302c; border-color: #ac2925; }
      .btn-github { background-color: #333; color: white; /* No border-color here */ }
      .btn-github:hover:not(:disabled) { background-color: #1a1a1a; }
      .btn-blog { background-color: #28a745; color: white; border-color: #28a745;}
      .btn-blog:hover:not(:disabled) { background-color: #218838; }
      .btn-docs { background-color: #17a2b8; color: white; /* No border-color here */ }
      .btn-docs:hover:not(:disabled) { background-color: #138496; }
  
      .platform-container { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; }
      .platform-card { border: 1px solid #E8EBED; border-radius: 6px; padding: 16px; background-color: #fff; display: flex; flex-direction: column; }
      .platform-title {
          font-size: 1.1rem; color: #3d474d; margin-top: 0; margin-bottom: 16px;
          border-bottom: 1px solid #E8EBED; padding-bottom: 10px; display: flex; align-items: center;
      }
      .platform-title i { margin-right: 10px; color: #5a666d; font-size: 1.3em; }
      .platform-buttons { display: flex; flex-direction: column; gap: 14px; flex-grow: 1; }
      .platform-buttons .nav-btn { justify-content: flex-start; }
  
      .footer { margin-top: 40px; text-align: center; color: #89949B; font-size: 0.8rem; }
      .footer a { color: #89949B; text-decoration: none; }
      .footer a:hover { text-decoration: underline; }
    `;
  
    const CLIENT_SCRIPT = `
      // [REFACTORED] Client-side logic remains the same but is now encapsulated.
      document.addEventListener('DOMContentLoaded', () => {
          const queryForm = document.getElementById('keyQueryForm');
          const uuidInput = document.getElementById('uuidInput');
          const resultContainer = document.getElementById('query-result');
  
          if (uuidInput) {
              uuidInput.focus();
          }
  
          if (queryForm) {
              queryForm.addEventListener('submit', async function(e) {
                  e.preventDefault();
                  const uuid = uuidInput.value.trim();
  
                  if (!uuid) {
                      resultContainer.style.display = 'block';
                      resultContainer.innerHTML = \`<div class="info-box error"><i class="fas fa-exclamation-circle" style="margin-right: 10px;"></i>UUID 不能为空。</div>\`;
                      return;
                  }
  
                  resultContainer.style.display = 'block';
                  resultContainer.innerHTML = \`<div class="info-box"><i class="fas fa-spinner fa-spin" style="margin-right: 10px;"></i>正在查询，请稍候...</div>\`;
  
                  try {
                      const response = await fetch('/query?uuid=' + encodeURIComponent(uuid));
                      const data = await response.json();
  
                      if (data.status === 'success') {
                          let resultHtml = '<h3><i class="fas fa-check-circle" style="color: #28a745;"></i> 查询成功</h3>';
                          
                          // Display UUID and RID
                          resultHtml += \`<div class="info-box success"><strong>UUID:</strong> \${escapeHtml(data.uuid)}</div>\`;
                          if (data.rid) {
                              resultHtml += \`<div class="info-box success"><strong>RID:</strong> \${escapeHtml(data.rid)}</div>\`;
                          }
                          
                          // Display Public Key
                          resultHtml += \`
                              <div class="form-group" style="margin-top: 15px;">
                                  <label for="publicKey">公钥内容</label>
                                  <textarea id="publicKey" rows="8" readonly>\${escapeHtml(data.public_key_pem)}</textarea>
                                  <div class="key-buttons">
                                      <button type="button" class="nav-btn" onclick="copyKey('publicKey')">复制</button>
                                      <button type="button" class="nav-btn primary" onclick="downloadKey('publicKey', '\${escapeHtml(data.uuid)}', 'public')">下载</button>
                                  </div>
                              </div>\`;
  
                          // Display Private Key if available
                          if (data.private_key_pem) {
                              resultHtml += \`
                                  <div class="form-group" style="margin-top: 15px;">
                                      <label for="privateKey">私钥内容</label>
                                      <textarea id="privateKey" rows="12" readonly>\${escapeHtml(data.private_key_pem)}</textarea>
                                      <div class="key-buttons">
                                          <button type="button" class="nav-btn" onclick="copyKey('privateKey')">复制</button>
                                          <button type="button" class="nav-btn primary" onclick="downloadKey('privateKey', '\${escapeHtml(data.uuid)}', 'private')">下载</button>
                                      </div>
                                  </div>
                                  <div class="info-box error">
                                      <i class="fas fa-info-circle" style="margin-right: 10px;"></i><strong>请务必妥善保管您的私钥，一旦丢失将无法恢复文件。</strong>
                                  </div>\`;
                          }
                          
                          resultContainer.innerHTML = resultHtml;
  
                      } else {
                          resultContainer.innerHTML = \`
                              <h3><i class="fas fa-times-circle" style="color: #c0392b;"></i> 查询失败</h3>
                              <div class="info-box error">
                                  <i class="fas fa-exclamation-triangle" style="margin-right: 10px;"></i>
                                  \${escapeHtml(data.message)} (UUID: \${escapeHtml(uuid)})
                              </div>\`;
                      }
                  } catch (error) {
                       resultContainer.innerHTML = \`
                          <h3><i class="fas fa-network-wired" style="color: #c0392b;"></i> 网络错误</h3>
                          <div class="info-box error">
                              <i class="fas fa-exclamation-triangle" style="margin-right: 10px;"></i>
                              发生网络或解析错误: \${escapeHtml(error.message)}
                          </div>\`;
                  }
              });
          }
      });
      
      function escapeHtml(text) {
        const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
        return (text == null ? '' : String(text)).replace(/[&<>\\"']/g, function(m) { return map[m]; });
      }
  
      function copyKey(elementId) {
          const textarea = document.getElementById(elementId);
          if (!textarea) return;
          navigator.clipboard.writeText(textarea.value).then(() => {
              alert('密钥已复制到剪贴板！');
          }).catch(err => {
              console.error('复制失败: ', err);
              alert('复制失败，请手动复制。');
          });
      }
  
      function downloadKey(elementId, uuid, keyType) {
          const keyContent = document.getElementById(elementId)?.value;
          if (!keyContent) return;
          const blob = new Blob([keyContent], { type: 'application/x-pem-file;charset=utf-8' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = \`\${keyType}_key_\${uuid}.pem\`;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          URL.revokeObjectURL(url);
      }
    `;
  
    return `
  <!DOCTYPE html>
  <html lang="zh-CN">
  <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>YZFN RSA加密</title>
      <link rel="icon" href="https://s3.yangzifun.org/logo.ico" type="image/x-icon">
      <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
      <style>${CSS_STYLES}</style>
  </head>
  <body>
      <div class="container">
          <div class="content-group">
              <h1 class="profile-name"><i class="fas fa-file-lock" style="margin-right: 15px;"></i>密钥查询与下载工具</h1>
              <p class="profile-quote">一个用于保护文件安全的跨平台RSA加密方案</p>
  
              <div class="card">
                  <h2><i class="fas fa-key" style="margin-right: 10px;"></i>密钥查询</h2>
                  <form id="keyQueryForm">
                      <div class="form-group">
                          <label for="uuidInput">输入 UUID:</label>
                          <input type="text" id="uuidInput" name="uuid" placeholder="例如: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" required>
                          <div class="info-box">
                              <i class="fas fa-info-circle" style="margin-right: 10px;"></i>请在此处输入您在加密文件时获得的<strong>UUID</strong>以查询对应密钥。
                          </div>
                      </div>
                      <button type="submit" class="nav-btn primary" style="width: 100%;">
                          <i class="fas fa-paper-plane" style="margin-right: 8px;"></i> 查询密钥
                      </button>
                  </form>
                  <div id="query-result" class="result-container" style="display: none;"></div>
              </div>
  
              <div class="card">
                  <h2><i class="fas fa-download" style="margin-right: 10px;"></i>下载组件</h2>
                  <p class="profile-quote" style="text-align:center; margin-bottom: 20px;">请根据您的操作系统选择对应的工具集。</p>
                  <div class="platform-container">
                      <div class="platform-card">
                          <h3 class="platform-title"><i class="fab fa-apple"></i> macOS</h3>
                          <div class="platform-buttons">
                              <a href="https://s3.yangzifun.org/crypt/encrypt_osx.sh" class="nav-btn" download><i class="fas fa-file-archive"></i>单个文件加密脚本</a>
                              <a href="https://s3.yangzifun.org/crypt/batch_encrypt_osx.sh" class="nav-btn" download><i class="fas fa-file-zipper"></i>批量文件加密脚本</a>
                              <a href="https://s3.yangzifun.org/crypt/encrypt_folder_osx.sh" class="nav-btn" download><i class="fas fa-folder-plus"></i>目录加密脚本</a>
                              <a href="https://s3.yangzifun.org/crypt/decrypt_osx.sh" class="nav-btn primary" download><i class="fas fa-lock-open"></i>解密脚本</a>
                          </div>
                      </div>
                      <div class="platform-card">
                          <h3 class="platform-title"><i class="fab fa-linux"></i> Linux</h3>
                          <div class="platform-buttons">
                              <a href="https://s3.yangzifun.org/crypt/encrypt_linux.sh" class="nav-btn" download><i class="fas fa-file-archive"></i>单个文件加密脚本</a>
                              <a href="https://s3.yangzifun.org/crypt/batch_encrypt_linux.sh" class="nav-btn" download><i class="fas fa-file-zipper"></i>批量文件加密脚本</a>
                              <a href="https://s3.yangzifun.org/crypt/encrypt_folder_linux.sh" class="nav-btn" download><i class="fas fa-folder-plus"></i>目录加密脚本</a>
                              <a href="https://s3.yangzifun.org/crypt/decrypt_linux.sh" class="nav-btn primary" download><i class="fas fa-lock-open"></i>解密脚本</a>
                          </div>
                      </div>
                      <div class="platform-card">
                          <h3 class="platform-title">加解密程序</h3>
                          <div class="platform-buttons">
                               <a href="https://s3.yangzifun.org/crypt/CryptoApp-Windows-x86_64.exe" class="nav-btn" download><i class="fab fa-windows"></i> Windows 加解密</a>
                               <a href="https://s3.yangzifun.org/crypt/CryptoApp-Linux-x86_64" class="nav-btn" download><i class="fab fa-linux"></i> Linux 加解密</a>
                               <a href="https://s3.yangzifun.org/crypt/CryptoApp-macOS-x86_64" class="nav-btn" download><i class="fab fa-apple"></i> macOS 加解密</a>
                          </div>
                      </div>
                      <div class="platform-card">
                          <h3 class="platform-title"><i class="fas fa-"skull-crossbones"></i> 勒索程序</h3>
                          <div class="platform-buttons">
                               <a href="https://s3.yangzifun.org/crypt/ransom_simulator.exe" class="nav-btn btn-danger" download><i class="fas fa-biohazard"></i> Windows 勒索程序 (⚠危险)</a>
                               <a href="https://s3.yangzifun.org/crypt/ransom_simulator_linux" class="nav-btn btn-danger" download><i class="fas fa-biohazard"></i> Linux 勒索程序 (⚠危险)</a>
                          </div>
                      </div>
                  </div>
  
                  <h2 style="margin-top: 30px;"><i class="fas fa-link" style="margin-right: 10px;"></i>相关链接</h2>
                  <div class="download-grid">
                      <!-- MODIFIED: Links are direct children of .download-grid again, no extra div wrappers -->
                      <a href="https://github.com/yangzifun/enc" target="_blank" rel="noopener noreferrer" class="nav-btn btn-github"><i class="fab fa-github"></i>项目 GitHub</a>
                      <a href="https://bbs.yangzihome.space/archives/encrypt" target="_blank" rel="noopener noreferrer" class="nav-btn btn-docs"><i class="fas fa-book"></i>在线文档</a>
                  </div>
              </div>
              
              <div class="footer">
                  <p>Powered by <a href="https://www.yangzihome.space">YZFN</a> | <a href="https://www.yangzihome.space/security-statement">安全声明</a></p>
              </div>
          </div>
      </div>
      <script>${CLIENT_SCRIPT}</script>
  </body>
  </html>
    `;
  }
  
  
  // ===================================================================================
  // API and Routing Logic
  // Rationale: These functions handle the core backend logic. Separating them from the
  // front-end code makes the worker's primary responsibilities clear.
  // ===================================================================================
  
  /**
   * Handles requests to the `/query` API endpoint.
   * @param {Request} request The incoming request object.
   * @param {object} env The environment object containing bindings (like D1).
   * @returns {Promise<Response>} A JSON response.
   */
  async function handleApiQuery(request, env) {
    const url = new URL(request.url);
    const uuidToQuery = url.searchParams.get('uuid');
  
    if (!uuidToQuery) {
      return Response.json({ status: "error", message: "缺少 UUID 参数" }, { status: 400 });
    }
  
    // Ensure the D1 binding 'search' is configured.
    if (!env.search || typeof env.search.prepare !== 'function') {
      const errMsg = "D1 数据库绑定 'search' 未正确初始化或缺失。";
      console.error(errMsg);
      return Response.json({ status: "error", message: errMsg }, { status: 500 });
    }
  
    try {
      const stmt = env.search.prepare("SELECT public_key, private_key, rid FROM keys WHERE uuid = ?");
      const { results } = await stmt.bind(uuidToQuery).all();
  
      if (results.length > 0) {
        const { public_key, private_key, rid } = results[0];
        return Response.json({
          status: "success",
          message: "查询成功",
          uuid: uuidToQuery,
          public_key_pem: public_key,
          private_key_pem: private_key,
          rid: rid
        }, { status: 200 });
      } else {
        return Response.json({
          status: "error",
          message: "未找到对应的 UUID 或密钥对",
          uuid: uuidToQuery
        }, { status: 404 });
      }
    } catch (dbQueryError) {
      console.error(`D1 查询错误: ${dbQueryError.message}`, dbQueryError);
      return Response.json({ 
          status: "error", 
          message: `数据库查询失败: ${dbQueryError.message}` 
      }, { status: 500 });
    }
  }
  
  /**
   * Handles requests for the main HTML page.
   * @returns {Response} An HTML response.
   */
  function handleStaticPage() {
    return new Response(getHtmlPage(), {
      headers: { 'Content-Type': 'text/html;charset=UTF-8' },
    });
  }
  
  
  // ===================================================================================
  // Main Worker Entrypoint
  // Rationale: The `fetch` handler now acts as a simple, clean router,
  // delegating tasks to specialized functions based on the request path and method.
  // ===================================================================================
  
  export default {
    async fetch(request, env, ctx) {
      const url = new URL(request.url);
  
      // This worker only processes GET requests.
      if (request.method !== 'GET') {
        return Response.json({ status: "error", message: "此 Worker 仅支持 GET 请求" }, { 
            status: 405, 
            headers: { 'Allow': 'GET' }
        });
      }
  
      // Simple path-based routing
      switch (url.pathname) {
        case '/':
          return handleStaticPage();
  
        case '/query':
          return handleApiQuery(request, env);
  
        default:
          return new Response("404 Not Found", { status: 404 });
      }
    },
  };
  