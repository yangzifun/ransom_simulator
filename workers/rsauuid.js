// src/index.js

/**
 * 助手函数：将 ArrayBuffer 转换为 PEM 格式的密钥字符串
 * @param {ArrayBuffer} keyData - 导出的密钥数据 (SPKI 或 PKCS#8 格式)
 * @param {string} type - 'public' 或 'private'，用于决定 PEM 头部和尾部
 * @returns {string} PEM 格式的密钥字符串
 */
function toPem(keyData, type) {
  // ArrayBuffer 转换为 Uint8Array，然后转换为字符串，再进行 base64 编码
  const base64 = btoa(String.fromCharCode(...new Uint8Array(keyData)));
  const header = type === 'public' ? 'BEGIN PUBLIC KEY' : 'BEGIN PRIVATE KEY';
  const footer = type === 'public' ? 'END PUBLIC KEY' : 'END PRIVATE KEY';
  // 每64个字符插入一个换行符，符合 PEM 格式规范
  const pem = base64.match(/.{1,64}/g).join('\n');
  return `-----${header}-----\n${pem}\n-----${footer}-----`;
}


// Worker 的主要入口点
export default {
  /**
   * Cloudflare Worker 的 fetch 处理函数，响应传入的 HTTP 请求。
   * @param {Request} request - 传入的 HTTP 请求对象。
   * @param {Env} env - 环境变量对象，包含 D1 数据库绑定。
   * @param {ExecutionContext} ctx - 执行上下文。
   * @returns {Response} HTTP 响应。
   */
  async fetch(request, env, ctx) {
    // 1. 只允许 POST 请求
    if (request.method !== 'POST') {
      console.warn(`Received unsupported method: ${request.method}. Only POST is allowed.`);
      return new Response(JSON.stringify({ status: "error", message: "只支持 POST 请求" }), {
        headers: { 'Content-Type': 'application/json' },
        status: 405 // Method Not Allowed
      });
    }

    // 对于 POST 请求，通常期望请求体是 JSON 格式，检查 Content-Type
    const contentType = request.headers.get("content-type") || "";
    if (!contentType.includes("application/json")) {
        console.warn(`Received unsupported Content-Type: ${contentType}. Expected application/json.`);
        return new Response(JSON.stringify({ status: "error", message: "Content-Type 必须是 application/json" }), {
            headers: { 'Content-Type': 'application/json' },
            status: 415 // Unsupported Media Type
        });
    }

    // 虽然当前逻辑不需要请求体，但如果将来有需要，可以在这里读取
    // let requestBody;
    // try {
    //     requestBody = await request.json();
    //     // 例如，可以根据 requestBody 中的参数来定制密钥生成，
    //     // 比如 requestBody.modulusLength 等。
    // } catch (e) {
    //     console.error("Error parsing request body as JSON:", e);
    //     return new Response(JSON.stringify({ status: "error", message: "请求体解析为 JSON 失败" }), {
    //         headers: { 'Content-Type': 'application/json' },
    //         status: 400
    //     });
    // }


    let uuid, publicKeyPem, privateKeyPem;
    let publicJwk, privateJwk; // JWK 格式的密钥（用于响应，不存储在 D1）

    try {
      // 2. 生成 UUID (使用 Worker 环境内置的 randomUUID())
      uuid = self.crypto.randomUUID(); 

      // 3. 生成 RSA 密钥对
      const keyPair = await crypto.subtle.generateKey(
        {
          name: "RSA-OAEP",          // 算法名称
          modulusLength: 2048,       // 密钥长度，2048位是常用安全长度
          publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 公开指数 (65537)
          hash: "SHA-256",           // 哈希算法
        },
        true,                        // extractable: 密钥是否可以导出
        ["encrypt", "decrypt"]       // keyUsages: 公钥用于加密，私钥用于解密
      );

      // 导出 PEM 格式的公钥和私钥
      publicKeyPem = toPem(await crypto.subtle.exportKey("spki", keyPair.publicKey), 'public');
      privateKeyPem = toPem(await crypto.subtle.exportKey("pkcs8", keyPair.privateKey), 'private');

      // 导出 JWK 格式的公钥和私钥 (仅用于响应，不存储在 D1)
      publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
      privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);

    } catch (keyGenError) {
      console.error(`Error generating UUID or RSA key pair: ${keyGenError.message}`, keyGenError);
      return new Response(JSON.stringify({
        status: "error",
        message: `生成 UUID 或 RSA 密钥对失败: ${keyGenError.message}`
      }), {
        headers: { 'Content-Type': 'application/json' },
        status: 500 // Internal Server Error
      });
    }

    // 4. 将 UUID、PEM 格式的公钥和私钥写入 D1 数据库
    // 'env.insert' 是通过 Cloudflare Dashboard 配置的 D1 数据库绑定名称
    try {
      // 增强的错误检查 A：D1 数据库绑定是否存在且有效
      if (!env.insert || typeof env.insert.prepare !== 'function') {
        const errMsg = "D1 数据库绑定 'insert' 未正确初始化或缺失。请检查 wrangler.toml 或 Cloudflare Dashboard 配置。";
        console.error(errMsg, { db_binding: env.insert });
        return new Response(JSON.stringify({
          status: "error",
          message: errMsg,
          db_error_code: "D1_BINDING_MISSING"
        }), {
          headers: { 'Content-Type': 'application/json' },
          status: 500
        });
      }

      // 准备 SQL INSERT 语句
      const stmt = env.insert.prepare(
        "INSERT INTO keys (uuid, public_key, private_key) VALUES (?, ?, ?)"
      );

      // 绑定参数并执行插入操作
      const result = await stmt.bind(uuid, publicKeyPem, privateKeyPem).run();

      // 增强的错误检查 B：D1 插入操作是否成功
      if (result.success) {
        // 5. 成功响应：返回 UUID 和所有密钥格式
        console.log(`Successfully saved UUID: ${uuid} to D1.`);
        return new Response(JSON.stringify({
          status: "success",
          message: "UUID 和 RSA 密钥对生成并保存成功。",
          uuid: uuid,
          public_key_pem: publicKeyPem,  // PEM 格式公钥
          private_key_pem: privateKeyPem, // PEM 格式私钥
          public_key_jwk: publicJwk,     // JWK 格式公钥
          private_key_jwk: privateJwk    // JWK 格式私钥 (再次强调：私钥 JWK 不应在生产环境中返回给客户端)
        }), {
          headers: { 'Content-Type': 'application/json' },
          status: 200 // OK
        });
      } else {
        // D1 插入操作失败，但未抛出异常（例如：数据完整性约束，如重复的主键）
        const errMsg = "UUID 和 RSA 密钥对生成成功，但写入 D1 数据库失败。";
        console.error(`${errMsg} D1 result indicated failure:`, result.error);
        return new Response(JSON.stringify({
          status: "error",
          message: errMsg,
          db_error: result.error || "未知 D1 数据库错误。",
          db_error_code: "D1_INSERT_FAILED",
          uuid: uuid, // 仍返回已生成的 UUID 和密钥，以便调试
        }), {
          headers: { 'Content-Type': 'application/json' },
          status: 500
        });
      }

    } catch (dbError) {
      // 增强的错误检查 C：D1 插入操作抛出异常
      // D1 插入操作抛出异常（例如：数据库连接问题、SQL 语法错误等）
      const errMsg = "UUID 和 RSA 密钥对生成成功，但写入 D1 数据库时发生意外错误。";
      console.error(`${errMsg} Caught D1 error: ${dbError.message}`, dbError);
      return new Response(JSON.stringify({
        status: "error",
        message: errMsg,
        db_error: dbError.message || dbError, // 返回具体的错误信息
        db_error_code: "D1_UNEXPECTED_ERROR",
        uuid: uuid, // 仍返回已生成的 UUID 和密钥，以便调试
      }), {
        headers: { 'Content-Type': 'application/json' },
        status: 500
      });
    }
  },
};
