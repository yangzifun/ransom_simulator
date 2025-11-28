/**
 * Cloudflare Worker for a Simulated C2 Server
 * 
 * Listens for beacons from the ransomware simulator, logs the connection details,
 * and provides a simple acknowledgement.
 */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // --- C2 Beacon Logic ---
    // We check if the request path matches our expected beacon endpoint.
    if (url.pathname === '/beacon_check_in') {
      
      // 1. Collect data from the incoming request (these are our IOCs)
      const clientIp = request.headers.get('CF-Connecting-IP');
      const userAgent = request.headers.get('User-Agent');
      const timestamp = new Date().toISOString();

      // 2. Create a structured JSON log object. This is much better than a simple string.
      const beaconData = {
        message: "C2 Beacon Received",
        timestamp: timestamp,
        source_ip: clientIp,
        user_agent: userAgent,
        url: request.url,
        method: request.method,
        // You can get more details from the 'request.cf' object if needed
        // country: request.cf.country, 
        // colo: request.cf.colo,
      };

      // 3. Log the data. This is the most important step.
      // In the Cloudflare Dashboard, you can view these logs in real-time.
      console.log(JSON.stringify(beaconData));

      // 4. Send a response back to the Go program.
      // A simple JSON response is professional and easy to parse.
      return new Response(JSON.stringify({ status: 'ok', message: 'Beacon acknowledged' }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // --- Default "Catch-All" Response ---
    // If the path is not for our beacon, return a generic message.
    // This prevents directory listing or exposing that this is a C2 server.
    return new Response('Service is online.', { status: 200 });
  },
};
