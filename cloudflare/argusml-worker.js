/**
 * ArgusML Threat Intelligence Ingest Worker
 * Accepts PQC encrypted threat intel from ArgusML IDPS
 * Stores to argusml-logs R2 bucket
 * Built by Juan Manuel De La Garza
 * Apache 2.0 License
 */

export default {
  async fetch(request, env) {
    if (request.method !== "POST") {
      return new Response(JSON.stringify({
        name: "ArgusML Threat Intel Ingest",
        version: "1.0.0",
        status: "operational",
        algorithms: ["ML-KEM-768", "ML-DSA-65", "AES-256-GCM"],
      }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");

    try {
      const body = await request.arrayBuffer();

      if (body.byteLength === 0) {
        return new Response(JSON.stringify({ status: "error", message: "Empty body" }), { status: 400 });
      }

      // Store PQC encrypted bundle to R2
      const key = `threats/${timestamp}-${Math.random().toString(36).substr(2, 8)}.pqc`;

      await env.ARGUSML_LOGS.put(key, body, {
        httpMetadata: {
          contentType: "application/octet-stream",
        },
        customMetadata: {
          source: "ArgusML",
          timestamp: new Date().toISOString(),
          size: String(body.byteLength),
          encryption: "ML-KEM-768+ML-DSA-65+AES-256-GCM",
        },
      });

      return new Response(JSON.stringify({
        status: "ok",
        key: key,
        size: body.byteLength,
        source: "ArgusML",
        encryption: "ML-KEM-768+ML-DSA-65+AES-256-GCM",
      }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });

    } catch (err) {
      return new Response(JSON.stringify({
        status: "error",
        message: err.message,
      }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
  }
};
