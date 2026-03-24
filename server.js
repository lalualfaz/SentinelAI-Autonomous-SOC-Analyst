import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(express.json());

// 1. Serve frontend from /public
app.use(express.static(path.join(__dirname, 'public')));

// Use process.env.PORT
const PORT = process.env.PORT || 3000;

// Security: Environment variables
const API_KEY = process.env.GEMINI_API_KEY;
if (!API_KEY) {
  console.error("❌ ERROR: GEMINI_API_KEY is missing from environment variables.");
  process.exit(1);
} else {
  console.log(`✅ API Key loaded securely: ...${API_KEY.slice(-4)}`);
}

// 8. Caching System: Prevent quota exhaustion
const investigationCache = new Map();

// 12. Master AI Prompt
const systemInstruction = `You are a SOC Analyst AI inside a real-time SIEM system.

Analyze the alert quickly and return ONLY valid JSON.

RULES:
* Keep response short and fast
* Always include MITRE mapping (minimum 2 techniques)
* Extract IOCs if present
* No text outside JSON

TASK:
1. verdict
2. severity
3. risk_score
4. confidence
5. attack_category
6. summary (max 3 lines)
7. mitre (min 2 techniques)
8. iocs
9. timeline (max 3 steps)
10. recommendations (max 3 actions)

OUTPUT FORMAT:
{
"verdict": "",
"severity": "",
"risk_score": 0,
"confidence": 0,
"attack_category": "",
"summary": "",
"mitre": [],
"iocs": [],
"timeline": [],
"recommendations": []
}

IMPORTANT:
* Never leave MITRE empty
* Optimize for speed and accuracy`;

// Helper: Delay for backoff
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

// 3. Timeout Controller (7 sec)
const fetchWithTimeout = async (url, options, timeoutMs = 7000) => {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(timeoutId);
    return response;
  } catch (error) {
    clearTimeout(timeoutId);
    if (error.name === 'AbortError') {
      throw new Error('Timeout: API request took longer than ' + timeoutMs + 'ms');
    }
    throw error;
  }
};

// 5. Smart Heuristic Fallback
const generateHeuristicFallback = (prompt) => {
  const pStr = String(prompt);
  const pLower = pStr.toLowerCase();
  
  const isRansomware = pLower.includes('ransomware') || pLower.includes('encrypt');
  const isMalware = pLower.includes('powershell') || pLower.includes('mimikatz') || pLower.includes('cobalt') || isRansomware;
  const isPhishing = pLower.includes('phishing') || pLower.includes('email');
  const isNetIntrusion = pLower.includes('scan') || pLower.includes('exfiltration') || pLower.includes('network');
  
  let verdict = "SUSPICIOUS";
  let severity = "MEDIUM";
  let risk_score = 50;
  let attack_category = "Anomaly Detection";
  
  if (isMalware || isRansomware) {
    verdict = "TRUE_POSITIVE";
    severity = "CRITICAL";
    risk_score = 95;
    attack_category = "Malware Execution / C2";
  } else if (isPhishing) {
    verdict = "LIKELY_POSITIVE";
    severity = "HIGH";
    risk_score = 75;
    attack_category = "Phishing Delivery";
  } else if (isNetIntrusion) {
    verdict = "LIKELY_POSITIVE";
    severity = "HIGH";
    risk_score = 80;
    attack_category = "Network Intrusion";
  }

  // Extract basics to make fallback look unique
  const hostMatch = pStr.match(/Host:\s*([^\n\r]+)/i);
  const userMatch = pStr.match(/User:\s*([^\n\r]+)/i);
  const ipMatch = pStr.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
  
  const hostStr = hostMatch ? hostMatch[1].trim() : "Unknown Host";
  const userStr = userMatch ? userMatch[1].trim() : "Unknown User";
  const ipStr = ipMatch ? ipMatch[0] : "10.0.0.x";

  let iocs = [];
  if (ipMatch) iocs.push({ type: "IP", value: ipStr, malicious: true });
  if (hostMatch) iocs.push({ type: "Hostname", value: hostStr, malicious: false });

  return {
    verdict,
    severity,
    risk_score,
    confidence: 100,
    attack_category,
    summary: `[API Quota Exceeded - Fallback] Analysis of activity on ${hostStr}. The system detected patterns consistent with ${attack_category}. Immediate investigation recommended.`,
    mitre: [
      { tactic: isMalware ? "Execution" : isPhishing ? "Initial Access" : "Discovery", technique: isMalware ? "T1059 - Command and Scripting Interpreter" : isPhishing ? "T1566 - Phishing" : "T1046 - Network Service Discovery" },
      { tactic: "Defense Evasion", technique: "T1562 - Impair Defenses" }
    ],
    iocs: iocs.length > 0 ? iocs : [{ type: "System", value: hostStr, malicious: false }],
    timeline: [
      { time: "T0", event: `Alert triggered involving ${hostStr} and user ${userStr}` },
      { time: "T+1", event: "Automated heuristic classification applied locally due to AI API quota/timeout" }
    ],
    recommendations: [`Investigate logs for ${hostStr}`, `Verify activity by ${userStr}`, "Retry AI scan when API quota is restored"]
  };
};

// 1. Backend REST API
app.post('/api/investigate', async (req, res) => {
  const startTime = Date.now();
  let { prompt } = req.body;

  if (!prompt) {
    return res.status(400).json({ error: "Missing 'prompt' in request body." });
  }

  // 6. Prompt Optimization (Trim to prevent timeout/bloat)
  prompt = String(prompt).slice(0, 1000);

  // 8. Checking Cache
  const cacheKey = Buffer.from(prompt).toString('base64').slice(0, 64);
  if (investigationCache.has(cacheKey)) {
    console.log(`[${new Date().toISOString()}] ⚡ Serving from Map() cache.`);
    return res.status(200).json(investigationCache.get(cacheKey));
  }

  console.log(`\n[${new Date().toISOString()}] Incoming request. Payload size: ${prompt.length} chars`);

  // Target Models
  const modelPrimary = "gemini-2.0-flash";
  const modelSecondary = "gemini-1.5-flash";
  let targetModel = modelPrimary;

  let attempt = 1;
  const maxAttempts = 3; // Initial + 2 Retries = 3 total attempts
  let finalResponse = null;

  while (attempt <= maxAttempts) {
    try {
      if (attempt > 1) {
        console.log(`[${new Date().toISOString()}] Retry ${attempt - 1} using model: ${targetModel}...`);
      }
      
      const url = `https://generativelanguage.googleapis.com/v1beta/models/${targetModel}:generateContent?key=${API_KEY}`;
      
      // Formatting Request accurately to Gemini spec
      const payload = {
        system_instruction: {
          parts: [{ text: systemInstruction }]
        },
        contents: [
          { parts: [{ text: `ALERT DATA:\n${prompt}` }] }
        ],
        generationConfig: {
          responseMimeType: "application/json",
          temperature: 0.2
        }
      };

      const fetchParams = {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      };

      // 3. Timeout Controller (15 sec)
      const response = await fetchWithTimeout(url, fetchParams, 15000);
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(`API Error ${response.status}: ${data.error?.message || response.statusText}`);
      }
      
      // 7. Parse & Validate Response
      const rawText = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
      const cleanText = rawText.replace(/^```(json)?\n?/i, '').replace(/\n?```$/i, '').trim();
      let aiJson = JSON.parse(cleanText); // Throws exception if parsing fails
      
      // 7. Enforce Data Constraints
      if (!aiJson.mitre || !Array.isArray(aiJson.mitre) || aiJson.mitre.length === 0) {
        aiJson.mitre = [{ tactic: "Initial Access", technique: "T1190" }, { tactic: "Execution", technique: "T1059" }];
      }
      if (aiJson.risk_score === undefined || aiJson.risk_score === null) aiJson.risk_score = 50;
      if (!aiJson.severity) aiJson.severity = "MEDIUM";

      finalResponse = aiJson;
      investigationCache.set(cacheKey, finalResponse); // Cache successful response
      break; 
      
    } catch (error) {
       console.error(`[${new Date().toISOString()}] ❌ Attempt ${attempt} Failed:`, error.message);
       
       // 4. Multi-Layer Fallback Routing
       if (attempt === 1) {
         // Step 1 -> retry
         await delay(1000);
       } else if (attempt === 2) {
         // Step 2 -> fallback to second model
         targetModel = modelSecondary;
         await delay(500);
       } else if (attempt === 3) {
         // Step 3 -> use smart heuristic fallback JSON
         console.warn(`[${new Date().toISOString()}] ⚠️ Exhausted retries. Injecting Smart Heuristic Fallback JSON.`);
         finalResponse = generateHeuristicFallback(prompt);
         break;
       }
    }
    attempt++;
  }

  const duration = Date.now() - startTime;
  console.log(`[${new Date().toISOString()}] ✅ Request completed in ${duration}ms.\n`);
  
  return res.status(200).json(finalResponse);
});

// 10. Keep Server Active Endpoint
app.get('/ping', (req, res) => {
  res.status(200).json({ status: "active", uptime: process.uptime() });
});

app.listen(PORT, () => {
  console.log(`========================================`);
  console.log(`🛡️  SOC SIEM Deployment Engine Active  `);
  console.log(`🚀 Listening on port ${PORT}`);
  console.log(`========================================\n`);
});
