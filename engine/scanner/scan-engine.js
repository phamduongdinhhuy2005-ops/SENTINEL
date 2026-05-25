/* global module */
// engine/scanner/scan-engine.js
// ── Sentinel v2 — Upgraded: Attack Surface scoring, Tech Stack fingerprint, Stop signal, URL dedup

const path = require('path');

const { validatePublicHttpUrl } = require('../utils/url');
const { toHeaderObject, buildRequestHeaders, summarizeAuth } = require('../utils/http');
const { responseFingerprint } = require('../utils/diff');

const { extractForms, extractLinks } = require('../collectors/blackbox/crawler');
const { probeOptions, probeMissingPath } = require('../collectors/blackbox/request-prober');
const { detectAuthHints } = require('../collectors/blackbox/auth-flow-collector');
const { detectVerboseErrors } = require('../collectors/blackbox/error-collector');

const { runUrlRules, runProjectRules } = require('./rule-engine');
const { runDynamicFuzzing } = require('./fuzzer');
const { summarizeFindings } = require('../report/report-engine');

const { walkFiles, readTextSafe } = require('../collectors/source/project-loader');
const { collectDependencyArtifacts } = require('../collectors/source/dependency-scanner');
const { collectConfigFiles, collectCiFiles } = require('../collectors/source/config-scanner');
const { collectTextFiles } = require('../collectors/source/secret-scanner');
const { collectCodeFiles } = require('../collectors/source/logging-scanner');

const { getDesignChecklist } = require('../collectors/checklist/design-checklist');
const { normalizeFinding } = require('../models/finding');
const { ScannerHttpClient } = require('../utils/http-client');

// ── Constants ────────────────────────────────────────────────────────────────
const PROBE_ROUTES = [
  '/admin', '/administrator', '/swagger', '/swagger-ui', '/swagger-ui.html',
  '/api-docs', '/api/v1', '/api/v2', '/api/v3',
  '/debug', '/actuator', '/actuator/health', '/actuator/env', '/actuator/info',
  '/metrics', '/health', '/healthz', '/ready',
  '/phpinfo.php', '/.env', '/.git/config', '/.git/HEAD',
  '/config', '/graphql', '/console', '/web.config',
  '/server-status', '/server-info', '/.htaccess',
  '/ftp', '/rest/admin/application-configuration',
];

const STATIC_EXT_RE = /\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|mp4|webp|pdf|zip|gz|bmp|map)(\?.*)?$/i;
const MAX_CRAWL_URLS = 40;

// ── Tech Stack Fingerprint ────────────────────────────────────────────────────
const TECH_SIGNATURES = [
  { name: 'WordPress',  re: /wp-content|wp-includes|wordpress/i,      header: null },
  { name: 'Laravel',    re: /laravel_session|X-Powered-By: PHP/i,      header: 'x-powered-by', headerRe: /php/i },
  { name: 'Django',     re: /csrfmiddlewaretoken|django/i,             header: null },
  { name: 'Rails',      re: /X-Runtime|_rails_session/i,               header: 'x-runtime', headerRe: /.+/ },
  { name: 'Next.js',    re: /__NEXT_DATA__|_next\/static/i,             header: null },
  { name: 'Nuxt.js',    re: /_nuxt\/|__nuxt/i,                         header: null },
  { name: 'Angular',    re: /ng-version|angular/i,                      header: null },
  { name: 'React',      re: /react\.|__reactFiber|ReactDOM/i,           header: null },
  // BUG FIX: Phiên bản cũ: /vue\.js|__vue__|v-app|nuxt/i
  // `nuxt` đã có trong Nuxt.js signature → Vue.js regex chứa `nuxt` khiến app Nuxt.js
  // bị detect là CẢ HAI "Vue.js" lẫn "Nuxt.js" (double detection).
  // FIX: Bỏ `nuxt` khỏi Vue.js regex.
  { name: 'Vue.js',     re: /vue\.js|__vue__|v-app/i,                   header: null },
  { name: 'Spring Boot',re: /Whitelabel Error Page|spring/i,           header: 'x-application-context', headerRe: /.+/ },
  { name: 'Express.js', re: null,                                       header: 'x-powered-by', headerRe: /express/i },
  { name: 'ASP.NET',    re: /__VIEWSTATE|__doPostBack|WebFormsBundle/i, header: 'x-powered-by', headerRe: /asp\.net/i },
  { name: 'PHP',        re: null,                                       header: 'x-powered-by', headerRe: /php/i },
  { name: 'Nginx',      re: null,                                       header: 'server', headerRe: /nginx/i },
  { name: 'Apache',     re: null,                                       header: 'server', headerRe: /apache/i },
  { name: 'IIS',        re: null,                                       header: 'server', headerRe: /iis/i },
  { name: 'Cloudflare', re: null,                                       header: 'cf-ray', headerRe: /.+/ },
];

function detectTechStack(text, headers) {
  const detected = new Set();
  for (const sig of TECH_SIGNATURES) {
    if (sig.re && text && sig.re.test(text)) { detected.add(sig.name); continue; }
    if (sig.header && sig.headerRe) {
      const val = headers.get ? headers.get(sig.header) : (headers[sig.header] || '');
      if (val && sig.headerRe.test(val)) detected.add(sig.name);
    }
  }
  return Array.from(detected);
}

// ── Attack Surface Scoring ────────────────────────────────────────────────────
const SURFACE_WEIGHTS = {
  '/admin': 3, '/administrator': 3, '/console': 3,
  '/swagger': 2, '/swagger-ui': 2, '/swagger-ui.html': 2, '/api-docs': 2,
  '/actuator': 2, '/actuator/env': 4, '/actuator/health': 1,
  '/graphql': 2, '/debug': 3,
  '/.env': 5, '/.git/config': 5, '/.git/HEAD': 4, '/.htaccess': 3, '/web.config': 4,
  '/phpinfo.php': 4, '/server-status': 3, '/server-info': 3,
  '/ftp': 3, '/rest/admin/application-configuration': 3,
  '/api/v1': 1, '/api/v2': 1, '/api/v3': 1,
};

function isConfirmedExposed(info) {
  return !!info &&
    (info.status === 200 || (info.status >= 300 && info.status < 400 && !info.redirectedToLogin)) &&
    info.isExposed !== false;
}

function computeAttackSurface(surfaceStatus, crawledCount, formsCount) {
  const exposed = [];
  let score = 0;

  for (const [route, info] of Object.entries(surfaceStatus)) {
    if (isConfirmedExposed(info)) {
      const w = SURFACE_WEIGHTS[route] || 1;
      score += w;
      exposed.push({ route, status: info.status, weight: w });
    }
  }

  // Bonus surface from crawl size and forms
  score += Math.min(crawledCount / 5, 10);
  score += Math.min(formsCount * 2, 10);

  return {
    score: Math.round(Math.min(score, 100)),
    exposedRoutes: exposed.sort((a, b) => b.weight - a.weight),
  };
}

// ── CSP Analysis ─────────────────────────────────────────────────────────────
function analyzeCsp(headers) {
  const csp = headers.get ? headers.get('content-security-policy') : (headers['content-security-policy'] || '');
  if (!csp) return { present: false, issues: ['Content-Security-Policy header absent'] };

  const issues = [];
  if (/unsafe-inline/i.test(csp))  issues.push("'unsafe-inline' allows inline script execution");
  if (/unsafe-eval/i.test(csp))    issues.push("'unsafe-eval' allows eval() — XSS risk");
  if (/\*/i.test(csp))             issues.push("Wildcard (*) in CSP source — too permissive");
  if (/data:/i.test(csp))          issues.push("data: URI scheme allowed — XSS vector");

  return { present: true, value: csp, issues };
}

// ── Route probing ─────────────────────────────────────────────────────────────
// BUG FIX: Phiên bản cũ không truyền `abortSignal` vào client.request() bên trong.
// → Nhấn "Stop Scan" không cancel được giai đoạn probe route.
// FIX: Thêm tham số abortSignal và truyền vào signal của mỗi request.
function bodyPreview(text, limit = 180) {
  return String(text || '').replace(/\s+/g, ' ').trim().slice(0, limit);
}

function looksLikeHtmlAppShell(text, contentType) {
  const body = String(text || '');
  const ct = String(contentType || '').toLowerCase();
  if (!ct.includes('html')) return false;
  return /<html[\s>]/i.test(body) &&
    /<script[^>]+src=|<app-root|<base href=|main\.[\w-]+\.js|runtime\.[\w-]+\.js/i.test(body);
}

function classifyProbeRoute(route, status, contentType, text) {
  if (status < 200 || status >= 400) return { isExposed: false, reason: `HTTP ${status}` };
  if (status >= 300 && status < 400) return { isExposed: true, reason: 'Redirects without an obvious login gate' };

  const body = String(text || '');
  const ct = String(contentType || '').toLowerCase();
  const htmlShell = looksLikeHtmlAppShell(body, ct);

  const routeChecks = [
    { re: /^\/\.env/i, match: /(?:^|\n)\s*[A-Z0-9_]{3,}\s*=\s*.+/m, reason: 'Response looks like an env file' },
    { re: /^\/\.git\/config/i, match: /\[core\]|\[remote\s+"origin"\]|repositoryformatversion/i, reason: 'Response looks like .git/config' },
    { re: /^\/\.git\/HEAD/i, match: /^ref:\s+refs\/heads\/|^[0-9a-f]{40}\s*$/im, reason: 'Response looks like .git/HEAD' },
    { re: /phpinfo\.php$/i, match: /phpinfo\(\)|PHP Version|<title>\s*phpinfo\(\)/i, reason: 'Response contains phpinfo output' },
    { re: /web\.config$/i, match: /<configuration[\s>]|<system\.webServer[\s>]/i, reason: 'Response looks like web.config XML' },
    { re: /\.htaccess$/i, match: /RewriteEngine|AuthType|Require all|Deny from|Allow from/i, reason: 'Response looks like .htaccess' },
    { re: /^\/actuator(?:\/|$)/i, match: /"_links"\s*:|"propertySources"\s*:|"activeProfiles"\s*:|"contexts"\s*:|management\.endpoints/i, reason: 'Response looks like Spring Actuator JSON' },
    { re: /^\/graphql$/i, match: /"errors"\s*:|"data"\s*:|Cannot query field|GraphQL/i, reason: 'Response looks like GraphQL output' },
    { re: /^\/swagger|^\/api-docs/i, match: /swagger-ui|openapi["\s:]+3|swagger["\s:]+["']?2|Swagger UI/i, reason: 'Response looks like Swagger/OpenAPI' },
    { re: /^\/server-status/i, match: /Apache Server Status|Server Version|Current Time|Restart Time/i, reason: 'Response looks like Apache server-status' },
    { re: /^\/server-info/i, match: /Apache Server Information|Module Name|Server Settings/i, reason: 'Response looks like Apache server-info' },
    { re: /^\/ftp$/i, match: /<title>\s*listing directory|Index of\s+\/ftp|href=["'][^"']+\.(?:pdf|md|bak|zip)/i, reason: 'Response looks like a directory listing' },
    { re: /^\/rest\/admin\/application-configuration$/i, match: /"config"\s*:\s*\{|"application"\s*:\s*\{|"server"\s*:\s*\{/i, reason: 'Response contains application configuration JSON' },
  ];

  const specific = routeChecks.find((check) => check.re.test(route));
  if (specific) {
    return specific.match.test(body)
      ? { isExposed: true, reason: specific.reason }
      : { isExposed: false, reason: htmlShell ? 'SPA fallback page, not the requested sensitive resource' : 'Missing expected content signature' };
  }

  if (htmlShell) return { isExposed: false, reason: 'SPA fallback page, not confirmed sensitive endpoint' };
  return { isExposed: true, reason: 'HTTP 200 with non-SPA response' };
}

async function probeRoutesEnhanced(origin, requestHeaders, client, abortSignal) {
  const surfaceStatus = {};
  const BATCH = 12;

  for (let i = 0; i < PROBE_ROUTES.length; i += BATCH) {
    if (abortSignal?.aborted) break;
    const batch = PROBE_ROUTES.slice(i, i + BATCH);
    await Promise.all(batch.map(async (route) => {
      if (abortSignal?.aborted) return;
      try {
        const res = await client.request(`${origin}${route}`, {
          method: 'GET',
          headers: requestHeaders,
          redirect: 'manual',
          signal: abortSignal,   // FIX: truyền signal để có thể abort
        });
        const location = res.response.headers.get('location') || '';
        const contentType = res.response.headers.get('content-type') || '';
        const exposure = classifyProbeRoute(route, res.response.status, contentType, res.text);
        surfaceStatus[route] = {
          status: res.response.status,
          redirectedToLogin: res.response.status >= 300 && res.response.status < 400 && /login|signin|account|auth/i.test(location),
          location,
          server:      res.response.headers.get('server')       || '',
          contentType,
          size:        res.text.length,
          bodySnippet: bodyPreview(res.text),
          isExposed: exposure.isExposed,
          exposureReason: exposure.reason,
        };
      } catch {
        surfaceStatus[route] = { status: 0, redirectedToLogin: false, location: '' };
      }
    }));
  }
  return surfaceStatus;
}

function extractServerFingerprint(headers) {
  return {
    server:           headers.get('server')              || '',
    poweredBy:        headers.get('x-powered-by')        || '',
    aspNetVersion:    headers.get('x-aspnet-version')    || '',
    aspNetMvcVersion: headers.get('x-aspnetmvc-version') || '',
    via:              headers.get('via')                 || '',
  };
}

function checkVersionDisclosure(fingerprint, context) {
  const findings = [];
  const patterns = [
    { field: 'server',        re: /apache\/[\d.]+|nginx\/[\d.]+|iis\/[\d.]+/i, label: 'Server version' },
    { field: 'poweredBy',     re: /php\/[\d.]+|asp\.net|express/i,             label: 'Technology version (X-Powered-By)' },
    { field: 'aspNetVersion', re: /.+/,                                         label: 'ASP.NET version (X-AspNet-Version)' },
  ];
  for (const pat of patterns) {
    const value = fingerprint[pat.field];
    if (value && pat.re.test(value)) {
      findings.push(normalizeFinding({
        ruleId: 'A02-FINGER-001', owaspCategory: 'A02',
        title: `${pat.label} lộ trong response header`,
        severity: 'low', confidence: 'high',
        target: context.finalUrl, location: 'response header',
        evidence: [`${pat.field}: ${value}`],
        remediation: 'Ẩn version information trong server headers.',
        references: ['https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/'],
        collector: 'blackbox',
      }));
      break;
    }
  }
  return findings;
}

function runGraphQlExposure(context) {
  const gql = (context.surfaceStatus || {})['/graphql'];
  if (isConfirmedExposed(gql)) {
    return [normalizeFinding({
      ruleId: 'A02-GRAPHQL-001', owaspCategory: 'A02',
      title: 'GraphQL endpoint public không có auth check rõ ràng',
      severity: context.isLocalhost ? 'low' : 'medium', confidence: 'medium',
      target: `${context.origin}/graphql`, location: '/graphql',
      evidence: ['/graphql trả về HTTP 200 — kiểm tra introspection có bị disable không'],
      remediation: 'Disable GraphQL introspection trên production. Implement authentication và query depth limiting.',
      references: ['https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html'],
      collector: 'blackbox',
    })];
  }
  return [];
}

function runGitExposure(surfaceStatus, origin) {
  const git = surfaceStatus['/.git/config'] || surfaceStatus['/.git/HEAD'];
  if (isConfirmedExposed(git)) {
    return [normalizeFinding({
      ruleId: 'A02-GIT-001', owaspCategory: 'A02',
      title: '.git directory exposed — source code có thể bị leak',
      severity: 'critical', confidence: 'high',
      target: `${origin}/.git/`, location: '/.git/',
      evidence: ['/.git/config hoặc /.git/HEAD trả về HTTP 200'],
      remediation: 'Block truy cập vào thư mục .git qua web server config. Dùng .htaccess hoặc nginx deny rules.',
      references: ['https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/'],
      collector: 'blackbox',
    })];
  }
  return [];
}

function runEnvExposure(surfaceStatus, origin) {
  const env = surfaceStatus['/.env'];
  if (isConfirmedExposed(env)) {
    return [normalizeFinding({
      ruleId: 'A02-ENV-001', owaspCategory: 'A02',
      title: '.env file exposed — credentials/secrets có thể bị leak',
      severity: 'critical', confidence: 'high',
      target: `${origin}/.env`, location: '/.env',
      evidence: ['/.env trả về HTTP 200 — chứa database credentials, API keys'],
      remediation: 'Đặt .env ngoài webroot. Dùng server config để block *.env. Rotate tất cả secrets ngay lập tức.',
      references: ['https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/'],
      collector: 'blackbox',
    })];
  }
  return [];
}

function runActuatorExposure(surfaceStatus, origin) {
  const dangerous = ['/actuator/env', '/actuator'];
  const findings = [];
  for (const route of dangerous) {
    if (isConfirmedExposed(surfaceStatus[route])) {
      findings.push(normalizeFinding({
        ruleId: 'A02-ACTUATOR-001', owaspCategory: 'A02',
        title: `Spring Boot Actuator endpoint ${route} exposed`,
        severity: 'high', confidence: 'high',
        target: `${origin}${route}`, location: route,
        evidence: [`${route} trả về HTTP 200 — có thể expose env vars, heap dumps, beans`],
        remediation: 'Bảo vệ actuator endpoints bằng Spring Security. Disable management.endpoints.web.exposure.include=*.',
        references: ['https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/'],
        collector: 'blackbox',
      }));
    }
  }
  return findings;
}

function runVerifiedExposureChecks(context) {
  const surfaceStatus = context.surfaceStatus || {};
  const findings = [];
  const ftp = surfaceStatus['/ftp'];
  if (isConfirmedExposed(ftp)) {
    findings.push(normalizeFinding({
      ruleId: 'A05-DIRLIST-VERIFIED-001',
      owaspCategory: 'A05',
      title: 'Public directory listing is reachable',
      severity: context.isLocalhost ? 'low' : 'medium',
      confidence: 'high',
      target: `${context.origin}/ftp`,
      location: '/ftp',
      evidence: [
        ftp.exposureReason || '/ftp returned a directory listing',
        ftp.bodySnippet ? `Body preview: ${ftp.bodySnippet}` : '',
      ].filter(Boolean),
      remediation: 'Disable directory listing and require authorization for downloadable files that should not be public.',
      references: ['https://owasp.org/Top10/2025/A05_2025-Security_Misconfiguration/'],
      collector: 'blackbox',
    }));
  }

  const config = surfaceStatus['/rest/admin/application-configuration'];
  if (isConfirmedExposed(config)) {
    findings.push(normalizeFinding({
      ruleId: 'A01-CONFIG-EXPOSURE-001',
      owaspCategory: 'A01',
      title: 'Application configuration endpoint is publicly readable',
      severity: context.isLocalhost ? 'low' : 'medium',
      confidence: 'high',
      target: `${context.origin}/rest/admin/application-configuration`,
      location: '/rest/admin/application-configuration',
      evidence: [
        config.exposureReason || 'Application configuration endpoint returned JSON',
        config.bodySnippet ? `Body preview: ${config.bodySnippet}` : '',
      ].filter(Boolean),
      remediation: 'Require server-side authorization for admin/configuration endpoints and avoid exposing deployment details to anonymous users.',
      references: ['https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/'],
      collector: 'blackbox',
    }));
  }

  return findings;
}

function getUrlScanCoverageNotes(context) {
  const auth = context.authSummary || {};
  const notes = [
    'URL Scan chỉ quan sát ứng dụng đang chạy qua HTTP request/response. Các lỗi cần đăng nhập, đổi role, thao tác giỏ hàng/checkout, upload hoặc flow nhiều bước có thể chưa được kích hoạt.',
    'Ứng dụng SPA có nhiều API ẩn trong JavaScript hoặc chỉ gọi sau hành động UI. Nếu crawler không đi tới flow đó, scanner sẽ không có endpoint để fuzz.',
    'Business logic, anti-automation/captcha, security-through-obscurity và lỗi phụ thuộc trạng thái dữ liệu thường cần kịch bản kiểm thử có trạng thái, không thể kết luận chỉ từ scan nặc danh.',
    'Một số finding dạng SSRF/header/proxy là heuristic. Cần xác minh bằng log server hoặc endpoint nội bộ trước khi xem là khai thác thành công.',
  ];
  if (!auth.hasCookie && !auth.hasBearerToken) {
    notes.unshift('Scan hiện không có cookie/token xác thực. Kết quả chủ yếu phản ánh bề mặt public, nên các lỗi sau đăng nhập có thể bị bỏ sót.');
  }
  return notes;
}

function getProjectScanCoverageNotes(context) {
  const notes = [
    'Project Scan là phân tích tĩnh/heuristic: tìm pattern rủi ro trong mã nguồn và config, nhưng không chứng minh chắc chắn endpoint có khai thác được ở runtime.',
    'Các lỗi phụ thuộc dữ liệu seed, trạng thái phiên, role người dùng, checkout/payment, captcha hoặc chuỗi hành động nhiều bước vẫn cần URL scan có auth hoặc test case chuyên biệt.',
    'Scanner bỏ qua thư mục nặng như node_modules, dist, build và có giới hạn số file đọc để tránh treo trên project lớn. Có thể tăng SENTINEL_PROJECT_MAX_FILES và SENTINEL_PROJECT_MAX_CODE_FILES khi cần quét sâu hơn.',
    'Repo benchmark hoặc intentionally vulnerable app thường chứa cả test fixture/codefix. Findings trong thư mục test/codefix nên được phân loại lại trước khi tính là lỗi production.',
  ];
  if ((context.files || []).length >= Number.parseInt(process.env.SENTINEL_PROJECT_MAX_FILES || '2500', 10)) {
    notes.unshift('Project có thể đã chạm giới hạn số file được walk. Một phần mã nguồn phía sau giới hạn có thể chưa được phân tích.');
  }
  return notes;
}

function detectProjectTechStack(context) {
  const detected = new Set();
  const packageJson = context.packageJson || '';
  const files = context.files || [];
  const joinedNames = files.map(f => String(f).toLowerCase()).join('\n');

  if (packageJson) {
    detected.add('Node.js');
    try {
      const pkg = JSON.parse(packageJson);
      const deps = {
        ...(pkg.dependencies || {}),
        ...(pkg.devDependencies || {}),
      };
      if (deps.react) detected.add('React');
      if (deps.next) detected.add('Next.js');
      if (deps.vue) detected.add('Vue.js');
      if (deps['@angular/core']) detected.add('Angular');
      if (deps.express) detected.add('Express.js');
      if (deps.electron) detected.add('Electron');
      if (deps.vite) detected.add('Vite');
    } catch {
      // Keep Node.js detection even when package.json is not parseable.
    }
  }

  if ((context.csprojFiles || []).length > 0 || /\.csproj\b|\.sln\b/.test(joinedNames)) detected.add('.NET');
  if (/pom\.xml|build\.gradle|gradlew|\.java\b/.test(joinedNames)) detected.add('Java');
  if (/spring|spring-boot/i.test((context.csprojFiles || []).map(f => f.content).join('\n') + joinedNames)) detected.add('Spring Boot');
  if (/composer\.json|artisan|\.php\b/.test(joinedNames)) detected.add('PHP');
  if (/composer\.json/.test(joinedNames) && /laravel/i.test(joinedNames + '\n' + (context.configFiles || []).map(f => f.content).join('\n'))) detected.add('Laravel');

  return Array.from(detected);
}

// ── URL SCAN ─────────────────────────────────────────────────────────────────
async function runUrlScan(inputUrl, options = {}) {
  const onProgress  = options.onProgress  || (() => {});
  const abortSignal = options.abortSignal  || null;
  const startTs     = Date.now();

  onProgress({ stage: 'crawl', msg: `Khởi tạo: ${inputUrl}`, level: 'info', ts: Date.now() });

  const allowPrivateTargets = process.env.SENTINEL_ALLOW_PRIVATE_TARGETS !== 'false';
  const parsed      = await validatePublicHttpUrl(inputUrl, { allowPrivate: allowPrivateTargets });
  const auth        = options.auth  || {};
  const maxDepth    = options.maxDepth  ?? 1;
  const maxBudget   = options.maxBudget ?? 30;
  const requestHeaders = buildRequestHeaders(auth);

  const hostname    = parsed.hostname.toLowerCase();
  const isLocalhost = ['localhost', '127.0.0.1', '::1'].includes(hostname) || hostname.endsWith('.local');

  const client = new ScannerHttpClient({
    timeoutMs:          options.timeoutMs  || 8000,
    maxRetries:         options.maxRetries || 1,
    concurrency:        options.concurrency || 12,
    requestDelayMs:     isLocalhost ? 0 : 60,
    rejectUnauthorized: !isLocalhost,
    validateUrl:        (url) => validatePublicHttpUrl(url, { allowPrivate: allowPrivateTargets }),
  });

  // ── STAGE 1: PARALLEL BFS CRAWL ──────────────────────────────
  const crawledUrls  = new Set();
  const urlQueue     = [parsed.toString()];
  let   currentDepth = 0;
  const allForms     = [];
  const allLinks     = new Set();

  onProgress({ stage: 'crawl', msg: `Đang crawl ${parsed.origin} (depth: ${maxDepth}, budget: ${maxBudget})…`, level: 'info', ts: Date.now() });

  while (urlQueue.length > 0 && currentDepth <= maxDepth && crawledUrls.size < MAX_CRAWL_URLS) {
    if (abortSignal?.aborted) break;

    const levelBatch = [];
    while (urlQueue.length > 0 && levelBatch.length < 20) {
      const u = urlQueue.shift();
      if (!crawledUrls.has(u) && !STATIC_EXT_RE.test(u)) {
        crawledUrls.add(u);
        levelBatch.push(u);
      }
    }

    const FETCH_BATCH = 6;
    for (let i = 0; i < levelBatch.length; i += FETCH_BATCH) {
      if (abortSignal?.aborted) break;
      await Promise.all(levelBatch.slice(i, i + FETCH_BATCH).map(async (urlToCrawl) => {
        try {
          onProgress({ stage: 'crawl', msg: `→ ${urlToCrawl}`, level: 'info', ts: Date.now() });
          const { text } = await client.request(urlToCrawl, { headers: requestHeaders, signal: abortSignal });
          extractForms(text).forEach(f => allForms.push(f));
          extractLinks(text, parsed.origin).forEach(l => {
            allLinks.add(l);
            if (!crawledUrls.has(l) && l.startsWith(parsed.origin) && !STATIC_EXT_RE.test(l))
              urlQueue.push(l);
          });
        } catch { /* ignore per-page errors */ }
      }));
    }
    currentDepth++;
  }

  onProgress({
    stage: 'crawl',
    msg: `Crawl xong: ${crawledUrls.size} trang · ${allForms.length} form · ${allLinks.size} link`,
    level: 'success', ts: Date.now(),
  });

  // ── Fetch main page ───────────────────────────────────────────
  const initialReq = await client.request(parsed.toString(), { headers: requestHeaders, signal: abortSignal }).catch(() => null);
  if (!initialReq) {
    await client.destroy();
    return { ok: false, error: 'Không thể kết nối tới URL', findings: [], metadata: { summary: { total: 0, byCategory: {}, bySeverity: {} } } };
  }

  const { response, text, finalUrl } = initialReq;
  const headers = response.headers;
  const setCookies = headers.getSetCookie
    ? headers.getSetCookie()
    : (headers.get('set-cookie') ? [headers.get('set-cookie')] : []);

  const authHints = detectAuthHints(text, toHeaderObject(headers));

  // ── STAGE 1b: PARALLEL PROBE + FINGERPRINT ────────────────────
  onProgress({ stage: 'probe', msg: `Đang probe ${PROBE_ROUTES.length} route + fingerprinting…`, level: 'info', ts: Date.now() });

  const [optionsProbe, missingPathProbeRaw, surfaceStatus] = await Promise.all([
    // BUG FIX: truyền `client` vào probeOptions và probeMissingPath
    // Phiên bản cũ bỏ qua `client`, dùng global fetch/defaultClient với timeout sai
    probeOptions(parsed.toString(), auth, client),
    probeMissingPath(parsed.origin, auth, client),
    // BUG FIX: truyền `abortSignal` để Stop Scan cancel được probe route
    probeRoutesEnhanced(parsed.origin, requestHeaders, client, abortSignal),
  ]);

  const accessibleCount = Object.values(surfaceStatus).filter(isConfirmedExposed).length;
  onProgress({
    stage: 'probe',
    msg: `Probe xong: ${accessibleCount}/${PROBE_ROUTES.length} route truy cập được`,
    level: accessibleCount > 5 ? 'warn' : 'success', ts: Date.now(),
  });

  const missingPathProbe = missingPathProbeRaw ? {
    url:              missingPathProbeRaw.url,
    status:           missingPathProbeRaw.response.status,
    hasVerboseErrors: detectVerboseErrors(missingPathProbeRaw.text),
    fingerprint:      responseFingerprint(missingPathProbeRaw.text),
  } : null;

  const cookieFlags = setCookies.map(raw => {
    const lower = raw.toLowerCase();
    return {
      raw, httpOnly: lower.includes('httponly'), secure: lower.includes('secure'),
      sameSite: lower.includes('samesite=strict') ? 'Strict' : lower.includes('samesite=lax') ? 'Lax' : lower.includes('samesite=none') ? 'None' : '',
    };
  });

  const fingerprint = extractServerFingerprint(headers);
  const probeResults = Object.entries(surfaceStatus).map(([route, info]) => ({
    route,
    url: `${parsed.origin}${route}`,
    status: info.status,
    contentType: info.contentType || '',
    bodySnippet: info.bodySnippet || '',
    isExposed: info.isExposed,
    exposureReason: info.exposureReason || '',
  }));

  // ── Tech Stack + Attack Surface + CSP ────────────────────────
  const techStack     = detectTechStack(text, headers);
  const cspAnalysis   = analyzeCsp(headers);
  const attackSurface = computeAttackSurface(surfaceStatus, crawledUrls.size, allForms.length);

  if (techStack.length > 0) {
    onProgress({ stage: 'probe', msg: `Tech stack: ${techStack.join(', ')}`, level: 'info', ts: Date.now() });
  }
  onProgress({ stage: 'probe', msg: `Điểm attack surface: ${attackSurface.score}/100`, level: attackSurface.score > 40 ? 'warn' : 'info', ts: Date.now() });

  const pageTitle = (text.match(/<title>(.*?)<\/title>/i)?.[1] || '').trim();
  const context = {
    scannedUrl: parsed.toString(), finalUrl, origin: parsed.origin,
    title: pageTitle,
    queryString: parsed.search || '',
    method: 'GET',
    protocol: parsed.protocol, hostname, isLocalhost,
    status: response.status, statusCode: response.status, text, headers, requestHeaders,
    responseHeaders: toHeaderObject(headers),
    requestBody: '',
    setCookies, cookieFlags, contentType: headers.get('content-type') || '',
    forms: allForms, links: [...allLinks],
    authHints, allowMethods: optionsProbe.allow, missingPathProbe,
    probeResults,
    surfaceStatus, authSummary: summarizeAuth(auth), fingerprint,
    techStack, cspAnalysis, attackSurface,
  };

  // ── STAGE 2: STATIC RULE ENGINE ──────────────────────────────
  onProgress({ stage: 'analyze', msg: 'Chạy static rule engine…', level: 'info', ts: Date.now() });
  const findings = runUrlRules(context);
  findings.push(...checkVersionDisclosure(fingerprint, context));
  findings.push(...runGraphQlExposure(context));
  findings.push(...runGitExposure(surfaceStatus, parsed.origin));
  findings.push(...runEnvExposure(surfaceStatus, parsed.origin));
  findings.push(...runActuatorExposure(surfaceStatus, parsed.origin));
  findings.push(...runVerifiedExposureChecks(context));

  onProgress({
    stage: 'analyze',
    msg: `Static analysis: ${findings.length} finding(s) sơ bộ`,
    level: findings.length > 0 ? 'warn' : 'success', ts: Date.now(),
  });

  // ── STAGE 3: DYNAMIC FUZZING ──────────────────────────────────
  if (!abortSignal?.aborted) {
    // FIX (vấn đề A): Xóa cache crawl trước khi fuzz.
    // ScannerHttpClient cache GET requests theo URL. Nếu không clear, fuzzer gửi payload
    // tới một URL đã crawl → client trả về cached response thay vì gửi request thật.
    // Kết quả: payload không thực sự chạm server → bỏ sót vulnerability.
    // Lưu ý: fuzzer thay đổi query string nên URL string thường khác, nhưng clear cache
    // ở đây là defensive measure đảm bảo không có edge case nào bị miss.
    client.clearCache();

    onProgress({ stage: 'fuzz', msg: `Dynamic fuzzing (budget: ${maxBudget} requests)…`, level: 'info', ts: Date.now() });
    const dynamicFindings = await runDynamicFuzzing(context, client, maxBudget, onProgress, abortSignal).catch(() => []);
    findings.push(...dynamicFindings);

    onProgress({
      stage: dynamicFindings.length > 0 ? 'found' : 'fuzz',
      msg: dynamicFindings.length > 0
        ? `Active testing: ${dynamicFindings.length} injection finding(s)`
        : 'Active testing xong — không phát hiện injection',
      level: dynamicFindings.length > 0 ? 'warn' : 'success', ts: Date.now(),
    });
  }

  await client.destroy();

  const summary = summarizeFindings(findings);
  const elapsed = ((Date.now() - startTs) / 1000).toFixed(1);
  onProgress({
    stage: 'done',
    msg: `✓ Scan hoàn tất — ${findings.length} findings trong ${elapsed}s`,
    level: 'success', ts: Date.now(),
  });

  return {
    ok: true, mode: 'url-scan',
    scannedUrl: parsed.toString(), finalUrl,
    status: response.status,
    title: pageTitle,
    findings,
    metadata: {
      headers: toHeaderObject(headers),
      crawledEndpointsCount: crawledUrls.size,
      formsDetected: allForms.length,
      linksDetected: allLinks.size,
      authHints, auth: summarizeAuth(auth),
      allowMethods: optionsProbe.allow,
      techStack,
      cspAnalysis,
      attackSurface,
      coverageNotes: getUrlScanCoverageNotes(context),
      summary,
    },
  };
}

// ── PROJECT SCAN ─────────────────────────────────────────────────────────────
// BUG FIX: Phiên bản cũ nhận `options.abortSignal` nhưng KHÔNG BAO GIỜ dùng nó.
// → Nhấn "Stop Scan" khi đang chạy project scan không có tác dụng.
// FIX: Kiểm tra abortSignal trước và sau các bước nặng (walkFiles, collectX).
async function runProjectScan(folderPath, options = {}) {
  const onProgress  = options.onProgress  || (() => {});
  const abortSignal = options.abortSignal  || null;
  const startTs     = Date.now();

  if (!folderPath || typeof folderPath !== 'string') throw new Error('Hãy chọn thư mục project.');

   onProgress({ stage: 'analyze', msg: `Đang quét project: ${folderPath}`, level: 'info', ts: Date.now() });

  if (abortSignal?.aborted) {
    return { ok: false, error: 'Scan đã bị hủy.', findings: [], metadata: { summary: { total: 0, byCategory: {}, bySeverity: {} } } };
  }

  const maxFiles = options.maxFiles || options.projectMaxFiles || process.env.SENTINEL_PROJECT_MAX_FILES || 2500;
  const files = walkFiles(folderPath, { maxFiles });
  onProgress({ stage: 'analyze', msg: `Tìm thấy ${files.length} files để phân tích`, level: 'info', ts: Date.now() });

  if (abortSignal?.aborted) {
    return { ok: false, error: 'Scan đã bị hủy.', findings: [], metadata: { summary: { total: 0, byCategory: {}, bySeverity: {} } } };
  }

  // FIX (vấn đề D): Abort check granular giữa mỗi collectX.
  // Phiên bản cũ gộp tất cả collect vào 1 block, nếu project lớn thì Stop Scan
  // chỉ có tác dụng sau khi tất cả 5 hàm chạy xong — UX kém.
  // FIX: kiểm tra signal trước mỗi collect nặng để cancel ngay khi người dùng nhấn Stop.
  const ABORTED = { ok: false, error: 'Scan đã bị hủy.', findings: [], metadata: { summary: { total: 0, byCategory: {}, bySeverity: {} } } };

  if (abortSignal?.aborted) return ABORTED;
  const dependencyArtifacts = collectDependencyArtifacts(files);

  if (abortSignal?.aborted) return ABORTED;
  const configFiles = collectConfigFiles(files);

  if (abortSignal?.aborted) return ABORTED;
  const textFiles = collectTextFiles(files);

  if (abortSignal?.aborted) return ABORTED;
  const codeFiles = collectCodeFiles(files);

  if (abortSignal?.aborted) return ABORTED;
  const ciFiles = collectCiFiles(files);

  if (abortSignal?.aborted) return ABORTED;

  // ── Additional context for A03 rules ─────────────────────────────────────
  const webConfigFiles = files
    .filter((f) => f.toLowerCase().endsWith('web.config'))
    .map((f) => ({ path: f, content: readTextSafe(f) }));

  const gitignorePath = files.find((f) => path.basename(f) === '.gitignore');
  const gitignoreContent = gitignorePath ? readTextSafe(gitignorePath) : undefined;

  const hasLockfile = !!dependencyArtifacts.packageLockPath;

  onProgress({ stage: 'analyze', msg: 'Chạy rule engine cho project…', level: 'info', ts: Date.now() });

  const context = {
    folderPath, files,
    repoRoot: folderPath,
    sourceFiles: files,
    packageJson:     dependencyArtifacts.packageJson,
    packageJsonPath: dependencyArtifacts.packageJsonPath,
    packageLockJson: dependencyArtifacts.packageLockJson,
    packageLockPath: dependencyArtifacts.packageLockPath,
    hasLockfile,
    csprojFiles:     dependencyArtifacts.csprojFiles,
    webConfigFiles,
    gitignoreContent,
    configFiles, textFiles, codeFiles, ciFiles,
  };

  const techStack = detectProjectTechStack(context);

  const findings = runProjectRules(context);
  const summary  = summarizeFindings(findings);
  const elapsed  = ((Date.now() - startTs) / 1000).toFixed(1);

  onProgress({
    stage: 'done',
    msg: `✓ Quét mã nguồn hoàn tất — ${findings.length} findings trong ${elapsed}s`,
    level: 'success', ts: Date.now(),
  });

  return {
    ok: true, mode: 'project-scan', target: folderPath, findings,
    metadata: {
      scannedFiles:     files.length,
      packageJsonFound: !!dependencyArtifacts.packageJsonPath,
      csprojCount:      dependencyArtifacts.csprojFiles.length,
      configCount:      configFiles.length,
      techStack,
      coverageNotes:    getProjectScanCoverageNotes(context),
      summary,
    },
  };
}

function getChecklist() {
  const categories = [
    { id: 'A01', name: 'Broken Access Control' },
    { id: 'A02', name: 'Cryptographic Failures' },
    { id: 'A03', name: 'Injection' },
    { id: 'A04', name: 'Insecure Design' },
    { id: 'A05', name: 'Security Misconfiguration' },
    { id: 'A06', name: 'Vulnerable & Outdated Components' },
    { id: 'A07', name: 'Identification & Authentication Failures' },
    { id: 'A08', name: 'Software & Data Integrity Failures' },
    { id: 'A09', name: 'Security Logging & Alerting Failures' },
    { id: 'A10', name: 'Mishandling of Exceptional Conditions' },
  ];
  return { categories, designQuestions: getDesignChecklist() };
}

module.exports = {
  runUrlScan,
  runProjectScan,
  getChecklist,
  _internals: {
    classifyProbeRoute,
    computeAttackSurface,
    isConfirmedExposed,
  },
};
