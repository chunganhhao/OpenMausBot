#!/usr/bin/env node
// Idempotent auto-patcher: raises OpenMausBot fallback AI limit from 5 -> 20 after app updates.
// shortcut: regex-patches minified Vite/esbuild bundles; update patterns if upstream renames {instanceId,model} schema.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const MAX_RELOAD_ATTEMPTS = 10;

const AIUSAGE_HOLD_EXPR = "(globalThis.__ombAiUsageHold??=(sel,deps,heldModels,nowMs)=>{try{if(!sel?.instanceId||!sel?.model)return null;const engines=deps?.engines?.()??[],eng=engines.find(e=>e.instanceId===sel.instanceId),email=eng?.snapshot?.account?.email?.trim()?.toLowerCase();if(!email)return null;for(const other of engines){if(other.instanceId===sel.instanceId||other.driverKind!==eng.driverKind||other.snapshot?.account?.email?.trim()?.toLowerCase()!==email)continue;const bu=deps?.blockedUntil?.(other.instanceId);if(typeof bu===\"number\"&&bu>nowMs)return{until:bu,resetsAt:bu,scope:\"model\"};for(const[k,v]of heldModels?.entries?.()??[])if(k.startsWith(other.instanceId+\"\\0\")&&v?.until>nowMs&&(v.scope===\"credits\"||k===other.instanceId+\"\\0\"+sel.model))return v}const fs=process.getBuiltinModule(\"node:fs\"),os=process.getBuiltinModule(\"node:os\"),path=process.getBuiltinModule(\"node:path\"),cpaDir=process.env.OMB_AIUSAGE_CPA_DIR||path.join(os.homedir(),\"Library/Application Support/AIUsage/CLIProxyAPI\");let cache=globalThis.__ombAiUsageCache;if(!cache||cache.dir!==cpaDir||nowMs<cache.at||nowMs-cache.at>4999){const byEmail=new Map;let agEnabled=!0;try{agEnabled=JSON.parse(fs.readFileSync(path.join(cpaDir,\"pool-protection.json\"),\"utf8\"))?.enabled!==!1}catch{}const authDir=path.join(cpaDir,\"auth\");if(fs.existsSync(authDir))for(const f of fs.readdirSync(authDir)){if(!f.endsWith(\".json\"))continue;try{const doc=JSON.parse(fs.readFileSync(path.join(authDir,f),\"utf8\")),em=typeof doc?.email===\"string\"?doc.email.trim().toLowerCase():\"\",tp=typeof doc?.type===\"string\"?doc.type.trim().toLowerCase():\"\";if(!em||!tp)continue;const key=tp+\":\"+em,prev=byEmail.get(key),disabled=doc.disabled===!0||doc.disabled===1||doc.circuit_breaker_tripped===!0,pools=new Set([...prev?.pools??[],...Array.isArray(doc.circuit_breaker_pools)?doc.circuit_breaker_pools.map(p=>String(p).toLowerCase()):[]]),excl=[...new Set([...prev?.excl??[],...Array.isArray(doc.excluded_models)?doc.excluded_models.map(m=>String(m).toLowerCase()):[]])];byEmail.set(key,{disabled:prev?prev.disabled&&disabled:disabled,pools,excl})}catch{}}cache=globalThis.__ombAiUsageCache={at:nowMs,dir:cpaDir,byEmail,agEnabled}}const credentialType=eng.driverKind===\"antigravityAgent\"?\"antigravity\":eng.driverKind,rec=cache.byEmail.get(credentialType+\":\"+email);if(!rec)return null;const holdUntil=nowMs+3e5;if(rec.disabled)return{until:holdUntil,resetsAt:holdUntil,scope:\"model\"};if(eng.driverKind===\"antigravityAgent\"&&cache.agEnabled){const m=String(sel.model).toLowerCase(),pool=m.startsWith(\"gemini-4-argon\")||m.includes(\"argon\")?\"argon\":m.startsWith(\"gemini-\")?\"gemini\":m.startsWith(\"claude-\")||m.startsWith(\"gpt-\")?\"claude\":null;if(pool&&rec.pools.has(pool)||rec.excl.some(x=>x===m||x.startsWith(m+\"-\")||x.includes(\"*\")&&new RegExp(\"^\"+x.split(\"*\").map(p=>p.replace(/[|\\\\{}()[\\]^$+?.]/g,c=>\"\\\\\"+c)).join(\".*\")+\"$\").test(m)))return{until:holdUntil,resetsAt:holdUntil,scope:\"model\"}}return null}catch{return null}})";

const RULES = [
  [/(const \w+=)5(,\w+=\{instanceId:"",model:""\})/g, "$120$2"],
  [/(![\w$]+\|\|[\w$]+\.length>=)5(\|\|[\w$]+\(\[\.\.\.[\w$]+,\{instanceId:)/g, "$120$2"],
  [/([\w$]+\.length<)5(&&[\w$]+\.jsx\("div",\{className:[\w$]+\("flex items-center gap-2")/g, "$120$2"],
  [/(\.fallback\.length\s*>\s*)5\b/g, "$120"],
  [/fallback must be a list of up to five \{ instanceId, model \} entries/g, "fallback must be a list of up to 20 { instanceId, model } entries"],
  [/(fallback:\s*(?:z|external_exports)\.array\((?:z|external_exports)\.object\(\{\s*instanceId:[^}]+\}\)\)\.max\()5(\))/g, "$120$2"],
  [/(safe\.startsWith\("\/assets\/"\)\s*\?\s*)"public, max-age=31536000, immutable"/g, '$1"no-cache"'],
  [/\^https\?:\\\/\\\/(github\\\.com|skills\\\.sh)\\\//g, "^https?:\\/\\/(?:www\\.)?$1\\/"],
  [
    /function limitBackupAllowed\((\w+),(\w+),(\w+)\)\{return \2\.instanceId===\1\.instanceId\?!1:\2\.driverKind!==\1\.driverKind\|\|!SUBSCRIPTION_DRIVERS\.has\(\1\.driverKind\)\?!0:billsEachUse\(\3\)\}/g,
    "function limitBackupAllowed($1,$2,$3){return $2.instanceId!==$1.instanceId}",
  ],
  [
    /export function limitBackupAllowed\(from, to, toConfig\) \{\s*if \(to\.instanceId === from\.instanceId\)\s*return false;\s*if \(to\.driverKind !== from\.driverKind \|\| !SUBSCRIPTION_DRIVERS\.has\(from\.driverKind\)\)\s*return true;\s*return billsEachUse\(toConfig\);\s*\}/g,
    "export function limitBackupAllowed(from, to, toConfig) {\n    return to.instanceId !== from.instanceId;\n}",
  ],
  [
    /;\(scope==="model"\|\|scope==="credits"\)&&(\w+)\(\{instanceId:(\w+)\.instanceId,model:\2\.models\.default\}\);for\(let (\w+) of scope==="signed-out"\?deps\.signedOutChosen\?\.\(botId\)\?\?deps\.chosen\(botId\):deps\.chosen\(botId\)\)\1\(\3\);/g,
    ';for(let $3 of scope==="signed-out"?deps.signedOutChosen?.(botId)??deps.chosen(botId):deps.chosen(botId))$1($3);(scope==="model"||scope==="credits")&&$1({instanceId:$2.instanceId,model:$2.models.default});',
  ],
  [
    /if \(scope === "model" \|\| scope === "credits"\)\s*add\(\{ instanceId: current\.instanceId, model: current\.models\.default \}\);\s*for \(const selection of scope === "signed-out" \? deps\.signedOutChosen\?\.\(botId\) \?\? deps\.chosen\(botId\) : deps\.chosen\(botId\)\)\s*add\(selection\);/g,
    'for (const selection of scope === "signed-out" ? deps.signedOutChosen?.(botId) ?? deps.chosen(botId) : deps.chosen(botId))\n            add(selection);\n        if (scope === "model" || scope === "credits")\n            add({ instanceId: current.instanceId, model: current.models.default });',
  ],
  [/(let full=windows\.filter\(\w+=>\w+\.used>=)100(\);)/g, "$199$2"],
  [/(const full = windows\.filter\(\(line\) => line\.used >= )100(\);)/g, "$199$2"],
  [
    /modelHeld=(\w+)=>\{let (\w+)=heldModels\.get\(modelKey\(\1\)\);return \2\?\2\.until>(\w+)\(\)\?\2:\(heldModels\.delete\(modelKey\(\1\)\),(\w+)\(\),null\):null\}/g,
    `modelHeld=$1=>{let $2=heldModels.get(modelKey($1));if($2){if($2.until>$3())return $2;heldModels.delete(modelKey($1)),$4()}return ${AIUSAGE_HOLD_EXPR}($1,deps,heldModels,$3())}`,
  ],
  [
    /const modelHeld = \(selection\) => \{\s*const held = heldModels\.get\(modelKey\(selection\)\);\s*if \(!held\)\s*return null;\s*if \(held\.until > now\(\)\)\s*return held;\s*heldModels\.delete\(modelKey\(selection\)\);\s*save\(\);\s*return null;\s*\};/g,
    `const modelHeld = (selection) => {\n        const held = heldModels.get(modelKey(selection));\n        if (held) {\n            if (held.until > now())\n                return held;\n            heldModels.delete(modelKey(selection));\n            save();\n        }\n        return ${AIUSAGE_HOLD_EXPR}(selection, deps, heldModels, now());\n    };`,
  ],
  [/\(globalThis\.__ombAiUsageHold\?\?=\(sel,deps,heldModels,nowMs\)=>\{[\s\S]*?catch\{return null\}\}\)/g, () => AIUSAGE_HOLD_EXPR],
];

export function applyRules(text) {
  return RULES.reduce((acc, [re, rep]) => acc.replace(re, rep), text);
}

export function isCliEntry(argv = process.argv) {
  return Array.isArray(argv) && typeof argv[1] === "string" && /(?:^|[\\/])patch-fallback-20\.mjs$/.test(argv[1]);
}

export function resolveServerPort(logText = "") {
  const matches = [...String(logText).matchAll(/\bport=(\d+)\b/g)];
  const last = matches.at(-1)?.[1];
  return last ? Number(last) : 8799;
}

export function resolveVerifiedServerPid({ execFile = execFileSync, logText = "" } = {}) {
  const port = resolveServerPort(logText);
  const raw = execFile("curl", ["-fsS", "--max-time", "2", `http://127.0.0.1:${port}/api/health`], { encoding: "utf8" });
  const health = JSON.parse(raw);
  if (health?.app !== "openmausbot" || health?.static !== true || !Number.isInteger(health?.pid) || health.pid <= 1) {
    throw new Error(`Invalid /api/health payload on port ${port}`);
  }
  const cmd = String(execFile("ps", ["-p", String(health.pid), "-o", "command="], { encoding: "utf8" })).trim();
  if (!cmd.includes("/Applications/OpenMausBot.app/") || !cmd.includes("--utility-sub-type=node.mojom.NodeService")) {
    throw new Error(`PID ${health.pid} command mismatch: ${cmd}`);
  }
  return health.pid;
}

export function runPatcher({
  resDir = "/Applications/OpenMausBot.app/Contents/Resources",
  home = homedir(),
  fsOps = { existsSync, readdirSync, readFileSync, rmSync, writeFileSync },
  execFile = execFileSync,
  killPid = (pid, sig) => process.kill(pid, sig),
  logger = console,
  maxAttempts = MAX_RELOAD_ATTEMPTS,
} = {}) {
  if (!fsOps.existsSync(resDir)) return { changed: 0, reloaded: false };

  const uiAssets = join(resDir, "ui/assets");
  const targets = [
    join(resDir, "server/index.js"),
    join(resDir, "server/server/routes/bot-patch.js"),
    join(resDir, "server/server/cloud-send-kinds.js"),
    join(resDir, "server/server/static-files.js"),
    join(resDir, "server/server/skill-fetch.js"),
    join(resDir, "server/server/limit-failover.js"),
    join(resDir, "server/server/limit-resets.js"),
    join(resDir, "server/server/host/limit-takeover.js"),
    ...(fsOps.existsSync(uiAssets)
      ? fsOps.readdirSync(uiAssets)
          .filter((f) => /^(BotSettingsDialog|VisibilitySection)-.*\.js$/.test(f))
          .map((f) => join(uiAssets, f))
      : []),
  ].filter((f) => fsOps.existsSync(f));

  let changed = 0;
  for (const file of targets) {
    const before = fsOps.readFileSync(file, "utf8");
    const after = applyRules(before);
    if (after !== before) {
      fsOps.writeFileSync(file, after, "utf8");
      changed++;
    }
  }

  const pendingFile = join(home, ".openmausbot/.reload-pending");
  const appSupport = join(home, "Library/Application Support/openmausbot");

  if (changed > 0) {
    for (const dir of ["Cache", "Code Cache", "server-compile-cache"]) {
      fsOps.rmSync(join(appSupport, dir), { recursive: true, force: true });
    }
    fsOps.writeFileSync(pendingFile, "1\n", "utf8");
  }

  if (changed === 0 && !fsOps.existsSync(pendingFile)) {
    return { changed: 0, reloaded: false };
  }

  const rawPending = fsOps.existsSync(pendingFile) ? String(fsOps.readFileSync(pendingFile, "utf8")).trim() : "1";
  const attempt = Number.parseInt(rawPending, 10) > 0 ? Number.parseInt(rawPending, 10) : 1;

  try {
    let appRunning = false;
    try {
      execFile("pgrep", ["-f", "/Applications/OpenMausBot.app/Contents/MacOS/OpenMausBot"], { stdio: "ignore" });
      appRunning = true;
    } catch (err) {
      if (err && typeof err === "object" && err.status === 1 && !err.code) {
        appRunning = false;
      } else {
        throw err;
      }
    }

    if (!appRunning) {
      fsOps.rmSync(pendingFile, { force: true });
      logger.log(`[${new Date().toISOString()}] Patched ${changed} file(s); OpenMausBot is not running (no reload needed).`);
      return { changed, reloaded: false };
    }

    const serverLog = join(home, "Library/Logs/openmausbot/server.log");
    const logText = fsOps.existsSync(serverLog) ? fsOps.readFileSync(serverLog, "utf8") : "";
    const pid = resolveVerifiedServerPid({ execFile, logText });
    killPid(pid, "SIGTERM");
    fsOps.rmSync(pendingFile, { force: true });
    logger.log(`[${new Date().toISOString()}] Patched ${changed} file(s) and signaled verified server PID ${pid}.`);
    return { changed, reloaded: true, pid };
  } catch (err) {
    if (attempt >= maxAttempts) {
      fsOps.rmSync(pendingFile, { force: true });
      logger.error?.(`[${new Date().toISOString()}] Max reload attempts (${maxAttempts}) reached; cleared pending marker: ${err instanceof Error ? err.message : String(err)}`);
      return { changed, reloaded: false, exhausted: true };
    }
    fsOps.writeFileSync(pendingFile, `${attempt + 1}\n`, "utf8");
    throw err;
  }
}

export function runSelfTest() {
  const sample = [
    'const fi=5,gi={instanceId:"",model:""};',
    '!b||i.length>=5||r([...i,{instanceId:c,model:b}]);',
    'i.length<5&&e.jsx("div",{className:D("flex items-center gap-2",x)});',
    'if(!Array.isArray(body3.fallback)||body3.fallback.length>5)return "fallback must be a list of up to five { instanceId, model } entries";',
    'fallback:external_exports.array(external_exports.object({instanceId:external_exports.string(),model:external_exports.string()})).max(5)',
    'safe.startsWith("/assets/")?"public, max-age=31536000, immutable":null',
    'const tree = github.match(/^https?:\\/\\/github\\.com\\/([^/]+)\\/([^/]+?)$/i);',
    'const registry = text.match(/^https?:\\/\\/skills\\.sh\\/([\\w.-]+)\\/([\\w.-]+)(?:\\/([\\w.-]+))?\\/?$/i);',
    'function limitBackupAllowed(from,to2,toConfig){return to2.instanceId===from.instanceId?!1:to2.driverKind!==from.driverKind||!SUBSCRIPTION_DRIVERS.has(from.driverKind)?!0:billsEachUse(toConfig)}',
    'export function limitBackupAllowed(from, to, toConfig) {\n    if (to.instanceId === from.instanceId)\n        return false;\n    if (to.driverKind !== from.driverKind || !SUBSCRIPTION_DRIVERS.has(from.driverKind))\n        return true;\n    return billsEachUse(toConfig);\n}',
    ';(scope==="model"||scope==="credits")&&add11({instanceId:current3.instanceId,model:current3.models.default});for(let selection3 of scope==="signed-out"?deps.signedOutChosen?.(botId)??deps.chosen(botId):deps.chosen(botId))add11(selection3);',
    'let full=windows.filter(line6=>line6.used>=100);',
    'const full = windows.filter((line) => line.used >= 100);',
    'modelHeld=selection3=>{let held4=heldModels.get(modelKey(selection3));return held4?held4.until>now2()?held4:(heldModels.delete(modelKey(selection3)),save7(),null):null}',
  ].join("\n");
  const out = applyRules(sample);
  assert(!out.includes("=5,") && !out.includes(">=5") && !out.includes("<5") && !out.includes(">5") && !out.includes("max(5)") && !out.includes("immutable"));
  assert(out.includes("(?:www\\.)?github\\.com") && out.includes("(?:www\\.)?skills\\.sh"));
  assert(out.includes("function limitBackupAllowed(from,to2,toConfig){return to2.instanceId!==from.instanceId}"));
  assert(out.includes("return to.instanceId !== from.instanceId;"));
  assert(out.includes("line6.used>=99") && out.includes("line.used >= 99"));
  assert(out.includes("__ombAiUsageHold"));
  assert.equal(applyRules(out), out, "must be idempotent");
  assert.equal(isCliEntry([]), false, "import with empty argv must not match CLI entry");
  assert.equal(isCliEntry(["node", "/Users/apple/Downloads/Repo Github/review-openmausbot-watchdog.cjs"]), false, "import from harness must not match CLI entry");
  assert.equal(isCliEntry(["node", "/Users/apple/.openmausbot/patch-fallback-20.mjs"]), true, "direct execution must match CLI entry");

  // Verify AIUsage hold + same-email sibling hold behavior in memory
  const holdFn = (0, eval)(AIUSAGE_HOLD_EXPR);
  const fakeEngines = [
    { instanceId: "codex", driverKind: "codex", snapshot: { account: { email: "nhntrong592@gmail.com" } } },
    { instanceId: "chatgpt", driverKind: "codex", snapshot: { account: { email: "nhntrong592@gmail.com" } } },
    { instanceId: "chatgpt-2", driverKind: "codex", snapshot: { account: { email: "chunganhhao03121996@gmail.com" } } },
  ];
  const siblingHold = holdFn(
    { instanceId: "chatgpt", model: "gpt-6" },
    { engines: () => fakeEngines, blockedUntil: (id) => (id === "codex" ? 200000 : null) },
    new Map(),
    100000,
  );
  assert.deepEqual(siblingHold, { until: 200000, resetsAt: 200000, scope: "model" }, "same-email sibling engine block must propagate");

  const mem = new Map([
    ["/Applications/OpenMausBot.app/Contents/Resources/server/index.js", 'if(body3.fallback.length>5)return "fallback must be a list of up to five { instanceId, model } entries";'],
  ]);
  const fsMock = {
    existsSync: (p) => p === "/Applications/OpenMausBot.app/Contents/Resources" || mem.has(p),
    readdirSync: () => [],
    readFileSync: (p) => mem.get(p),
    writeFileSync: (p, v) => mem.set(p, v),
    rmSync: (p) => mem.delete(p),
  };
  let mode = "pgrep-enoent";
  const killed = [];
  const execMock = (cmd, args) => {
    if (cmd === "pgrep") {
      if (mode === "pgrep-enoent") throw Object.assign(new Error("spawn pgrep ENOENT"), { code: "ENOENT" });
      if (mode === "app-stopped") throw Object.assign(new Error("no match"), { status: 1 });
      return "4207\n";
    }
    if (cmd === "curl") return JSON.stringify({ app: "openmausbot", pid: 74810, static: true });
    if (cmd === "ps" && args[1] === "74810") {
      return "/Applications/OpenMausBot.app/Contents/Frameworks/OpenMausBot Helper.app/Contents/MacOS/OpenMausBot Helper --type=utility --utility-sub-type=node.mojom.NodeService";
    }
    throw new Error(`Unexpected command: ${cmd}`);
  };
  const killMock = (pid, sig) => {
    killed.push([pid, sig]);
    if (mode === "kill-eperm") throw new Error("EPERM");
  };

  // 1. pgrep ENOENT must throw and keep .reload-pending (not treat as app closed)
  assert.throws(() => runPatcher({ home: "/Users/apple", fsOps: fsMock, execFile: execMock, killPid: killMock, logger: { log() {}, error() {} } }), /ENOENT/);
  assert.equal(mem.get("/Users/apple/.openmausbot/.reload-pending"), "2\n");

  // 2. kill EPERM must throw and increment attempt counter in .reload-pending
  mode = "kill-eperm";
  assert.throws(() => runPatcher({ home: "/Users/apple", fsOps: fsMock, execFile: execMock, killPid: killMock, logger: { log() {}, error() {} } }), /EPERM/);
  assert.equal(mem.get("/Users/apple/.openmausbot/.reload-pending"), "3\n");

  // 3. Subsequent run (changed === 0) succeeds, signals only 74810, and clears .reload-pending
  mode = "ok";
  const retry = runPatcher({ home: "/Users/apple", fsOps: fsMock, execFile: execMock, killPid: killMock, logger: { log() {}, error() {} } });
  assert.equal(retry.changed, 0);
  assert.equal(retry.reloaded, true);
  assert.equal(retry.pid, 74810);
  assert.equal(mem.has("/Users/apple/.openmausbot/.reload-pending"), false);
  assert.deepEqual(killed, [[74810, "SIGTERM"], [74810, "SIGTERM"]]);
  console.log("SELF_TEST_OK");
}

if (isCliEntry(process.argv)) {
  if (process.argv.includes("--self-test")) {
    runSelfTest();
    process.exit(0);
  }
  try {
    runPatcher();
  } catch (err) {
    console.error(`[${new Date().toISOString()}] OpenMausBot patch-fallback-20 reload error: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 1;
  }
}
