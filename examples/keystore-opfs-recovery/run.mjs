// Dependency-free WebDriver runner. Requires Node 20+, Chrome and ChromeDriver.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve, extname, sep } from 'node:path';
import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';

const root = fileURLToPath(new URL('.', import.meta.url));
const server = createServer(async (req, res) => {
    try {
        const path = resolve(root, '.' + decodeURIComponent(new URL(req.url, 'http://localhost').pathname));
        if (!path.startsWith(root.endsWith(sep) ? root : root + sep) && path !== resolve(root)) {
            res.writeHead(403).end();
            return;
        }
        const file = path === resolve(root) ? resolve(root, 'index.html') : path;
        res.setHeader('Content-Type', ({ '.html': 'text/html', '.js': 'text/javascript', '.wasm': 'application/wasm' })[extname(file)] || 'application/octet-stream');
        res.setHeader('Cache-Control', 'no-store');
        res.end(await readFile(file));
    } catch { res.writeHead(404).end(); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const driverPort = Number(process.env.WEBDRIVER_PORT || 9516);
const driver = spawn(process.env.CHROMEDRIVER || 'chromedriver', [`--port=${driverPort}`], { stdio: ['ignore', 'pipe', 'pipe'] });
let driverError;
let driverLog = '';
driver.on('error', error => { driverError = error; });
driver.stdout.on('data', data => { driverLog += data; });
driver.stderr.on('data', data => { driverLog += data; });
const base = `http://127.0.0.1:${driverPort}`;
async function request(path, method = 'GET', body) {
    const response = await fetch(base + path, {
        method, headers: { 'Content-Type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(30000),
    });
    const { value } = await response.json();
    if (!response.ok || value?.error) throw new Error(JSON.stringify(value));
    return value;
}
let session;
try {
    const deadline = Date.now() + 15000;
    for (;;) {
        if (driverError) throw driverError;
        try { await request('/status'); break; } catch (error) {
            if (Date.now() > deadline) throw error;
            await delay(100);
        }
    }
    const chrome = { args: ['--headless=new', '--disable-dev-shm-usage'] };
    if (process.env.CHROME_BIN) chrome.binary = process.env.CHROME_BIN;
    session = (await request('/session', 'POST', { capabilities: { alwaysMatch: { browserName: 'chrome', 'goog:chromeOptions': chrome } } })).sessionId;
    await request(`/session/${session}/url`, 'POST', { url: `http://127.0.0.1:${server.address().port}/` });
    const deadlineTests = Date.now() + 60000;
    for (;;) {
        let result;
        try {
            result = await request(`/session/${session}/execute/sync`, 'POST', {
                script: "return {status:document.documentElement.dataset.result, text:document.querySelector('#result')?.textContent}", args: [],
            });
        } catch (error) {
            // The recovery test deliberately unloads its document mid-commit.
            if (Date.now() < deadlineTests && /execution context|document unloaded|frame detached/i.test(error.message)) {
                await delay(100);
                continue;
            }
            throw error;
        }
        if (result.status === 'failed') throw new Error(result.text);
        if (result.status === 'passed') { console.log(result.text); break; }
        if (Date.now() > deadlineTests) throw new Error(`Browser tests timed out: ${result.text}`);
        await delay(100);
    }
} catch (error) {
    console.error(driverLog);
    throw error;
} finally {
    if (session) await request(`/session/${session}`, 'DELETE').catch(() => {});
    driver.kill();
    server.close();
}
