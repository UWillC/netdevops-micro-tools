"""ui_smoke.py - drive headless Chrome over DevTools against a LOCAL server (port 8000).

Why: pytest cannot see what the page renders. Twice on 2026-09-18 the API was right
and the screen was not (empty result hid NOT EVALUATED; KEV chip missing on cards).

  1. python3 -m uvicorn api.main:app --port 8000
  2. "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new \
       --remote-debugging-port=9333 --user-data-dir=/tmp/ui-smoke-profile about:blank
  3. python3 scripts/dev/ui_smoke.py /tmp/ui.png     (needs: pip install websockets)

Edit the (platform, version) list in main() for the case you want to look at.
"""
import asyncio, json, sys, urllib.request, base64
import websockets
PORT=9333; OUT=sys.argv[1]
async def main():
    tabs=json.load(urllib.request.urlopen(f"http://127.0.0.1:{PORT}/json"))
    ws_url=[t for t in tabs if t["type"]=="page"][0]["webSocketDebuggerUrl"]
    async with websockets.connect(ws_url,max_size=50_000_000) as ws:
        n=0
        async def call(method,**params):
            nonlocal n; n+=1; await ws.send(json.dumps({"id":n,"method":method,"params":params}))
            while True:
                m=json.loads(await ws.recv())
                if m.get("id")==n: return m.get("result",{})
        async def js(expr):
            r=await call("Runtime.evaluate",expression=expr,awaitPromise=True,returnByValue=True)
            return r.get("result",{}).get("value")
        await call("Page.enable"); await call("Page.navigate",url="http://127.0.0.1:8000/"); await asyncio.sleep(1.5)
        await js("localStorage.setItem('netdevops_unlocked','true')"); await call("Page.navigate",url="http://127.0.0.1:8000/"); await asyncio.sleep(2.5)
        await js("document.querySelector('[data-tab=\"cve\"]').click()")
        results={}
        for plat,ver in [("IOS XE","17.9.04")]:
            await js(f"(()=>{{const s=document.getElementById('cve-platform'); s.value={json.dumps(plat)}; s.dispatchEvent(new Event('change')); return s.value}})()")
            ex=await js("document.getElementById('cve-version').value")
            await js(f"document.getElementById('cve-version').value={json.dumps(ver)}")
            await js("document.getElementById('cve-form').requestSubmit()"); await asyncio.sleep(7)
            results[plat]={
              "example_after_change":ex,
              "sections":await js("Array.from(document.querySelectorAll('.cve-section-header')).map(e=>e.firstChild.textContent)"),
              "cards":await js("document.querySelectorAll('#cve-cards .cve-item').length"),
              "hardening_cards":await js("Array.from(document.querySelectorAll('#cve-cards .tag-bundle')).map(e=>e.textContent)"),
              "kev_chips":await js("Array.from(document.querySelectorAll('#cve-cards .tag-escalation')).map(e=>e.textContent)"),
              "posture":await js("Array.from(document.querySelectorAll('#cve-summary .summary-row')).map(e=>e.innerText.replace(/\\s+/g,' ')).slice(2,9)"),
              "text_head":await js("document.getElementById('cve-output').value.split('\\n').filter(l=>/^Matched, confirmed|^Lower confidence|^HARDENING|^Not confirmed|^Severity breakdown|^  (CRITICAL|HIGH|MEDIUM|LOW):/.test(l))"),
            }
        await js("document.getElementById('cve-summary').scrollIntoView()")
        box=await js("(()=>{const r=document.getElementById('cve-summary').getBoundingClientRect(); return [r.x,r.y,r.width,r.height]})()")
        shot=await call("Page.captureScreenshot",format="png"); open(OUT,"wb").write(base64.b64decode(shot["data"]))
        print("OUTPUT:", await js("document.getElementById('cve-output').value.slice(0,300)"))
        print("gate:", await js("localStorage.getItem('netdevops_unlocked')"), "| form:", await js("!!document.getElementById('cve-form')"), "| activeTab:", await js("(document.querySelector('.tab-content.active')||{}).id"))
        errs=await js("window.__errs||[]")
        print(json.dumps(results,indent=1)); print("js errors:",errs)
asyncio.run(main())
