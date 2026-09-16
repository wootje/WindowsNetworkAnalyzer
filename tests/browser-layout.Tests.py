"""Responsive CSS regression checks in a real Chromium browser.

Development only: Python 3 and playwright are needed. This never captures
Windows traffic. All test records are synthetic. Invoke:
    python tests/browser-layout.Tests.py --browser /usr/bin/chromium
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import shutil
import tempfile
from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parent.parent
WIDTHS = [320, 360, 390, 650, 768, 850, 1024, 1199, 1200, 1280, 1366, 1440, 1669, 1920, 2560]


def sample_data(count: int = 10000) -> dict:
    records = []
    apps = [('chatgpt.exe', 'Example desktop application'),
            ('chrome.exe', 'Google Chrome'), ('svchost.exe', 'Microsoft Windows'),
            ('firefox.exe', 'Firefox'), ('example-agent.exe', 'Example agent')]
    for i in range(count):
        name, app = apps[i % len(apps)]
        if i % 9 == 0:
            summary = ('UDP port 5353 is used by multicast DNS to resolve names '
                       'and support discovery on a local network.')
            protocol, remote, port, local, source, scope = 'UDP', '10.10.10.52', 5353, '224.0.0.251', 'WFP5156', 'Private'
        else:
            summary = ('This is possible encrypted web traffic. The process and port '
                       'do not reveal the exact page, payload or user action. '
                       'Open this record to inspect the evidence and its limitations.')
            protocol, remote, port, local, source, scope = 'TCP', f'198.51.100.{i % 254 + 1}', 443, '10.10.10.10', 'TcpSnapshot', 'Documentation'
        records.append(dict(
            id=f'c{i:06d}', processName=name, processId=1000+i, application=app,
            processPath='C:\\Program Files\\Example\\'+name,
            attributionStatus='MatchedLiveProcess', processEvidence='Synthetic fixture, not a real capture.',
            protocol=protocol, remoteAddress=remote, remotePort=port,
            localAddress=local, localPort=5353 if port == 5353 else 50000+i%10000,
            state='WFP: permitted at the audited layer' if source == 'WFP5156' else 'Established',
            allowed=True, direction='Inbound' if port == 5353 else 'Unknown (snapshot)',
            source=source, ipScope=scope, dnsNames=[] if port == 5353 else ['cdn.example.test'],
            firstSeen='2026-09-16T08:00:00Z', lastSeen='2026-09-16T08:04:00Z',
            observations=(i % 5) + 1,
            services=['Dnscache'] if name == 'svchost.exe' else [],
            serviceDetails=[dict(name='Dnscache', displayName='DNS Client', description='Synthetic service description', state='Running', startMode='Auto')] if name == 'svchost.exe' else [],
            ipRegistration=dict(status='SkippedNonPublic', name='', organization=''),
            explanation=dict(category='Local name discovery candidate' if port == 5353 else 'Web traffic',
                             summary=summary, confidence='Likely', purpose=summary,
                             evidence=['Synthetic record used to test report rendering.'],
                             limitations=['This is not measured network activity.']),
        ))
    # Deliberately long, unbroken values test intrinsic table width and wrapping.
    records[5].update(
        processName='very-long-process-'+('x'*140)+'.exe', application='Long application '+('y'*170),
        processPath='C:\\Applications\\'+('LongDirectory'*35)+'\\test.exe',
        remoteAddress='2001:0db8:ffff:ffff:aaaa:bbbb:cccc:dddd',
        localAddress='fe80:0000:0000:0000:1111:2222:3333:4444%123',
        dnsNames=[('a'*63)+'.'+('b'*63)+'.'+('c'*63)+'.example.test'],
        company='Example publisher '+('p'*100), sha256='a'*64,
        signatureStatus='Unknown', signer='Example signer '+('s'*120),
        ipRegistration=dict(status='Fixture', organization='Registry-'+('r'*140), country='ZZ'),
    )
    return dict(meta=dict(version='3.0.1', computer='SYNTHETIC TEST PC', phase='Layout test only',
                          started='2026-09-16T08:00:00Z', finished='2026-09-16T08:05:00Z',
                          durationSeconds=300, sources=['TcpSnapshot','WFP5156'], warnings=[]),
                connections=records)


def render_fixture(data: dict) -> str:
    template = (ROOT / 'report-template.html').read_text(encoding='utf-8')
    css = (ROOT / 'report-responsive.css').read_text(encoding='utf-8')
    embedded = re.search(r'<style id="wna-responsive-layout">\s*([\s\S]*?)</style>', template)
    assert embedded and embedded.group(1).strip() == css.strip(), 'Embedded CSS differs from patcher CSS'
    payload = json.dumps(data, ensure_ascii=True).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
    return template.replace('__NETWORK_REPORT_FILTER_ENGINE__', (ROOT/'report-filters.js').read_text()).replace('__NETWORK_REPORT_DATA__', payload)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--browser', default=shutil.which('chromium') or shutil.which('google-chrome'))
    parser.add_argument('--output', type=Path, help='Keep generated test report, screenshots and metrics in this folder.')
    args = parser.parse_args()
    tmp = tempfile.TemporaryDirectory(prefix='wna-layout-')
    out = args.output or Path(tmp.name)
    out.mkdir(parents=True, exist_ok=True)
    fixture = out/'synthetic-report.html'
    data = sample_data()
    fixture.write_text(render_fixture(data), encoding='utf-8')
    metrics, errors, requests = [], [], []
    with sync_playwright() as p:
        kwargs = {'headless': True, 'args': ['--no-sandbox']}
        if args.browser:
            kwargs['executable_path'] = args.browser
        browser = p.chromium.launch(**kwargs)
        page = browser.new_page(viewport={'width':1669, 'height':1050}, color_scheme='dark')
        page.on('pageerror', lambda e: errors.append(str(e)))
        page.on('request', lambda r: requests.append(r.url) if r.url.startswith(('http://','https://')) else None)
        page.set_content(fixture.read_text(encoding="utf-8"), wait_until="load")
        expect(page.locator("#stat-rows")).to_have_text("10,000")
        for light in (False, True):
            page.evaluate('(v) => document.documentElement.classList.toggle("light", v)', light)
            for width in WIDTHS:
                page.set_viewport_size({'width':width, 'height':1050})
                page.locator('.advanced-group').evaluate_all('(nodes) => nodes.forEach(n => n.open = true)')
                result = page.evaluate('''() => {
                    const wrap=document.querySelector('.table-wrap');
                    const table=wrap.querySelector('table');
                    const doc=document.documentElement;
                    const cells=[...document.querySelectorAll('#rows td')];
                    const badCells=cells.filter(e=>e.scrollWidth>e.clientWidth+1).map(e=>({text:e.textContent.slice(0,90),width:e.clientWidth,scroll:e.scrollWidth}));
                    const boxes=[table,...document.querySelectorAll('.field input,.field select,#rows td')];
                    const outside=boxes.filter(e=>{const b=e.getBoundingClientRect();return b.left < -1 || b.right>doc.clientWidth+1}).map(e=>e.id||e.tagName);
                    return {viewport:window.innerWidth,docWidth:doc.clientWidth,docScroll:doc.scrollWidth,
                        wrapWidth:wrap.clientWidth,wrapScroll:wrap.scrollWidth,badCells,outside,
                        rows:document.querySelectorAll('#rows tr').length,cellCount:cells.length,
                        tableDisplay:getComputedStyle(table).display,
                        label:getComputedStyle(cells[0],'::before').content,
                        headingWidths:[...table.querySelectorAll('thead th button')].map(e=>e.getBoundingClientRect().width),
                        headingGridWidth:table.querySelector('thead tr').getBoundingClientRect().width};
                }''')
                result['theme']='light' if light else 'dark'
                assert result['docScroll'] <= result['docWidth']+1, result
                assert result['wrapScroll'] <= result['wrapWidth']+1, result
                assert not result['badCells'], result
                assert not result['outside'], result
                assert result['rows']==50 and result['cellCount']==450, result
                assert result['tableDisplay']==('block' if width<1200 else 'table'), result
                if width<1200:
                    assert 'Process / application' in result['label'], result
                    columns=2 if width<=650 else 3
                    expected=(result['headingGridWidth']-(columns-1)*6)/columns
                    assert all(w >= expected-2 for w in result['headingWidths']), result
                # All data cells must remain readable, not hidden/clipped.
                assert page.locator('#rows tr').first.locator('td').evaluate_all('(nodes)=>nodes.every(n=>getComputedStyle(n).visibility === "visible" && getComputedStyle(n).display!=="none")')
                metrics.append(result)
                page.locator('.advanced-group').evaluate_all('(nodes) => nodes.forEach(n => n.open = false)')
                if width in (390,1024,1669) and not light:
                    page.locator('.table-wrap thead').scroll_into_view_if_needed()
                    if width < 650:
                        page.screenshot(path=str(out/f'table-{width}.png'))
                    else:
                        page.locator('.table-wrap').screenshot(path=str(out/f'table-{width}.png'))
        # Actual browser interaction checks, including a narrow viewport.
        page.set_viewport_size({'width':390, 'height':844})
        page.locator('th[data-key="app"] button').click()
        assert page.locator('th[data-key="app"]').get_attribute('aria-sort')=='ascending'
        page.locator('th[data-key="app"] button').click()
        assert page.locator('th[data-key="app"]').get_attribute('aria-sort')=='descending'
        page.locator('#search').fill('very-long-process-')
        expect(page.locator("#stat-rows")).to_have_text("1")
        page.locator('#rows .app-button').first.click()
        assert page.locator('#detail').is_visible()
        bounds=page.locator('#detail').evaluate('(d)=>({w:d.clientWidth,s:d.scrollWidth})')
        assert bounds['s'] <= bounds['w']+1, bounds
        assert page.locator('#detail-body').inner_text().find('a'*64)>=0
        page.locator('#close-detail').click()
        with page.expect_download() as download:
            page.locator('#export').click()
        file=out/'selection.csv'
        download.value.save_as(file)
        assert 'very-long-process-' in file.read_text(encoding='utf-8-sig')
        page.locator('#reset').click()
        expect(page.locator("#stat-rows")).to_have_text("10,000")
        page.locator('#page-size').select_option('100')
        assert page.locator('#rows tr').count()==100
        page.locator('#next').click()
        assert page.locator('#page-status').inner_text()=='2 / 100'
        page.locator('#search').fill('NoSuchProcessForEmptyState')
        expect(page.locator("#stat-rows")).to_have_text("0")
        assert page.locator('#rows .empty').is_visible()
        assert 'No matching records' in page.locator('#rows .empty').inner_text()
        page.locator('#reset').click()
        page.set_viewport_size({'width':1280,'height':900})
        page.emulate_media(media='print')
        assert page.locator('.table-wrap table').evaluate('(e)=>getComputedStyle(e).display')=='table'
        assert page.locator('.table-wrap thead').evaluate('(e)=>getComputedStyle(e).display')=='table-header-group'
        assert not errors, errors
        assert not requests, requests
        version=browser.version
        browser.close()
    result=dict(passed=True, browser='Chromium '+version, viewportChecks=len(metrics), widths=WIDTHS,
                records=10000, themes=['dark','light'], interactionChecks='sorting, search, full details, CSV, pagination, empty state, print layout',
                pageErrors=errors, externalRequests=requests, metrics=metrics)
    (out/'browser-layout-results.json').write_text(json.dumps(result,indent=2))
    print(json.dumps({k:v for k,v in result.items() if k!='metrics'},indent=2))
    tmp.cleanup()

if __name__ == '__main__':
    main()
