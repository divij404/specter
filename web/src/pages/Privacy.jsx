import { Link } from 'react-router-dom'
import Logo from '../components/Logo'
import Footer from '../components/Footer'

const codeStyle = { fontFamily: 'var(--font-mono)', fontSize: '0.9em', color: 'var(--teal)', background: 'rgba(56,163,184,0.1)', padding: '1px 5px', borderRadius: 3, whiteSpace: 'nowrap' }
const container = { maxWidth: 760, margin: '0 auto', padding: '0 clamp(20px,5vw,48px)' }

function Table({ cols, rows }) {
  return (
    <div style={{ marginTop: 20, border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', overflow: 'hidden' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
        <thead>
          <tr style={{ background: 'var(--surface-raised)' }}>
            {cols.map(c => (
              <th key={c} style={{ fontFamily: 'var(--font-mono)', fontSize: 10, letterSpacing: '0.08em',
                textTransform: 'uppercase', color: 'var(--text-dim)', padding: '10px 16px',
                textAlign: 'left', borderBottom: '1px solid var(--border)' }}>
                {c}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i}>
              {row.map((cell, j) => (
                <td key={j} style={{
                  padding: '10px 16px', fontFamily: 'var(--font-mono)', fontSize: 12,
                  color: j === 0 ? 'var(--teal)' : 'var(--text-muted)', verticalAlign: 'top',
                  borderBottom: i < rows.length - 1 ? '1px solid var(--border)' : 'none',
                }}>
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function Section({ title, children }) {
  return (
    <div style={{ marginTop: 48 }}>
      <h2 style={{ fontFamily: 'var(--font-display)', fontSize: 22, fontWeight: 700,
        letterSpacing: '-0.02em', color: 'var(--text)', marginBottom: 14,
        paddingBottom: 12, borderBottom: '1px solid var(--border)' }}>
        {title}
      </h2>
      {children}
    </div>
  )
}

function P({ children }) {
  return <p style={{ fontSize: 15, lineHeight: 1.75, color: 'var(--text-muted)', fontWeight: 300, marginTop: 12 }}>{children}</p>
}

function Note({ children }) {
  return (
    <div style={{ marginTop: 16, padding: '14px 16px', background: 'var(--surface)',
      border: '1px solid var(--border)', borderLeft: '3px solid var(--teal-dim)',
      borderRadius: '0 var(--radius-sm) var(--radius-sm) 0',
      fontSize: 13.5, color: 'var(--text-muted)', lineHeight: 1.6, fontWeight: 300 }}>
      {children}
    </div>
  )
}

export default function Privacy() {
  return (
    <>
      {/* Nav */}
      <nav style={{ position: 'sticky', top: 0, zIndex: 100, borderBottom: '1px solid var(--border)',
        background: 'rgba(8,11,15,0.88)', backdropFilter: 'blur(16px)' }}>
        <div style={{ maxWidth: 1100, margin: '0 auto', padding: '0 clamp(20px,5vw,64px)',
          height: 60, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Link to="/" style={{ display: 'flex', alignItems: 'center', gap: 10, color: 'var(--text)' }}>
            <Logo size={24} />
            <span style={{ fontFamily: 'var(--font-display)', fontSize: 17, fontWeight: 800, letterSpacing: '-0.01em' }}>
              Specter
            </span>
          </Link>
          <Link to="/" style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13, color: 'var(--text-dim)',
            transition: 'color 0.15s ease' }}>
            <svg width={14} height={14} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
              <polyline points="15 18 9 12 15 6"/>
            </svg>
            Back to home
          </Link>
        </div>
      </nav>

      {/* Hero */}
      <div style={{ padding: 'clamp(56px,8vw,96px) 0 clamp(40px,5vw,64px)', borderBottom: '1px solid var(--border)' }}>
        <div style={container}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, letterSpacing: '0.12em',
            color: 'var(--teal)', textTransform: 'uppercase', marginBottom: 16 }}>
            Legal
          </div>
          <h1 style={{ fontFamily: 'var(--font-display)', fontSize: 'clamp(32px,5vw,52px)',
            fontWeight: 800, letterSpacing: '-0.03em', lineHeight: 1.08, marginBottom: 16 }}>
            Privacy Policy
          </h1>
          <p style={{ fontSize: 17, lineHeight: 1.7, color: 'var(--text-muted)', fontWeight: 300, maxWidth: '55ch' }}>
            Specter is a privacy tool. It would be absurd if it weren't private itself. Here's exactly what it does — and doesn't — do with your data.
          </p>
          <div style={{ display: 'flex', gap: 20, marginTop: 20, flexWrap: 'wrap' }}>
            {['Last updated: June 2026', 'Effective: v1.0+'].map(t => (
              <span key={t} style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)', letterSpacing: '0.04em' }}>{t}</span>
            ))}
          </div>
        </div>
      </div>

      {/* Content */}
      <div style={{ padding: 'clamp(40px,6vw,72px) 0' }}>
        <div style={container}>

          {/* TL;DR card */}
          <div style={{ background: 'rgba(56,163,184,0.05)', border: '1px solid var(--teal-dim)',
            borderRadius: 'var(--radius-lg)', padding: '24px 28px', display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, letterSpacing: '0.1em', color: 'var(--teal)', textTransform: 'uppercase' }}>
              TL;DR — The short version
            </div>
            <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 10 }}>
              {[
                'All browsing data stays on your device. Nothing is transmitted anywhere.',
                'Specter collects zero telemetry, analytics, or usage data about you.',
                'ML inference runs locally via ONNX Runtime + WebAssembly — no cloud calls, ever.',
                'Optional VirusTotal lookups send only the domain name (never the full URL) and require your own API key.',
                'Specter requests the minimum Chrome permissions needed to function.',
              ].map((text, i) => (
                <li key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                  <svg width={15} height={15} viewBox="0 0 24 24" fill="none" stroke="#3DBE7A" strokeWidth="2.5" style={{ flexShrink: 0, marginTop: 3 }}>
                    <polyline points="20 6 9 17 4 12"/>
                  </svg>
                  <span style={{ flex: 1, minWidth: 0, fontSize: 14.5, color: 'var(--text-muted)', lineHeight: 1.6 }}>
                    {text}
                  </span>
                </li>
              ))}
            </ul>
          </div>

          <Section title="1. Data Specter collects">
            <P>Specter intercepts network requests made by your browser and classifies them locally. The following data is captured per request and stored in <code style={codeStyle}>chrome.storage.local</code> on your device:</P>
            <Table
              cols={['Field', 'Description', 'Leaves device?']}
              rows={[
                ['Full URL', 'The complete request URL', 'Never'],
                ['Initiator domain', 'The site that triggered the request', 'Never'],
                ['Request headers', 'HTTP headers sent with the request', 'Never'],
                ['Response status & size', 'HTTP status code and response size in bytes', 'Never'],
                ['Content-type', 'MIME type of the response', 'Never'],
                ['Timing', 'Milliseconds after page load events', 'Never'],
                ['ML classification', 'Category and confidence score assigned by the local model', 'Never'],
              ]}
            />
            <Note>Response body contents are never captured — this is an accepted architectural tradeoff that also strengthens privacy guarantees.</Note>
          </Section>

          <Section title="2. Where data is stored">
            <P>All data is stored exclusively in <code style={codeStyle}>chrome.storage.local</code> on your device. It is never synced to Chrome's cloud storage, never written to a remote database, and never transmitted to any server.</P>
            <Table
              cols={['Storage key', 'Contents']}
              rows={[
                ['session:current', 'Active session metadata'],
                ['requests:{session_id}', 'Classified request objects'],
                ['scores:{session_id}', 'Per-site privacy scores'],
                ['sessions:history', 'Session summaries'],
                ['settings', 'User preferences'],
                ['blocking:dynamic_domains', 'Domains in active block rules'],
                ['blocking:allowlist', 'Per-site domain overrides'],
                ['fp:session_seed', 'PRNG seed for fingerprint defense (session storage — cleared on tab close)'],
              ]}
            />
            <P>You can clear all stored data at any time from <strong style={{ color: 'var(--text)' }}>Dashboard → Settings → Clear all data</strong>, or by removing the extension from Chrome.</P>
          </Section>

          <Section title="3. Chrome permissions">
            <P>Specter requests only the permissions necessary to function:</P>
            <Table
              cols={['Permission', 'Why it\'s needed']}
              rows={[
                ['webRequest', 'Intercepts network requests for classification'],
                ['storage', 'Saves classified requests and settings locally'],
                ['declarativeNetRequest', 'Implements optional blocking via Chrome\'s native API'],
                ['tabs', 'Associates requests with the correct browser tab'],
                ['host permissions', 'Required by webRequest to observe cross-origin requests'],
              ]}
            />
            <Note>Specter does not request <code style={codeStyle}>history</code>, <code style={codeStyle}>bookmarks</code>, <code style={codeStyle}>cookies</code>, or <code style={codeStyle}>identity</code>.</Note>
          </Section>

          <Section title="4. Optional VirusTotal lookups">
            <P>This feature is <strong style={{ color: 'var(--text)' }}>disabled by default</strong> and requires you to supply your own VirusTotal API key in Settings. When triggered, only the <strong style={{ color: 'var(--text)' }}>domain name</strong> is sent — never the full URL path. Your API key is stored locally and never transmitted except directly to the VirusTotal API.</P>
            <P>VirusTotal is operated by Google. See their <a href="https://support.virustotal.com/hc/en-us/articles/115002168385-Privacy-Policy" target="_blank" rel="noopener noreferrer" style={{ color: 'var(--teal)' }}>privacy policy</a>.</P>
          </Section>

          <Section title="5. What Specter does not do">
            <ul style={{ marginTop: 12, paddingLeft: 0, display: 'flex', flexDirection: 'column', gap: 8, listStyle: 'none' }}>
              {[
                'Does not collect telemetry, analytics, or crash reports',
                'Does not sync browsing data to any cloud service',
                'Does not proxy your traffic through any intermediate server',
                'Does not upload request data, URLs, or session history anywhere',
                'Does not run ads or monetize your browsing behavior',
                'Does not use remote code execution — all scripts are bundled inside the extension',
              ].map(t => (
                <li key={t} style={{ display: 'flex', alignItems: 'flex-start', gap: 10,
                  fontSize: 15, color: 'var(--text-muted)', fontWeight: 300, lineHeight: 1.6 }}>
                  <span style={{ color: 'var(--text-dim)', marginTop: 2 }}>—</span>
                  {t}
                </li>
              ))}
            </ul>
          </Section>

          <Section title="6. Open source & auditability">
            <P>Specter is fully open source. Every claim in this policy can be verified by reading the code.</P>
            <P><a href="https://github.com/divij404/specter" target="_blank" rel="noopener noreferrer" style={{ color: 'var(--teal)' }}>github.com/divij404/specter →</a></P>
          </Section>

          <Section title="7. Contact">
            <P>Questions? Open an issue on <a href="https://github.com/divij404/specter/issues" target="_blank" rel="noopener noreferrer" style={{ color: 'var(--teal)' }}>GitHub</a>.</P>
          </Section>

        </div>
      </div>

      <Footer />
    </>
  )
}
