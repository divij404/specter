import React from 'react'
import Nav from '../components/Nav'
import LiveFeed from '../components/LiveFeed'
import Footer from '../components/Footer'

const CWS_URL = 'https://chromewebstore.google.com/detail/specter/dimockbooampdcmcboibloaflhmpokbl'
const codeStyle = { fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--teal)', background: 'var(--teal-glow)', padding: '1px 5px', borderRadius: 3 }
const GH_URL  = 'https://github.com/divij404/specter'

/* ─── shared ─── */
const container = { maxWidth: 1100, margin: '0 auto', padding: '0 clamp(20px,5vw,64px)' }
const sectionPad = { padding: 'clamp(64px,8vw,112px) 0' }

function SectionLabel({ children }) {
  return (
    <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, letterSpacing: '0.12em',
      color: 'var(--teal)', textTransform: 'uppercase', marginBottom: 16 }}>
      {children}
    </div>
  )
}
function SectionTitle({ children, style }) {
  return (
    <h2 style={{ fontFamily: 'var(--font-display)', fontSize: 'clamp(28px,3.5vw,44px)',
      fontWeight: 800, letterSpacing: '-0.03em', lineHeight: 1.1,
      color: 'var(--text)', marginBottom: 16, ...style }}>
      {children}
    </h2>
  )
}
function SectionSub({ children }) {
  return (
    <p style={{ fontSize: 17, lineHeight: 1.7, color: 'var(--text-muted)', maxWidth: '60ch', fontWeight: 300 }}>
      {children}
    </p>
  )
}

/* ─── Hero ─── */
function Hero() {
  return (
    <section style={{
      padding: 'clamp(100px,14vw,160px) 0 clamp(64px,8vw,96px)',
      position: 'relative', overflow: 'hidden',
    }}>
      {/* bg glow */}
      <div style={{
        position: 'absolute', top: -120, left: '50%', transform: 'translateX(-50%)',
        width: 900, height: 600,
        background: 'radial-gradient(ellipse, rgba(56,163,184,0.07) 0%, transparent 70%)',
        pointerEvents: 'none',
      }} />
      {/* grid texture */}
      <div style={{
        position: 'absolute', inset: 0, pointerEvents: 'none', opacity: 0.18,
        backgroundImage: 'linear-gradient(var(--border) 1px, transparent 1px), linear-gradient(90deg, var(--border) 1px, transparent 1px)',
        backgroundSize: '40px 40px',
        maskImage: 'radial-gradient(ellipse 80% 60% at 50% 0%, black 0%, transparent 100%)',
        WebkitMaskImage: 'radial-gradient(ellipse 80% 60% at 50% 0%, black 0%, transparent 100%)',
      }} />

      <div style={{ ...container, position: 'relative', zIndex: 1 }}>
        <div style={{
          display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
          gap: 64, alignItems: 'center',
        }}>
          {/* Left */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 28 }}>
            <h1 style={{
              fontFamily: 'var(--font-display)', fontSize: 'clamp(40px,5.5vw,68px)',
              fontWeight: 800, lineHeight: 1.07, letterSpacing: '-0.03em',
              animation: 'fade-up 0.5s 0.08s ease-out both',
            }}>
              See every tracker<br />
              <span style={{ color: 'var(--teal)' }}>before it sees you.</span>
            </h1>

            <p style={{
              fontSize: 17, lineHeight: 1.7, color: 'var(--text-muted)', maxWidth: '52ch',
              fontWeight: 300, animation: 'fade-up 0.5s 0.16s ease-out both',
            }}>
              Specter intercepts, classifies, and visualizes every tracker,
              fingerprinter, and session replay tool firing on any site — in
              real time, entirely inside your browser. No proxy. No server. No data leaves your machine.
            </p>

            <div style={{
              display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap',
              animation: 'fade-up 0.5s 0.24s ease-out both',
            }}>
              <BtnPrimary href={CWS_URL}>
                <DownloadIcon /> Add to Chrome — free
              </BtnPrimary>
              <BtnGhost href={GH_URL}>
                <GithubIcon /> View source
              </BtnGhost>
            </div>

            <div style={{
              display: 'flex', alignItems: 'center', gap: 20, flexWrap: 'wrap',
              animation: 'fade-up 0.5s 0.32s ease-out both',
            }}>
              {[
                { icon: <ShieldIcon />, text: 'Zero telemetry' },
                { icon: <ClockIcon />,  text: '<20ms inference' },
                { icon: <PulseIcon />,  text: 'ML-based, not blocklists' },
              ].map(({ icon, text }) => (
                <div key={text} style={{ display: 'flex', alignItems: 'center', gap: 6,
                  fontFamily: 'var(--font-mono)', fontSize: 11.5, color: 'var(--text-dim)', letterSpacing: '0.03em' }}>
                  <span style={{ color: 'var(--teal)', opacity: 0.7 }}>{icon}</span>
                  {text}
                </div>
              ))}
            </div>
          </div>

          {/* Right — live feed */}
          <div style={{ animation: 'fade-up 0.6s 0.2s ease-out both' }}>
            <LiveFeed />
          </div>
        </div>
      </div>
    </section>
  )
}

/* ─── Stats ─── */
function Stats() {
  const items = [
    { num: '6',     label: 'Tracker Categories' },
    { num: '96.2%', label: 'Classifier Accuracy' },
    { num: '35%+',  label: 'Novel vs. Blocklists' },
    { num: '<50ms', label: 'ONNX Inference' },
  ]
  return (
    <div style={{ borderTop: '1px solid var(--border)', borderBottom: '1px solid var(--border)' }}>
      <div style={container}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)' }}>
          {items.map(({ num, label }, i) => (
            <div key={label} style={{
              padding: '32px 0', textAlign: 'center',
              borderRight: i < items.length - 1 ? '1px solid var(--border)' : 'none',
            }}>
              <div style={{ fontFamily: 'var(--font-display)', fontSize: 'clamp(28px,3vw,42px)',
                fontWeight: 800, letterSpacing: '-0.04em', color: 'var(--teal)', lineHeight: 1 }}>
                {num}
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, letterSpacing: '0.06em',
                color: 'var(--text-dim)', textTransform: 'uppercase', marginTop: 4 }}>
                {label}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

/* ─── Categories ─── */
const CATEGORIES = [
  { badge: 'tracker',   color: '#E05252', bg: 'rgba(224,82,82,0.1)',   icon: '🕵️', name: 'Behavioral Trackers',   label: 'TRACKER',       desc: 'Cross-site tracking scripts that build persistent user profiles across domains using request timing, referrer chains, and cookie patterns.' },
  { badge: 'fp',        color: '#FF8C00', bg: 'rgba(255,140,0,0.1)',   icon: '🔍', name: 'Fingerprinting Scripts', label: 'FINGERPRINT',   desc: 'Scripts that probe your browser\'s unique characteristics — canvas, WebGL, fonts, audio — to identify you without cookies.' },
  { badge: 'session',   color: '#8B5CF6', bg: 'rgba(139,92,246,0.1)',  icon: '📹', name: 'Session Replay',        label: 'SESSION REPLAY', desc: 'Tools like Hotjar, FullStory, and Microsoft Clarity that record every click, scroll, and keystroke — even when proxied through first-party domains.' },
  { badge: 'ad',        color: '#F0B429', bg: 'rgba(240,180,41,0.1)',  icon: '📣', name: 'Ad Networks',           label: 'AD NETWORK',    desc: 'Demand-side platforms, RTB exchanges, and audience measurement endpoints monetizing your browsing behavior in real time.' },
  { badge: 'analytics', color: '#38A3B8', bg: 'rgba(56,163,184,0.1)',  icon: '📊', name: 'Analytics',             label: 'ANALYTICS',     desc: 'Google Analytics, Mixpanel, Segment, and similar tools. Identified and quantified — so you decide how much measurement is acceptable.' },
  { badge: 'legit',     color: '#3DBE7A', bg: 'rgba(61,190,122,0.1)',  icon: '✅', name: 'Legitimate Third-Party', label: 'LEGITIMATE',    desc: 'CDNs, font services, open source libraries, and other requests with no tracking characteristics. Signal-to-noise clarity.' },
]

function Categories() {
  return (
    <section id="features" style={{ ...sectionPad, background: 'var(--bg-mid)' }}>
      <div style={container}>
        <SectionLabel>What Specter detects</SectionLabel>
        <SectionTitle>Six threat categories.<br />One ML model.</SectionTitle>
        <SectionSub>
          Specter classifies every network request using behavioral signatures — not just domain blocklists — so it catches threats existing tools miss.
        </SectionSub>

        <div style={{
          display: 'grid', gridTemplateColumns: 'repeat(3,1fr)',
          gap: 1, background: 'var(--border)',
          border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)',
          overflow: 'hidden', marginTop: 56,
        }}>
          {CATEGORIES.map(c => (
            <div key={c.badge} style={{
              background: 'var(--surface)', padding: '28px 24px',
              display: 'flex', flexDirection: 'column', gap: 12,
              transition: 'background-color 0.15s ease', cursor: 'default',
            }}
              onMouseEnter={e => e.currentTarget.style.background = 'var(--surface-raised)'}
              onMouseLeave={e => e.currentTarget.style.background = 'var(--surface)'}
            >
              <div style={{ width: 36, height: 36, borderRadius: 'var(--radius-sm)',
                background: c.bg, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 16 }}>
                {c.icon}
              </div>
              <div style={{ fontFamily: 'var(--font-display)', fontSize: 15, fontWeight: 700,
                color: 'var(--text)', letterSpacing: '-0.01em' }}>
                {c.name}
              </div>
              <p style={{ fontSize: 13.5, lineHeight: 1.6, color: 'var(--text-muted)', fontWeight: 300 }}>
                {c.desc}
              </p>
              <span style={{
                display: 'inline-flex', alignItems: 'center', padding: '2px 7px',
                borderRadius: 3, fontSize: 9.5, fontWeight: 500, letterSpacing: '0.04em',
                background: `${c.bg}`, color: c.color, alignSelf: 'flex-start',
              }}>
                {c.label}
              </span>
            </div>
          ))}
        </div>
      </div>

      <style>{`
        @media (max-width: 800px) {
          #features .cat-grid { grid-template-columns: 1fr 1fr !important; }
        }
        @media (max-width: 500px) {
          #features .cat-grid { grid-template-columns: 1fr !important; }
        }
      `}</style>
    </section>
  )
}

/* ─── How It Works ─── */
const STEPS = [
  { n: '01', title: 'Intercept via webRequest API',       desc: <>Chrome's <code style={codeStyle}>chrome.webRequest.onCompleted</code> captures every HTTP/HTTPS request: URL, headers, response size, timing, initiator — everything needed for classification.</> },
  { n: '02', title: 'Feature extraction',                 desc: 'Each request is reduced to ~27 behavioral features: subdomain depth, query parameter fingerprints, response timing relative to page load, CORS flags, and known tracking param presence.' },
  { n: '03', title: 'ONNX inference in the service worker', desc: 'An XGBoost classifier — exported to ONNX and bundled inside the extension — runs via WebAssembly in the service worker. Under 50ms per request. No network call.' },
  { n: '04', title: 'Live dashboard & privacy score',     desc: 'Results stream to the full-page dashboard with confidence scores, category badges, and a composite privacy risk score (0–100) per visited site.' },
]

const ARCH_LAYERS = [
  { tag: 'webRequest', name: 'Request Interceptor',  detail: 'MV3 service worker' },
  { tag: 'features',   name: 'Feature Extractor',    detail: '~27 signals' },
  { tag: 'onnx',       name: 'ML Classifier',        detail: 'XGBoost · WASM' },
  { tag: 'storage',    name: 'Local Storage',        detail: 'chrome.storage.local' },
  { tag: 'dashboard',  name: 'Live Dashboard',       detail: 'Extension tab' },
]

function HowItWorks() {
  return (
    <section id="how-it-works" style={{
      ...sectionPad, background: '#050709',
      borderTop: '1px solid var(--border)', borderBottom: '1px solid var(--border)',
    }}>
      <div style={container}>
        <SectionLabel>Under the hood</SectionLabel>
        <SectionTitle>No proxy. No server.<br />Just your browser.</SectionTitle>

        <div style={{
          display: 'grid', gridTemplateColumns: '1fr 1fr',
          gap: 80, alignItems: 'start', marginTop: 56,
        }}>
          {/* Steps */}
          <div>
            {STEPS.map((s, i) => (
              <div key={s.n} style={{
                display: 'grid', gridTemplateColumns: '48px 1fr', gap: 20,
                padding: '28px 0',
                borderBottom: i < STEPS.length - 1 ? '1px solid var(--border)' : 'none',
              }}>
                <div style={{
                  width: 40, height: 40, borderRadius: '50%',
                  border: '1px solid var(--border-bright)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-muted)',
                  background: 'var(--surface)',
                }}>
                  {s.n}
                </div>
                <div style={{ paddingTop: 8 }}>
                  <div style={{ fontFamily: 'var(--font-display)', fontSize: 16, fontWeight: 700,
                    color: 'var(--text)', letterSpacing: '-0.01em', marginBottom: 6 }}>
                    {s.title}
                  </div>
                  <div style={{ fontSize: 14, lineHeight: 1.65, color: 'var(--text-muted)', fontWeight: 300 }}>
                    {s.desc}
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* Arch card */}
          <div style={{
            background: 'var(--surface)', border: '1px solid var(--border)',
            borderRadius: 'var(--radius-lg)', padding: 28,
            display: 'flex', flexDirection: 'column', gap: 24,
            boxShadow: '0 12px 40px rgba(0,0,0,0.3)',
          }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, letterSpacing: '0.1em',
              color: 'var(--text-dim)', textTransform: 'uppercase' }}>
              Architecture
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {ARCH_LAYERS.map((l, i) => (
                <div key={l.tag}>
                  <div style={{
                    display: 'flex', alignItems: 'center', gap: 12,
                    padding: '12px 16px', background: 'var(--surface-raised)',
                    border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)',
                  }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--teal)',
                      background: 'var(--teal-glow)', padding: '3px 7px', borderRadius: 3, whiteSpace: 'nowrap' }}>
                      {l.tag}
                    </span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-muted)' }}>
                      {l.name}
                    </span>
                    <span style={{ marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>
                      {l.detail}
                    </span>
                  </div>
                  {i < ARCH_LAYERS.length - 1 && (
                    <div style={{ display: 'flex', justifyContent: 'center', color: 'var(--text-dim)', fontSize: 12, padding: '2px 0' }}>↓</div>
                  )}
                </div>
              ))}
            </div>
            <div style={{
              display: 'flex', alignItems: 'flex-start', gap: 10, padding: '12px 14px',
              background: 'rgba(56,163,184,0.06)', border: '1px solid var(--teal-dim)',
              borderRadius: 'var(--radius-sm)', fontSize: 13, color: 'var(--teal)', lineHeight: 1.5,
            }}>
              <ShieldIcon />
              All data stays in <code style={codeStyle}>chrome.storage.local</code>. Nothing is transmitted to any external server. Ever.
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}

/* ─── Compare ─── */
function Compare() {
  return (
    <section id="compare" style={{ ...sectionPad, background: 'var(--bg-mid)' }}>
      <div style={container}>
        <SectionLabel>Specter vs. uBlock Origin</SectionLabel>
        <SectionTitle>Catches what blocklists miss.</SectionTitle>
        <SectionSub>
          uBlock Origin is excellent at blocking known domains. Specter classifies behavior — catching novel trackers, proxied session replay tools, and first-party disguised tracking that no blocklist covers.
        </SectionSub>
        <p style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)', marginTop: 12, letterSpacing: '0.04em' }}>
          ↓ Illustrative example
        </p>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24, marginTop: 56 }}>
          <CompareCard title="Specter detects" count="47 threats" countType="high" rows={[
            { color: '#E05252', domain: 'clarity.ms via first-party proxy', badge: 'NOVEL', badgeType: 'novel' },
            { color: '#FF8C00', domain: 'cdn.shopify.com/fingerprint.js',   badge: 'NOVEL', badgeType: 'novel' },
            { color: '#8B5CF6', domain: 'hj.internal.co (hotjar proxy)',    badge: 'NOVEL', badgeType: 'novel' },
            { color: '#F0B429', domain: 'doubleclick.net',                  badge: 'BOTH',  badgeType: 'both' },
            { color: '#38A3B8', domain: 'google-analytics.com/collect',     badge: 'BOTH',  badgeType: 'both' },
          ]} />
          <CompareCard title="uBlock Origin detects" count="31 threats" countType="low" rows={[
            { color: '#5A7090', domain: 'clarity.ms via first-party proxy', badge: 'MISSED', badgeType: 'missed' },
            { color: '#5A7090', domain: 'cdn.shopify.com/fingerprint.js',   badge: 'MISSED', badgeType: 'missed' },
            { color: '#5A7090', domain: 'hj.internal.co (hotjar proxy)',    badge: 'MISSED', badgeType: 'missed' },
            { color: '#F0B429', domain: 'doubleclick.net',                  badge: 'BOTH',   badgeType: 'both' },
            { color: '#38A3B8', domain: 'google-analytics.com/collect',     badge: 'BOTH',   badgeType: 'both' },
          ]} />
        </div>
      </div>
    </section>
  )
}

function CompareCard({ title, count, countType, rows }) {
  const countStyle = countType === 'high'
    ? { background: 'rgba(56,163,184,0.12)', color: 'var(--teal)' }
    : { background: 'rgba(61,190,122,0.12)', color: 'var(--green)' }

  const BADGE = {
    novel:  { bg: 'rgba(255,140,0,0.15)',  color: '#FF8C00' },
    both:   { bg: 'rgba(61,190,122,0.1)',  color: '#3DBE7A' },
    missed: { bg: 'rgba(90,112,144,0.12)', color: '#5A7090' },
  }

  return (
    <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', overflow: 'hidden' }}>
      <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border)', background: 'var(--surface-raised)',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ fontFamily: 'var(--font-display)', fontSize: 14, fontWeight: 700, color: 'var(--text)' }}>{title}</span>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, padding: '3px 9px', borderRadius: 999, ...countStyle }}>{count}</span>
      </div>
      {rows.map((r, i) => (
        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 20px', fontSize: 13 }}>
          <div style={{ width: 7, height: 7, borderRadius: '50%', background: r.color, flexShrink: 0 }} />
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-muted)', flex: 1,
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.domain}</span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9.5, padding: '2px 7px', borderRadius: 3,
            ...BADGE[r.badgeType], letterSpacing: '0.04em', whiteSpace: 'nowrap' }}>{r.badge}</span>
        </div>
      ))}
    </div>
  )
}

/* ─── Privacy Cards ─── */
function PrivacySection() {
  const cards = [
    { title: 'No external servers', desc: 'Every request is intercepted, classified, and stored entirely within your Chrome extension. No data ever leaves your machine — not even anonymized analytics.' },
    { title: 'Minimum permissions', desc: <>Specter requests only what it needs: <code style={codeStyle}>webRequest</code>, <code style={codeStyle}>storage</code>, <code style={codeStyle}>declarativeNetRequest</code>. No broad host permissions. No tab history access.</> },
    { title: 'Fully open source', desc: 'Every line of code is auditable on GitHub. The ML model training pipeline, feature extraction, and inference are all public. No black boxes.' },
  ]
  return (
    <section style={sectionPad}>
      <div style={container}>
        <SectionLabel>Privacy by design</SectionLabel>
        <SectionTitle>A privacy tool that<br />practices what it preaches.</SectionTitle>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 24, marginTop: 56 }}>
          {cards.map(c => (
            <div key={c.title} style={{
              padding: '28px 24px', background: 'var(--surface)',
              border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)',
              display: 'flex', flexDirection: 'column', gap: 14,
            }}>
              <div style={{ width: 40, height: 40, borderRadius: 'var(--radius-sm)',
                background: 'var(--teal-glow)', border: '1px solid var(--teal-dim)',
                display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <ShieldIcon />
              </div>
              <div style={{ fontFamily: 'var(--font-display)', fontSize: 16, fontWeight: 700,
                color: 'var(--text)', letterSpacing: '-0.01em' }}>{c.title}</div>
              <div style={{ fontSize: 14, lineHeight: 1.65, color: 'var(--text-muted)', fontWeight: 300 }}>{c.desc}</div>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}

/* ─── CTA ─── */
function CTA() {
  return (
    <section style={{
      padding: 'clamp(80px,10vw,128px) 0', textAlign: 'center',
      position: 'relative', overflow: 'hidden',
    }}>
      <div style={{
        position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
        width: 700, height: 400,
        background: 'radial-gradient(ellipse, rgba(56,163,184,0.08) 0%, transparent 70%)',
        pointerEvents: 'none',
      }} />
      <div style={{ ...container, position: 'relative', zIndex: 1,
        display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 28 }}>
        <h2 style={{ fontFamily: 'var(--font-display)', fontSize: 'clamp(32px,4vw,52px)',
          fontWeight: 800, letterSpacing: '-0.03em', lineHeight: 1.08, maxWidth: '16ch' }}>
          Start seeing what's tracking you.
        </h2>
        <p style={{ fontSize: 17, color: 'var(--text-muted)', maxWidth: '50ch', lineHeight: 1.7, fontWeight: 300 }}>
          Install the extension. Open any website. Watch Specter reveal everything firing in the background — in real time.
        </p>
        <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap', justifyContent: 'center' }}>
          <BtnPrimary href={CWS_URL} large>
            <DownloadIcon /> Add to Chrome — free
          </BtnPrimary>
          <BtnGhost href={GH_URL} large>
            View on GitHub
          </BtnGhost>
        </div>
        <p style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)', letterSpacing: '0.04em' }}>
          Available on the Chrome Web Store · Chrome 114+ · No account required
        </p>
      </div>
    </section>
  )
}

/* ─── Button helpers ─── */
function BtnPrimary({ href, children, large }) {
  const [hov, setHov] = React.useState(false)
  return (
    <a href={href} target="_blank" rel="noopener noreferrer"
      onMouseEnter={() => setHov(true)} onMouseLeave={() => setHov(false)}
      style={{
        display: 'inline-flex', alignItems: 'center', gap: 8,
        padding: large ? '15px 32px' : '13px 26px',
        background: hov ? 'var(--teal-bright)' : 'var(--teal)',
        color: 'var(--bg)', borderRadius: 'var(--radius-sm)',
        fontSize: large ? 15.5 : 14.5, fontWeight: 600, letterSpacing: '0.01em',
        transform: hov ? 'translateY(-1px)' : 'none',
        boxShadow: hov ? '0 6px 20px rgba(56,163,184,0.25)' : 'none',
        transition: 'background-color 0.15s ease, transform 0.1s ease, box-shadow 0.15s ease',
        cursor: 'pointer',
      }}>
      {children}
    </a>
  )
}

function BtnGhost({ href, children, large }) {
  const [hov, setHov] = React.useState(false)
  return (
    <a href={href} target="_blank" rel="noopener noreferrer"
      onMouseEnter={() => setHov(true)} onMouseLeave={() => setHov(false)}
      style={{
        display: 'inline-flex', alignItems: 'center', gap: 8,
        padding: large ? '15px 28px' : '13px 22px',
        border: `1px solid ${hov ? 'var(--teal-dim)' : 'var(--border-bright)'}`,
        borderRadius: 'var(--radius-sm)', fontSize: large ? 15.5 : 14.5, fontWeight: 400,
        color: hov ? 'var(--teal)' : 'var(--text-muted)',
        transform: hov ? 'translateY(-1px)' : 'none',
        transition: 'border-color 0.15s ease, color 0.15s ease, transform 0.1s ease',
        cursor: 'pointer',
      }}>
      {children}
    </a>
  )
}

/* ─── Icons ─── */
const iconProps = { width: 14, height: 14, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 2 }
function DownloadIcon() { return <svg {...iconProps} strokeWidth="2.5"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg> }
function GithubIcon() { return <svg {...iconProps}><path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 00-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0020 4.77 5.07 5.07 0 0019.91 1S18.73.65 16 2.48a13.38 13.38 0 00-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 005 4.77a5.44 5.44 0 00-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 009 18.13V22"/></svg> }
function ShieldIcon() { return <svg {...{ ...iconProps, width: 16, height: 16 }}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> }
function ClockIcon() { return <svg {...iconProps}><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg> }
function PulseIcon() { return <svg {...iconProps}><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg> }

export default function Home() {
  return (
    <>
      <Nav />
      <main style={{ paddingTop: 60 }}>
        <Hero />
        <Stats />
        <Categories />
        <HowItWorks />
        <Compare />
        <PrivacySection />
        <CTA />
      </main>
      <Footer />
    </>
  )
}
