import { Link } from 'react-router-dom'
import Logo from './Logo'

const CWS_URL = 'https://chromewebstore.google.com/detail/specter/dimockbooampdcmcboibloaflhmpokbl'

export default function Nav() {
  return (
    <nav style={{
      position: 'fixed', top: 0, left: 0, right: 0, zIndex: 100,
      borderBottom: '1px solid var(--border)',
      background: 'rgba(8,11,15,0.82)',
      backdropFilter: 'blur(16px)',
      WebkitBackdropFilter: 'blur(16px)',
    }}>
      <div style={{
        maxWidth: 1100, margin: '0 auto',
        padding: '0 clamp(20px, 5vw, 64px)',
        height: 60, display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      }}>
        <Link to="/" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Logo size={28} />
          <span style={{ fontFamily: 'var(--font-display)', fontSize: 17, fontWeight: 800, letterSpacing: '-0.01em' }}>
            Specter
          </span>
        </Link>

        <ul style={{ display: 'flex', alignItems: 'center', gap: 32, listStyle: 'none' }}>
          {[
            { label: 'Features', href: '/#features' },
            { label: 'How it works', href: '/#how-it-works' },
            { label: 'GitHub', href: 'https://github.com/divij404/specter', external: true },
          ].map(({ label, href, external }) => (
            <li key={label} style={{ display: 'none' }} className="nav-link-item">
              {external
                ? <a href={href} target="_blank" rel="noopener noreferrer" style={linkStyle}>{label}</a>
                : <a href={href} style={linkStyle}>{label}</a>
              }
            </li>
          ))}
          {/* Always-visible links */}
          <li><a href="/#features" style={linkStyle}>Features</a></li>
          <li><a href="/#how-it-works" style={linkStyle}>How it works</a></li>
          <li><a href="https://github.com/divij404/specter" target="_blank" rel="noopener noreferrer" style={linkStyle}>GitHub</a></li>
          <li>
            <a href={CWS_URL} target="_blank" rel="noopener noreferrer" style={ctaStyle}
              onMouseEnter={e => { e.currentTarget.style.background = 'var(--teal-bright)'; e.currentTarget.style.transform = 'translateY(-1px)' }}
              onMouseLeave={e => { e.currentTarget.style.background = 'var(--teal)'; e.currentTarget.style.transform = 'translateY(0)' }}
            >
              <DownloadIcon /> Add to Chrome
            </a>
          </li>
        </ul>
      </div>

      <style>{`
        @media (max-width: 700px) {
          nav ul li:not(:last-child) { display: none !important; }
        }
      `}</style>
    </nav>
  )
}

const linkStyle = {
  fontSize: 13.5, fontWeight: 400, color: 'var(--text-muted)',
  transition: 'color 0.15s ease', letterSpacing: '0.01em', padding: '8px 4px',
}

const ctaStyle = {
  display: 'inline-flex', alignItems: 'center', gap: 8,
  padding: '8px 18px', background: 'var(--teal)', color: 'var(--bg)',
  borderRadius: 'var(--radius-sm)', fontSize: 13, fontWeight: 600,
  letterSpacing: '0.02em', transition: 'background-color 0.15s ease, transform 0.1s ease',
  cursor: 'pointer',
}

function DownloadIcon() {
  return (
    <svg width={12} height={12} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
      <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
      <polyline points="7 10 12 15 17 10"/>
      <line x1="12" y1="15" x2="12" y2="3"/>
    </svg>
  )
}
