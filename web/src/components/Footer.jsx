import { Link } from 'react-router-dom'
import Logo from './Logo'

const CWS_URL = 'https://chromewebstore.google.com/detail/specter/dimockbooampdcmcboibloaflhmpokbl'

export default function Footer() {
  return (
    <footer style={{ borderTop: '1px solid var(--border)', padding: '40px 0' }}>
      <div style={{
        maxWidth: 1100, margin: '0 auto',
        padding: '0 clamp(20px, 5vw, 64px)',
        display: 'flex', alignItems: 'center',
        justifyContent: 'space-between', gap: 24, flexWrap: 'wrap',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Logo size={20} />
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11.5, color: 'var(--text-dim)' }}>
            Specter
          </span>
        </div>
        <ul style={{ display: 'flex', gap: 24, listStyle: 'none' }}>
          <li><a href="https://github.com/divij404/specter" target="_blank" rel="noopener noreferrer" style={linkStyle}>GitHub</a></li>
          <li><a href={CWS_URL} target="_blank" rel="noopener noreferrer" style={linkStyle}>Chrome Web Store</a></li>
          <li><Link to="/privacy" style={linkStyle}>Privacy</Link></li>
        </ul>
      </div>
    </footer>
  )
}

const linkStyle = {
  fontSize: 13, color: 'var(--text-dim)',
  transition: 'color 0.15s ease',
  onMouseEnter: undefined,
}
