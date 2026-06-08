import { useState, useEffect, useRef } from 'react'

const FEED_DATA = [
  { badge: 'tracker',   label: 'TRACKER',       domain: 'pixel.rubiconproject.com',   conf: '94%', confClass: 'high', time: '12ms'  },
  { badge: 'fp',        label: 'FINGERPRINT',   domain: 'cdn.shopify.com',             conf: '87%', confClass: 'high', time: '23ms'  },
  { badge: 'session',   label: 'SESSION REPLAY', domain: 'hj.internal.co',             conf: '91%', confClass: 'high', time: '8ms'   },
  { badge: 'analytics', label: 'ANALYTICS',     domain: 'google-analytics.com',        conf: '99%', confClass: 'high', time: '31ms'  },
  { badge: 'legit',     label: 'LEGITIMATE',    domain: 'fonts.googleapis.com',        conf: '97%', confClass: 'low',  time: '44ms'  },
  { badge: 'ad',        label: 'AD NETWORK',    domain: 'doubleclick.net',             conf: '96%', confClass: 'high', time: '19ms'  },
  { badge: 'tracker',   label: 'TRACKER',       domain: 'mc.us13.list-manage.com',    conf: '78%', confClass: 'med',  time: '55ms'  },
  { badge: 'fp',        label: 'FINGERPRINT',   domain: 'ct.pinterest.com',           conf: '83%', confClass: 'high', time: '62ms'  },
  { badge: 'legit',     label: 'LEGITIMATE',    domain: 'cdnjs.cloudflare.com',       conf: '98%', confClass: 'low',  time: '70ms'  },
  { badge: 'session',   label: 'SESSION REPLAY', domain: 'fullstory.com/rec/bundle',  conf: '89%', confClass: 'high', time: '88ms'  },
  { badge: 'ad',        label: 'AD NETWORK',    domain: 'bid.g.doubleclick.net',      conf: '95%', confClass: 'high', time: '95ms'  },
  { badge: 'analytics', label: 'ANALYTICS',     domain: 'a.clarity.ms/collect',       conf: '92%', confClass: 'high', time: '103ms' },
]

const BADGE_STYLES = {
  tracker:   { background: 'rgba(224,82,82,0.15)',   color: '#E05252' },
  fp:        { background: 'rgba(255,140,0,0.15)',   color: '#FF8C00' },
  session:   { background: 'rgba(139,92,246,0.15)',  color: '#8B5CF6' },
  ad:        { background: 'rgba(240,180,41,0.15)',  color: '#F0B429' },
  analytics: { background: 'rgba(56,163,184,0.15)',  color: '#38A3B8' },
  legit:     { background: 'rgba(61,190,122,0.15)',  color: '#3DBE7A' },
}

const CONF_COLORS = { high: '#E05252', med: '#F0B429', low: '#3DBE7A' }

export default function LiveFeed() {
  const [rows, setRows] = useState(FEED_DATA.slice(0, 5))
  const [shownIdx, setShownIdx] = useState(5)
  const [reqCount, setReqCount] = useState(5)
  const [trackerCount, setTrackerCount] = useState(4)
  const shownRef = useRef(5)

  useEffect(() => {
    const id = setInterval(() => {
      const item = FEED_DATA[shownRef.current % FEED_DATA.length]
      shownRef.current++
      setRows(prev => [{ ...item, isNew: true }, ...prev].slice(0, 14))
      setReqCount(c => c + 1)
      if (item.badge !== 'legit') setTrackerCount(c => c + 1)
    }, 1200)
    return () => clearInterval(id)
  }, [])

  const risk = Math.min(99, Math.round(50 + (trackerCount / reqCount) * 60))
  const riskColor = risk > 70 ? '#E05252' : risk > 45 ? '#F0B429' : '#3DBE7A'

  return (
    <div style={{
      background: 'var(--surface)', border: '1px solid var(--border)',
      borderRadius: 'var(--radius-lg)', overflow: 'hidden',
      boxShadow: '0 0 0 1px rgba(56,163,184,0.06), 0 24px 60px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.04)',
    }}>
      {/* Titlebar */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '12px 16px', borderBottom: '1px solid var(--border)',
        background: 'var(--surface-raised)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ display: 'flex', gap: 5 }}>
            {['#FF5F57','#FEBC2E','#28C840'].map(c => (
              <div key={c} style={{ width: 9, height: 9, borderRadius: '50%', background: c }} />
            ))}
          </div>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)', letterSpacing: '0.04em' }}>
            specter — request feed
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--teal)', letterSpacing: '0.06em' }}>
          <div style={{ width: 5, height: 5, borderRadius: '50%', background: 'var(--teal)', animation: 'pulse-dot 1.5s ease infinite' }} />
          LIVE
        </div>
      </div>

      {/* Feed body */}
      <div style={{ height: 280, overflow: 'hidden', position: 'relative' }}>
        <div style={{
          position: 'absolute', bottom: 0, left: 0, right: 0, height: 60, zIndex: 1,
          background: 'linear-gradient(transparent, var(--surface))', pointerEvents: 'none',
        }} />
        {rows.map((row, i) => (
          <FeedRow key={`${row.domain}-${i}`} row={row} isNew={i === 0 && row.isNew} />
        ))}
      </div>

      {/* Footer */}
      <div style={{
        padding: '10px 16px', borderTop: '1px solid var(--border)',
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        background: 'var(--surface-raised)',
      }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10.5, color: 'var(--text-dim)' }}>
          <span style={{ color: 'var(--text-muted)' }}>{reqCount}</span> requests ·{' '}
          <span style={{ color: 'var(--text-muted)' }}>{trackerCount}</span> threats
        </span>
        <span style={{ display: 'flex', alignItems: 'center', gap: 6, fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>
          RISK <span style={{ fontSize: 18, fontWeight: 500, color: riskColor }}>{risk}</span>
        </span>
      </div>
    </div>
  )
}

function FeedRow({ row, isNew }) {
  return (
    <div style={{
      display: 'grid', gridTemplateColumns: 'auto 1fr 56px 44px',
      alignItems: 'center', gap: 10, padding: '7px 16px',
      borderBottom: '1px solid rgba(28,37,53,0.5)',
      fontFamily: 'var(--font-mono)', fontSize: 11,
      animation: isNew ? 'slide-in 0.3s ease-out both' : 'none',
      transition: 'background-color 0.1s ease',
    }}>
      <span style={{
        display: 'inline-flex', alignItems: 'center', flexShrink: 0,
        padding: '2px 7px', borderRadius: 3,
        fontSize: 9.5, fontWeight: 500, letterSpacing: '0.04em',
        whiteSpace: 'nowrap', lineHeight: 1.2,
        ...BADGE_STYLES[row.badge],
      }}>
        {row.label}
      </span>
      <span style={{ color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {row.domain}
      </span>
      <span style={{ fontSize: 10.5, textAlign: 'right', color: CONF_COLORS[row.confClass] }}>
        {row.conf}
      </span>
      <span style={{ color: 'var(--text-dim)', fontSize: 10, textAlign: 'right' }}>
        {row.time}
      </span>
    </div>
  )
}
