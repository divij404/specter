export default function Logo({ size = 28 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 128 128" xmlns="http://www.w3.org/2000/svg">
      <rect x="0" y="0" width="128" height="128" rx="20" fill="#080B0F"/>
      <rect x="1" y="1" width="126" height="126" rx="19.5" fill="none" stroke="#1C2535" strokeWidth="1.5"/>
      <circle cx="64" cy="54" r="44" fill="none" stroke="#38A3B8" strokeWidth="0.8" strokeOpacity="0.2" strokeDasharray="4 5"/>
      <path d="M30 64 Q30 20 64 20 Q98 20 98 64 L98 102 Q89 94 80 102 Q71 110 64 102 Q57 110 48 102 Q39 94 30 102 Z"
        fill="#E2E8F0" stroke="#263040" strokeWidth="1.2"/>
      <ellipse cx="51" cy="52" rx="7.5" ry="8.5" fill="#1A3D47"/>
      <ellipse cx="77" cy="52" rx="7.5" ry="8.5" fill="#1A3D47"/>
      <ellipse cx="51" cy="52" rx="4.5" ry="5" fill="#38A3B8"/>
      <ellipse cx="77" cy="52" rx="4.5" ry="5" fill="#38A3B8"/>
      <circle cx="52" cy="53" r="2" fill="#080B0F"/>
      <circle cx="78" cy="53" r="2" fill="#080B0F"/>
      <circle cx="49" cy="49" r="1.3" fill="#4AB3C7" opacity="0.9"/>
      <circle cx="75" cy="49" r="1.3" fill="#4AB3C7" opacity="0.9"/>
      <circle cx="106" cy="35" r="3.5" fill="#FF8C00" opacity="0.9"/>
      <circle cx="18"  cy="42" r="3"   fill="#FF8C00" opacity="0.8"/>
    </svg>
  )
}
