// A CSS/SVG "3D" shield-and-lock mark - no image assets or 3D engine
// needed. The illusion of depth comes from layered drop-shadows plus a
// slow perspective rotation, not an actual 3D renderer.
export default function ShieldLogo({ size = 120 }) {
  return (
    <div
      style={{
        width: size,
        height: size,
        perspective: 700,
      }}
    >
      <svg
        viewBox="0 0 100 100"
        width={size}
        height={size}
        style={{
          animation: "float3d 7s ease-in-out infinite",
          transformStyle: "preserve-3d",
          filter: "drop-shadow(0 18px 24px rgba(193, 95, 60, 0.35))",
        }}
      >
        <defs>
          <linearGradient id="shieldFace" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#e2794f" />
            <stop offset="55%" stopColor="#c15f3c" />
            <stop offset="100%" stopColor="#963f24" />
          </linearGradient>
          <linearGradient id="shieldEdge" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#7a3319" />
            <stop offset="100%" stopColor="#5a2412" />
          </linearGradient>
          <linearGradient id="lockGrad" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#fff6f0" />
            <stop offset="100%" stopColor="#f4e3d8" />
          </linearGradient>
        </defs>

        {/* extruded "side" layer for the 3D feel */}
        <path
          d="M50 6 L90 20 V48 C90 72 73 88 50 98 C27 88 10 72 10 48 V20 Z"
          fill="url(#shieldEdge)"
          transform="translate(0,4)"
        />
        {/* front face */}
        <path
          d="M50 4 L90 18 V46 C90 70 73 86 50 96 C27 86 10 70 10 46 V18 Z"
          fill="url(#shieldFace)"
          stroke="rgba(255,255,255,0.25)"
          strokeWidth="0.5"
        />

        {/* padlock glyph */}
        <rect x="38" y="46" width="24" height="20" rx="3" fill="url(#lockGrad)" />
        <path
          d="M42 46 V38 a8 8 0 0 1 16 0 v8"
          fill="none"
          stroke="url(#lockGrad)"
          strokeWidth="4.5"
          strokeLinecap="round"
        />
        <circle cx="50" cy="54" r="3" fill="#c15f3c" />
        <rect x="48.5" y="54" width="3" height="6" rx="1.2" fill="#c15f3c" />
      </svg>
    </div>
  );
}
