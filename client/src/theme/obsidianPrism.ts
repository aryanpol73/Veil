/**
 * ============================================================================
 *  VEIL — DESIGN SYSTEM: "OBSIDIAN PRISM"
 * ============================================================================
 *  A dark frosted lens illuminated by prismatic refraction. Explicitly NOT
 *  flat #000000 / #121212. Every surface is a layered chromatic void with
 *  specular edges, so depth is communicated by *light leakage* rather than
 *  by drop shadows (which read as cheap on OLED).
 *
 *  Layer model (back -> front):
 *    L0  Chromatic void base gradient (#080914 -> #0D0B18)
 *    L1  Refraction orbs (blurred radial gradients, parallax on scroll)
 *    L2  Frosted glass surfaces (BlurView, dark tint, saturation boost)
 *    L3  Prismatic specular hairlines (top/left 8% white, cyan when active)
 *    L4  Content (mono HUD + humanist sans)
 *    L5  Forensic watermark (always last, non-interactive)
 * ============================================================================
 */

import { Platform, StyleSheet, TextStyle, ViewStyle } from 'react-native';

/* -------------------------------------------------------------------------- */
/* Color primitives                                                           */
/* -------------------------------------------------------------------------- */

/**
 * Applies an alpha channel to a 6-digit hex color, returning 8-digit hex.
 * Kept as hex (not rgba()) because react-native-svg gradient stops and
 * Android's BlurView overlay both handle #RRGGBBAA more predictably.
 */
export const withAlpha = (hex: string, alpha: number): string => {
  const clamped = Math.max(0, Math.min(1, alpha));
  const byte = Math.round(clamped * 255)
    .toString(16)
    .padStart(2, '0');
  return `${hex}${byte}`;
};

export const Palette = {
  /* --- Void substrate ---------------------------------------------------- */
  voidMidnight: '#080914', // Deep Midnight Indigo — primary base
  voidSmoke: '#0D0B18', // Smoke Pitch — bleed target
  voidTrench: '#050610', // Deepest recess (behind modals / scrim)

  /* --- Glass substrates -------------------------------------------------- */
  glassObsidian: '#161B2E', // Persistent bubble body
  glassQuartz: '#1A1726', // Timed bubble body (smoked quartz)
  glassShroud: '#1D1526', // View-Once body (crystalline shroud)
  glassElevated: '#12162A', // Sheets, composer tray

  /* --- Prismatic accents ------------------------------------------------- */
  prismCyan: '#00F0FF', // Primary interactive / active edges
  prismLime: '#A3FF12', // Secondary telemetry / verified state
  prismViolet: '#8A2BE2', // Ambient refraction only (never text)
  prismMagenta: '#EC4899', // View-Once / destructive-irreversible
  prismAmber: '#F59E0B', // Timed retention countdown
  prismEmerald: '#34D399', // Persistent retention micro-dot

  /* --- Text ramp --------------------------------------------------------- */
  textPrimary: '#E2E8F0', // Message bodies — ultra-crisp, high contrast
  textHud: '#94A3B8', // Monospace HUD / fingerprints — muted slate-cyan
  textMuted: '#5B6478', // Timestamps, disabled affordances
  textInverse: '#050610', // On-accent (e.g. inside cyan send pill)

  /* --- Structural -------------------------------------------------------- */
  hairline: '#FFFFFF', // Use via withAlpha(...) only
  danger: '#F43F5E',
} as const;

/**
 * Semantic border tokens. The "specular" pair is applied asymmetrically —
 * bright on the top/left, near-invisible on the bottom/right — which is what
 * makes a flat rect read as a physically bevelled piece of glass.
 */
export const Borders = {
  specularHigh: withAlpha(Palette.hairline, 0.08), // top / left
  specularLow: withAlpha(Palette.hairline, 0.02), // bottom / right
  activeHigh: withAlpha(Palette.prismCyan, 0.2), // focused / pressed
  activeLow: withAlpha(Palette.prismCyan, 0.06),
  hairWidth: StyleSheet.hairlineWidth,
  width: 1,
} as const;

/* -------------------------------------------------------------------------- */
/* Gradients & refraction orbs                                                */
/* -------------------------------------------------------------------------- */

/** Linear stops for the L0 chromatic void substrate. */
export const VoidGradient = {
  colors: [Palette.voidMidnight, '#0A0A16', Palette.voidSmoke] as const,
  locations: [0, 0.55, 1] as const,
  start: { x: 0.1, y: 0 },
  end: { x: 0.9, y: 1 },
} as const;

export interface RefractionOrb {
  /** Stable key for React reconciliation. */
  id: string;
  /** Core color at stop 0 (already alpha-baked per the design spec). */
  core: string;
  /** Normalized viewport anchor (0..1). */
  anchor: { x: number; y: number };
  /** Radius as a fraction of the viewport's shorter axis. */
  radius: number;
  /**
   * Parallax coefficient applied to scroll velocity. Negative values drift
   * against the finger, which reads as "the light source is behind the glass".
   */
  parallax: number;
  /** Independent idle drift period in ms (breathing, never fully static). */
  driftMs: number;
}

/**
 * Three orbs only. A fourth reads as noise and costs a full-screen composite
 * pass on mid-tier Android.
 */
export const RefractionOrbs: readonly RefractionOrb[] = [
  {
    id: 'cyan',
    core: withAlpha(Palette.prismCyan, 0.07), // spec #00F0FF12 ≈ 7%
    anchor: { x: 0.18, y: 0.12 },
    radius: 0.85,
    parallax: -0.16,
    driftMs: 14000,
  },
  {
    id: 'violet',
    core: withAlpha(Palette.prismViolet, 0.083), // spec #8A2BE215
    anchor: { x: 0.86, y: 0.38 },
    radius: 1.02,
    parallax: 0.24,
    driftMs: 19000,
  },
  {
    id: 'lime',
    core: withAlpha(Palette.prismLime, 0.031), // spec #A3FF1208
    anchor: { x: 0.42, y: 0.94 },
    radius: 0.7,
    parallax: -0.34,
    driftMs: 23000,
  },
] as const;

/* -------------------------------------------------------------------------- */
/* Blur                                                                       */
/* -------------------------------------------------------------------------- */

export const Blur = {
  /** Chat header / composer tray — heavy frosted saturation. */
  chrome: {
    intensity: 85,
    tint: 'dark' as const,
    /** Android's native blur is a no-op pre-31; force the Dimezis backend. */
    experimentalBlurMethod: 'dimezisBlurView' as const,
  },
  /** Message bubbles — lighter, so text stays crisp over the void. */
  surface: { intensity: 42, tint: 'dark' as const },
  /** View-Once shroud — near-opaque until the user holds. */
  shroud: { intensity: 96, tint: 'dark' as const },
  /**
   * Android BlurView renders lighter than iOS at identical intensity; we
   * composite a tint scrim underneath to normalize perceived density.
   */
  scrim: Platform.select({
    ios: withAlpha(Palette.voidMidnight, 0.28),
    default: withAlpha(Palette.voidMidnight, 0.52),
  })!,
} as const;

/* -------------------------------------------------------------------------- */
/* Typography                                                                 */
/* -------------------------------------------------------------------------- */

/**
 * Two families, zero exceptions:
 *  - Mono  => anything machine-authored (fingerprints, IDs, counters, labels)
 *  - Sans  => anything human-authored (message bodies, names)
 * The contrast between them is the entire HUD language.
 */
export const Fonts = {
  mono: Platform.select({
    ios: 'JetBrainsMono-Regular',
    android: 'JetBrainsMono-Regular',
    default: 'monospace',
  })!,
  monoBold: Platform.select({
    ios: 'JetBrainsMono-Bold',
    android: 'JetBrainsMono-Bold',
    default: 'monospace',
  })!,
  sans: Platform.select({
    ios: 'Inter-Regular',
    android: 'Inter-Regular',
    default: 'System',
  })!,
  sansMedium: Platform.select({
    ios: 'Inter-Medium',
    android: 'Inter-Medium',
    default: 'System',
  })!,
} as const;

export const Type: Record<string, TextStyle> = {
  /** Screen titles. */
  h1: {
    fontFamily: Fonts.monoBold,
    fontSize: 20,
    lineHeight: 24,
    letterSpacing: 0.5,
    color: Palette.textPrimary,
  },
  /** Section / peer identity in header. */
  h2: {
    fontFamily: Fonts.mono,
    fontSize: 15,
    lineHeight: 19,
    letterSpacing: 0.5,
    color: Palette.textPrimary,
  },
  /** Cryptographic fingerprints — always mono, always letterspaced. */
  fingerprint: {
    fontFamily: Fonts.mono,
    fontSize: 11,
    lineHeight: 14,
    letterSpacing: 1.1,
    color: Palette.textHud,
  },
  /** Small uppercase machine labels ("VIEW-ONCE", "GHOST"). */
  hudLabel: {
    fontFamily: Fonts.mono,
    fontSize: 9.5,
    lineHeight: 12,
    letterSpacing: 1.4,
    textTransform: 'uppercase',
    color: Palette.textHud,
  },
  /** Message bodies. */
  body: {
    fontFamily: Fonts.sans,
    fontSize: 15.5,
    lineHeight: 22,
    letterSpacing: 0.05,
    color: Palette.textPrimary,
  },
  /** Timestamps, ttl remainders. */
  meta: {
    fontFamily: Fonts.mono,
    fontSize: 10,
    lineHeight: 13,
    letterSpacing: 0.4,
    color: Palette.textMuted,
  },
  /** Composer input. */
  input: {
    fontFamily: Fonts.sans,
    fontSize: 16,
    lineHeight: 21,
    color: Palette.textPrimary,
  },
};

/* -------------------------------------------------------------------------- */
/* Space, radius, motion                                                      */
/* -------------------------------------------------------------------------- */

export const Space = { xxs: 2, xs: 4, sm: 8, md: 12, lg: 16, xl: 24, xxl: 32 } as const;

export const Radius = {
  sm: 8,
  md: 14,
  bubble: 20,
  /** The "tail" corner of a bubble, kept tight for a lens-cut feel. */
  bubbleTail: 6,
  pill: 999,
} as const;

/**
 * Reanimated v3 spring presets. Tactile => low damping ratio + high stiffness.
 * All durations are expressed as physics, never as timing curves, except for
 * opacity crossfades where physics reads as jitter.
 */
export const Motion = {
  /** Press-in / press-out on interactive glass. */
  tactile: { damping: 18, stiffness: 320, mass: 0.7 },
  /** Bubble entry — slight overshoot so it "lands". */
  land: { damping: 14, stiffness: 210, mass: 0.9 },
  /** Orb parallax — heavy, lagging, dreamlike. */
  ambient: { damping: 40, stiffness: 22, mass: 1.6 },
  /** Reveal / burn crossfades. */
  fade: { duration: 180 },
  burn: { duration: 420 },
} as const;

/* -------------------------------------------------------------------------- */
/* Retention mode theming                                                     */
/* -------------------------------------------------------------------------- */

export type RetentionMode = 'persistent' | 'timed' | 'viewOnce';

export interface RetentionTheme {
  label: string;
  /** Bubble fill. Alpha-baked; sits over BlurView. */
  fill: string;
  /** Accent used for the micro-dot / ring / edge glow. */
  accent: string;
  /** Outer edge glow color (shadowColor on iOS, border tint on Android). */
  edgeGlow: string;
  /** Single-codepoint glyph rendered in the bubble's HUD strip. */
  glyph: string;
}

export const Retention: Record<RetentionMode, RetentionTheme> = {
  persistent: {
    label: 'Persistent',
    fill: withAlpha(Palette.glassObsidian, 0.65), // rgba(22,27,46,0.65)
    accent: Palette.prismEmerald,
    edgeGlow: withAlpha(Palette.prismEmerald, 0.14),
    glyph: '▣',
  },
  timed: {
    label: 'Timed',
    fill: withAlpha(Palette.glassQuartz, 0.62),
    accent: Palette.prismAmber,
    edgeGlow: withAlpha(Palette.prismAmber, 0.22),
    glyph: '◷',
  },
  viewOnce: {
    label: 'View-Once',
    fill: withAlpha(Palette.glassShroud, 0.58),
    accent: Palette.prismMagenta,
    edgeGlow: withAlpha(Palette.prismMagenta, 0.34),
    glyph: '✦',
  },
};

/* -------------------------------------------------------------------------- */
/* Reusable surface styles                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Prismatic specular border. RN cannot render a per-edge gradient stroke, so
 * we fake it: a uniform low-alpha border plus an absolutely-positioned 1px
 * highlight on the top and left edges. Composited, it is indistinguishable
 * from a gradient stroke at device pixel ratios >= 2.
 */
export const Surface = StyleSheet.create({
  glass: {
    borderWidth: Borders.width,
    borderColor: Borders.specularLow,
    borderRadius: Radius.md,
    overflow: 'hidden',
    backgroundColor: Blur.scrim,
  },
  specularTop: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    height: Borders.width,
    backgroundColor: Borders.specularHigh,
  },
  specularLeft: {
    position: 'absolute',
    top: 0,
    bottom: 0,
    left: 0,
    width: Borders.width,
    backgroundColor: Borders.specularHigh,
  },
  /** Applied additively when an element is focused / pressed / live. */
  activeEdge: { borderColor: Borders.activeHigh },
  fill: StyleSheet.absoluteFill,
});

/**
 * Outer glow. iOS gets a real shadow; Android gets elevation + a tinted
 * border, because Android shadows cannot be colored below API 28.
 */
export const glow = (color: string, radius = 18): ViewStyle =>
  Platform.select<ViewStyle>({
    ios: {
      shadowColor: color,
      shadowOpacity: 0.9,
      shadowRadius: radius,
      shadowOffset: { width: 0, height: 0 },
    },
    default: { elevation: 0, borderColor: color },
  })!;

export const ObsidianPrism = {
  Palette,
  Borders,
  VoidGradient,
  RefractionOrbs,
  Blur,
  Fonts,
  Type,
  Space,
  Radius,
  Motion,
  Retention,
  Surface,
  withAlpha,
  glow,
} as const;

export default ObsidianPrism;
