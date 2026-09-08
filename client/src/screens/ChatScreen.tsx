/**
 * ============================================================================
 *  VEIL — CHAT SCREEN
 * ============================================================================
 *  Layer order, back to front:
 *    PrismBackdrop  (void gradient + 3 parallax refraction orbs)
 *    FlatList       (message bubbles, inverted)
 *    FrostedHeader  (BlurView 85, peer fingerprint HUD)
 *    Composer       (BlurView 85, retention selector, send)
 *    DynamicWatermark (always last, pointerEvents none)
 *
 *  Retention behaviour:
 *    Persistent  emerald micro-dot, SQLCipher-backed
 *    Timed       amber pulsating ring + live countdown, TTL armed on read
 *    View-Once   crystalline shroud, blurred until held, burned on release
 * ============================================================================
 */

import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  FlatList,
  KeyboardAvoidingView,
  ListRenderItemInfo,
  Platform,
  Pressable,
  StyleSheet,
  Text,
  TextInput,
  View,
  useWindowDimensions,
} from 'react-native';
import { BlurView } from 'expo-blur';
import { LinearGradient } from 'expo-linear-gradient';
import Svg, { Circle, Defs, RadialGradient, Stop } from 'react-native-svg';
import { Gesture, GestureDetector } from 'react-native-gesture-handler';
import Animated, {
  Easing,
  interpolate,
  runOnJS,
  useAnimatedScrollHandler,
  useAnimatedStyle,
  useDerivedValue,
  useSharedValue,
  withRepeat,
  withSequence,
  withSpring,
  withTiming,
  type SharedValue,
} from 'react-native-reanimated';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import HapticFeedback from 'react-native-haptic-feedback';

import {
  Blur,
  Borders,
  Motion,
  Palette,
  Radius,
  RefractionOrbs,
  Retention,
  Space,
  Surface,
  Type,
  VoidGradient,
  glow,
  withAlpha,
  type RetentionMode,
} from '../theme/obsidianPrism';
import DynamicWatermark from '../components/DynamicWatermark';
import {
  RamVault,
  insertMessage,
  listMessages,
  markReadAndArmTtl,
  type StoredMessage,
} from '../storage/db';

const haptic = (type: Parameters<typeof HapticFeedback.trigger>[0]) =>
  HapticFeedback.trigger(type, { enableVibrateFallback: true, ignoreAndroidSystemSettings: false });

/* ========================================================================== */
/* Backdrop                                                                   */
/* ========================================================================== */

interface OrbProps {
  orb: (typeof RefractionOrbs)[number];
  velocity: SharedValue<number>;
  viewport: { w: number; h: number };
}

/**
 * A single blurred refraction orb. RN has no radial gradient primitive, so this
 * is an SVG circle filled with a RadialGradient — cheaper and sharper than
 * stacking translucent views, and it composites on the GPU.
 */
const RefractionOrbView: React.FC<OrbProps> = ({ orb, velocity, viewport }) => {
  const idle = useSharedValue(0);

  useEffect(() => {
    idle.value = withRepeat(
      withTiming(1, { duration: orb.driftMs, easing: Easing.inOut(Easing.sin) }),
      -1,
      true,
    );
  }, [idle, orb.driftMs]);

  const radius = Math.min(viewport.w, viewport.h) * orb.radius;
  const size = radius * 2;

  const style = useAnimatedStyle(() => {
    // Scroll velocity drives parallax; the spring lag is what makes the light
    // feel like it sits behind glass rather than being painted on it.
    const scrollShift = velocity.value * orb.parallax;
    const idleX = interpolate(idle.value, [0, 1], [-18, 18]) * Math.sign(orb.parallax || 1);
    const idleY = interpolate(idle.value, [0, 1], [12, -12]);
    return {
      transform: [
        { translateX: withSpring(idleX + scrollShift * 0.6, Motion.ambient) },
        { translateY: withSpring(idleY + scrollShift, Motion.ambient) },
        { scale: withSpring(1 + Math.min(Math.abs(velocity.value) / 2600, 0.12), Motion.ambient) },
      ],
    };
  });

  return (
    <Animated.View
      pointerEvents="none"
      style={[
        {
          position: 'absolute',
          left: viewport.w * orb.anchor.x - radius,
          top: viewport.h * orb.anchor.y - radius,
          width: size,
          height: size,
        },
        style,
      ]}
    >
      <Svg width={size} height={size}>
        <Defs>
          <RadialGradient id={`orb-${orb.id}`} cx="50%" cy="50%" r="50%">
            <Stop offset="0%" stopColor={orb.core} stopOpacity={1} />
            <Stop offset="45%" stopColor={orb.core} stopOpacity={0.45} />
            <Stop offset="100%" stopColor={orb.core} stopOpacity={0} />
          </RadialGradient>
        </Defs>
        <Circle cx={radius} cy={radius} r={radius} fill={`url(#orb-${orb.id})`} />
      </Svg>
    </Animated.View>
  );
};

const PrismBackdrop: React.FC<{ velocity: SharedValue<number> }> = ({ velocity }) => {
  const { width, height } = useWindowDimensions();
  return (
    <View style={StyleSheet.absoluteFill} pointerEvents="none">
      <LinearGradient
        colors={VoidGradient.colors}
        locations={VoidGradient.locations}
        start={VoidGradient.start}
        end={VoidGradient.end}
        style={StyleSheet.absoluteFill}
      />
      {RefractionOrbs.map((orb) => (
        <RefractionOrbView key={orb.id} orb={orb} velocity={velocity} viewport={{ w: width, h: height }} />
      ))}
    </View>
  );
};

/* ========================================================================== */
/* Specular glass frame                                                       */
/* ========================================================================== */

/** The asymmetric hairline that turns a rect into a bevelled piece of glass. */
const Specular: React.FC<{ active?: boolean; color?: string }> = ({ active, color }) => (
  <>
    <View
      style={[Surface.specularTop, active && { backgroundColor: color ?? Borders.activeHigh }]}
      pointerEvents="none"
    />
    <View
      style={[Surface.specularLeft, active && { backgroundColor: color ?? Borders.activeHigh }]}
      pointerEvents="none"
    />
  </>
);

/* ========================================================================== */
/* Countdown                                                                  */
/* ========================================================================== */

/** 250ms tick — smooth enough to read as live, cheap enough to ignore. */
function useCountdown(expiresAt: number | null): { remainingMs: number; fraction: number } {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    if (!expiresAt) return;
    const t = setInterval(() => setNow(Date.now()), 250);
    return () => clearInterval(t);
  }, [expiresAt]);

  if (!expiresAt) return { remainingMs: 0, fraction: 1 };
  const remainingMs = Math.max(0, expiresAt - now);
  return { remainingMs, fraction: remainingMs / Math.max(1, expiresAt - (expiresAt - 60_000)) };
}

const formatRemaining = (ms: number): string => {
  const total = Math.ceil(ms / 1000);
  if (total >= 3600) return `${Math.floor(total / 3600)}h${String(Math.floor((total % 3600) / 60)).padStart(2, '0')}`;
  if (total >= 60) return `${Math.floor(total / 60)}:${String(total % 60).padStart(2, '0')}`;
  return `${total}s`;
};

/* ========================================================================== */
/* Bubbles                                                                    */
/* ========================================================================== */

interface BubbleProps {
  message: StoredMessage;
  onBurn: (id: string) => void;
  onRead: (id: string) => void;
}

/** Shared chrome: fill, blur, specular edge, HUD strip, entry spring. */
const BubbleShell: React.FC<{
  mode: RetentionMode;
  mine: boolean;
  children: React.ReactNode;
  hud?: React.ReactNode;
  glowStrength?: SharedValue<number>;
}> = ({ mode, mine, children, hud, glowStrength }) => {
  const theme = Retention[mode];
  const enter = useSharedValue(0);

  useEffect(() => {
    enter.value = withSpring(1, Motion.land);
  }, [enter]);

  const style = useAnimatedStyle(() => ({
    opacity: enter.value,
    transform: [
      { translateY: interpolate(enter.value, [0, 1], [14, 0]) },
      { scale: interpolate(enter.value, [0, 1], [0.96, 1]) },
    ],
    shadowOpacity: glowStrength ? 0.3 + glowStrength.value * 0.7 : 0.35,
  }));

  return (
    <Animated.View
      style={[
        styles.bubbleWrap,
        mine ? styles.bubbleMine : styles.bubbleTheirs,
        glow(theme.edgeGlow, mode === 'viewOnce' ? 22 : 14),
        style,
      ]}
    >
      <View
        style={[
          styles.bubble,
          mine ? styles.bubbleRadiusMine : styles.bubbleRadiusTheirs,
          { backgroundColor: theme.fill, borderColor: withAlpha(theme.accent, 0.16) },
        ]}
      >
        <BlurView {...Blur.surface} style={StyleSheet.absoluteFill} />
        <Specular />
        <View style={styles.bubbleInner}>
          {hud}
          {children}
        </View>
      </View>
    </Animated.View>
  );
};

/* ---- Persistent ---------------------------------------------------------- */

const PersistentBubble: React.FC<BubbleProps> = ({ message }) => {
  const mine = message.direction === 'out';
  return (
    <BubbleShell mode="persistent" mine={mine}>
      <Text style={Type.body} selectable={false}>
        {message.body}
      </Text>
      <View style={styles.footRow}>
        {/* Emerald micro-dot: the entire visual signature of "this survives". */}
        <View style={[styles.microDot, { backgroundColor: Retention.persistent.accent }]} />
        <Text style={Type.meta}>
          {new Date(message.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
        </Text>
      </View>
    </BubbleShell>
  );
};

/* ---- Timed --------------------------------------------------------------- */

const TimedBubble: React.FC<BubbleProps> = ({ message, onBurn, onRead }) => {
  const mine = message.direction === 'out';
  const { remainingMs } = useCountdown(message.expires_at);
  const pulse = useSharedValue(0);
  const armed = useRef(false);

  useEffect(() => {
    pulse.value = withRepeat(withTiming(1, { duration: 1100, easing: Easing.inOut(Easing.quad) }), -1, true);
  }, [pulse]);

  // Arm the TTL on first render of an inbound message, i.e. on actual read.
  useEffect(() => {
    if (!armed.current && !mine && !message.read_at) {
      armed.current = true;
      onRead(message.id);
    }
  }, [mine, message.id, message.read_at, onRead]);

  useEffect(() => {
    if (message.expires_at && remainingMs <= 0) {
      haptic('impactLight');
      onBurn(message.id);
    }
  }, [remainingMs, message.expires_at, message.id, onBurn]);

  const ringStyle = useAnimatedStyle(() => ({
    opacity: interpolate(pulse.value, [0, 1], [0.45, 1]),
    transform: [{ scale: interpolate(pulse.value, [0, 1], [0.9, 1.06]) }],
  }));

  const urgent = remainingMs > 0 && remainingMs < 10_000;

  return (
    <BubbleShell
      mode="timed"
      mine={mine}
      hud={
        <View style={styles.hudStrip}>
          <Animated.View
            style={[
              styles.countRing,
              { borderColor: urgent ? Palette.danger : Retention.timed.accent },
              ringStyle,
            ]}
          />
          <Text
            style={[
              Type.hudLabel,
              { color: urgent ? Palette.danger : Retention.timed.accent, letterSpacing: 1 },
            ]}
          >
            {Retention.timed.glyph} {message.expires_at ? formatRemaining(remainingMs) : 'ARMED ON READ'}
          </Text>
        </View>
      }
    >
      <Text style={Type.body} selectable={false}>
        {message.body}
      </Text>
    </BubbleShell>
  );
};

/* ---- View-Once ----------------------------------------------------------- */

/**
 * "Crystalline Shroud". Text is rendered but sits under a heavy BlurView whose
 * intensity is driven to zero only while a finger is held down. Releasing burns
 * the message from RamVault irreversibly — there is no undo and no confirm,
 * because a confirm dialog is a second chance to photograph.
 */
const ViewOnceBubble: React.FC<BubbleProps> = ({ message, onBurn }) => {
  const mine = message.direction === 'out';
  const reveal = useSharedValue(0);
  const shimmer = useSharedValue(0);
  const collapse = useSharedValue(0);
  const [burning, setBurning] = useState(false);

  useEffect(() => {
    shimmer.value = withRepeat(withTiming(1, { duration: 2400, easing: Easing.inOut(Easing.sin) }), -1, true);
  }, [shimmer]);

  const commitBurn = useCallback(() => {
    if (burning) return;
    setBurning(true);
    haptic('notificationSuccess');
    collapse.value = withTiming(1, Motion.burn);
    setTimeout(() => onBurn(message.id), Motion.burn.duration);
  }, [burning, collapse, message.id, onBurn]);

  const gesture = useMemo(
    () =>
      Gesture.LongPress()
        .minDuration(160)
        .maxDistance(9999) // never cancel on micro-movement of a resting thumb
        .shouldCancelWhenOutside(false)
        .onStart(() => {
          reveal.value = withSpring(1, Motion.tactile);
          runOnJS(haptic)('impactMedium');
        })
        .onFinalize(() => {
          reveal.value = withTiming(0, Motion.fade);
          runOnJS(commitBurn)();
        }),
    [reveal, commitBurn],
  );

  const shroudStyle = useAnimatedStyle(() => ({
    opacity: (1 - reveal.value) * (1 - collapse.value * 0.4),
  }));

  const textStyle = useAnimatedStyle(() => ({
    opacity: reveal.value,
    transform: [{ scale: interpolate(reveal.value, [0, 1], [0.98, 1]) }],
  }));

  const containerStyle = useAnimatedStyle(() => ({
    opacity: 1 - collapse.value,
    transform: [
      { scaleY: interpolate(collapse.value, [0, 1], [1, 0.72]) },
      { translateY: interpolate(collapse.value, [0, 1], [0, -8]) },
    ],
  }));

  const iridescence = useAnimatedStyle(() => ({
    opacity: interpolate(shimmer.value, [0, 1], [0.25, 0.7]),
    transform: [{ translateX: interpolate(shimmer.value, [0, 1], [-40, 40]) }],
  }));

  return (
    <GestureDetector gesture={gesture}>
      <Animated.View style={containerStyle}>
        <BubbleShell
          mode="viewOnce"
          mine={mine}
          glowStrength={reveal}
          hud={
            <View style={styles.hudStrip}>
              <Text style={[Type.hudLabel, { color: Retention.viewOnce.accent }]}>
                {Retention.viewOnce.glyph} View-Once · hold to reveal
              </Text>
            </View>
          }
        >
          <View>
            <Animated.Text style={[Type.body, textStyle]} selectable={false}>
              {message.body}
            </Animated.Text>

            {/* Shroud: blur + iridescent sweep, absolutely over the text. */}
            <Animated.View style={[styles.shroud, shroudStyle]} pointerEvents="none">
              <BlurView {...Blur.shroud} style={StyleSheet.absoluteFill} />
              <View
                style={[
                  StyleSheet.absoluteFill,
                  { backgroundColor: withAlpha(Palette.glassShroud, 0.55) },
                ]}
              />
              <Animated.View style={[styles.iridescence, iridescence]}>
                <LinearGradient
                  colors={[
                    withAlpha(Palette.prismMagenta, 0),
                    withAlpha(Palette.prismCyan, 0.22),
                    withAlpha(Palette.prismViolet, 0.18),
                    withAlpha(Palette.prismMagenta, 0),
                  ]}
                  start={{ x: 0, y: 0 }}
                  end={{ x: 1, y: 1 }}
                  style={StyleSheet.absoluteFill}
                />
              </Animated.View>
            </Animated.View>
          </View>
        </BubbleShell>
      </Animated.View>
    </GestureDetector>
  );
};

/* ========================================================================== */
/* Header                                                                     */
/* ========================================================================== */

const FrostedHeader: React.FC<{
  alias: string;
  fingerprint: string;
  verified: boolean;
  maskLabel: string;
  onBack: () => void;
}> = ({ alias, fingerprint, verified, maskLabel, onBack }) => {
  const insets = useSafeAreaInsets();
  return (
    <View style={[styles.header, { paddingTop: insets.top + Space.sm }]}>
      <BlurView {...Blur.chrome} style={StyleSheet.absoluteFill} />
      <View style={[StyleSheet.absoluteFill, { backgroundColor: Blur.scrim }]} />
      <Specular />
      <View style={styles.headerRow}>
        <Pressable onPress={onBack} hitSlop={14} style={styles.backBtn}>
          <Text style={[Type.h2, { color: Palette.prismCyan }]}>‹</Text>
        </Pressable>

        <View style={styles.headerCenter}>
          <Text style={Type.h2} numberOfLines={1}>
            {alias}
          </Text>
          <View style={styles.fpRow}>
            <View
              style={[
                styles.microDot,
                { backgroundColor: verified ? Palette.prismLime : Palette.textMuted },
              ]}
            />
            <Text style={Type.fingerprint} numberOfLines={1}>
              {fingerprint}
            </Text>
          </View>
        </View>

        <View style={styles.maskChip}>
          <Specular />
          <Text style={Type.hudLabel}>{maskLabel}</Text>
        </View>
      </View>
    </View>
  );
};

/* ========================================================================== */
/* Composer                                                                   */
/* ========================================================================== */

const MODES: RetentionMode[] = ['persistent', 'timed', 'viewOnce'];
const TTL_PRESETS = [10_000, 60_000, 3_600_000, 86_400_000];

const RetentionPill: React.FC<{
  mode: RetentionMode;
  selected: boolean;
  onPress: () => void;
}> = ({ mode, selected, onPress }) => {
  const press = useSharedValue(0);
  const theme = Retention[mode];

  const style = useAnimatedStyle(() => ({
    transform: [{ scale: interpolate(press.value, [0, 1], [1, 0.94]) }],
    borderColor: selected ? withAlpha(theme.accent, 0.55) : Borders.specularLow,
    backgroundColor: selected ? withAlpha(theme.accent, 0.1) : withAlpha(Palette.hairline, 0.02),
  }));

  return (
    <Pressable
      onPressIn={() => {
        press.value = withSpring(1, Motion.tactile);
      }}
      onPressOut={() => {
        press.value = withSpring(0, Motion.tactile);
      }}
      onPress={() => {
        haptic('selection');
        onPress();
      }}
    >
      <Animated.View style={[styles.pill, style]}>
        <Text
          style={[Type.hudLabel, { color: selected ? theme.accent : Palette.textMuted }]}
        >
          {theme.glyph} {theme.label}
        </Text>
      </Animated.View>
    </Pressable>
  );
};

const Composer: React.FC<{
  mode: RetentionMode;
  ttlMs: number;
  onModeChange: (m: RetentionMode) => void;
  onTtlChange: (ms: number) => void;
  onSend: (text: string) => void;
}> = ({ mode, ttlMs, onModeChange, onTtlChange, onSend }) => {
  const insets = useSafeAreaInsets();
  const [text, setText] = useState('');
  const [focused, setFocused] = useState(false);
  const sendScale = useSharedValue(0);

  const canSend = text.trim().length > 0;

  const sendStyle = useAnimatedStyle(() => ({
    transform: [{ scale: interpolate(sendScale.value, [0, 1], [1, 0.88]) }],
    opacity: canSend ? 1 : 0.35,
  }));

  const submit = () => {
    if (!canSend) return;
    haptic(mode === 'viewOnce' ? 'impactHeavy' : 'impactLight');
    onSend(text.trim());
    setText('');
  };

  return (
    <View style={[styles.composer, { paddingBottom: insets.bottom + Space.sm }]}>
      <BlurView {...Blur.chrome} style={StyleSheet.absoluteFill} />
      <View style={[StyleSheet.absoluteFill, { backgroundColor: Blur.scrim }]} />
      <Specular />

      <View style={styles.pillRow}>
        {MODES.map((m) => (
          <RetentionPill key={m} mode={m} selected={mode === m} onPress={() => onModeChange(m)} />
        ))}
      </View>

      {/* TTL selector appears only for Timed — no dead controls on screen. */}
      {mode === 'timed' && (
        <View style={styles.ttlRow}>
          {TTL_PRESETS.map((ms) => (
            <Pressable
              key={ms}
              onPress={() => {
                haptic('selection');
                onTtlChange(ms);
              }}
              style={[
                styles.ttlChip,
                ttlMs === ms && { borderColor: withAlpha(Retention.timed.accent, 0.5) },
              ]}
            >
              <Text
                style={[
                  Type.meta,
                  ttlMs === ms && { color: Retention.timed.accent },
                ]}
              >
                {formatRemaining(ms)}
              </Text>
            </Pressable>
          ))}
        </View>
      )}

      <View style={[styles.inputRow, focused && Surface.activeEdge]}>
        <Specular active={focused} />
        <TextInput
          value={text}
          onChangeText={setText}
          onFocus={() => setFocused(true)}
          onBlur={() => setFocused(false)}
          placeholder={
            mode === 'viewOnce' ? 'Ephemeral — leaves no trace…' : 'Encrypted message…'
          }
          placeholderTextColor={Palette.textMuted}
          style={[Type.input, styles.input]}
          multiline
          maxLength={4000}
          // No predictive text: the keyboard's learning cache is an off-app
          // plaintext store and defeats the entire retention model.
          autoCorrect={false}
          spellCheck={false}
          keyboardAppearance="dark"
          textContentType="none"
        />
        <Pressable
          onPressIn={() => {
            sendScale.value = withSpring(1, Motion.tactile);
          }}
          onPressOut={() => {
            sendScale.value = withSpring(0, Motion.tactile);
          }}
          onPress={submit}
          disabled={!canSend}
          hitSlop={10}
        >
          <Animated.View
            style={[
              styles.sendBtn,
              { backgroundColor: withAlpha(Retention[mode].accent, 0.16) },
              glow(Retention[mode].edgeGlow, 12),
              sendStyle,
            ]}
          >
            <Text style={[Type.hudLabel, { color: Retention[mode].accent, letterSpacing: 0 }]}>
              ➤
            </Text>
          </Animated.View>
        </Pressable>
      </View>
    </View>
  );
};

/* ========================================================================== */
/* Screen                                                                     */
/* ========================================================================== */

export interface ChatScreenProps {
  threadId: string;
  peer: { alias: string; fingerprint: string; verified: boolean };
  /** Persona label. Reads "Personal" in both partitions — no decoy tell. */
  maskLabel: string;
  deviceFingerprint: string;
  sessionId: string;
  onBack: () => void;
  /** Wire to the ratchet + relay. Resolve on relay ACK. */
  onTransmit?: (msg: StoredMessage, ttlMs?: number) => Promise<void>;
}

export const ChatScreen: React.FC<ChatScreenProps> = ({
  threadId,
  peer,
  maskLabel,
  deviceFingerprint,
  sessionId,
  onBack,
  onTransmit,
}) => {
  const [messages, setMessages] = useState<StoredMessage[]>([]);
  const [mode, setMode] = useState<RetentionMode>('persistent');
  const [ttlMs, setTtlMs] = useState<number>(TTL_PRESETS[1]);
  const velocity = useSharedValue(0);
  const listRef = useRef<FlatList<StoredMessage>>(null);

  /* ---- Load + periodic reconcile (TTL expiry, RAM sweeps) -------------- */

  const reload = useCallback(() => {
    setMessages(listMessages(threadId));
  }, [threadId]);

  useEffect(() => {
    reload();
    const t = setInterval(reload, 2000);
    return () => clearInterval(t);
  }, [reload]);

  /* ---- Scroll velocity -> orb parallax --------------------------------- */

  const lastY = useSharedValue(0);
  const scrollHandler = useAnimatedScrollHandler({
    onScroll: (e) => {
      const dy = e.contentOffset.y - lastY.value;
      lastY.value = e.contentOffset.y;
      // Clamped so a fling does not launch the orbs off-canvas.
      velocity.value = Math.max(-900, Math.min(900, dy * 26));
    },
    onEndDrag: () => {
      velocity.value = 0;
    },
    onMomentumEnd: () => {
      velocity.value = 0;
    },
  });

  /* ---- Actions --------------------------------------------------------- */

  const handleSend = useCallback(
    (text: string) => {
      const msg = insertMessage({
        id: `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
        threadId,
        direction: 'out',
        retention: mode,
        body: text,
        ttlMs: mode === 'timed' ? ttlMs : undefined,
      });
      setMessages((prev) => [...prev, msg]);
      requestAnimationFrame(() => listRef.current?.scrollToOffset({ offset: 0, animated: true }));
      // Ratchet-encrypt and hand to the blind relay. Failures are surfaced by
      // the delivery indicator, never by a modal — a modal during duress is a
      // behavioural tell and an interruption.
      onTransmit?.(msg, mode === 'timed' ? ttlMs : undefined).catch(() => {});
    },
    [mode, threadId, ttlMs, onTransmit],
  );

  const handleBurn = useCallback((id: string) => {
    RamVault.burn(id);
    setMessages((prev) => prev.filter((m) => m.id !== id));
  }, []);

  const handleRead = useCallback((id: string) => {
    try {
      markReadAndArmTtl(id);
    } catch {
      /* RAM-only messages have no row to arm */
    }
  }, []);

  /**
   * A capture attempt burns every unread View-Once in the viewport. The
   * watermark already identifies the capturer; this limits what they got.
   */
  const handleCaptureDetected = useCallback(() => {
    const doomed = messages.filter((m) => m.retention === 'viewOnce').map((m) => m.id);
    doomed.forEach((id) => RamVault.burn(id));
    if (doomed.length) setMessages((prev) => prev.filter((m) => !doomed.includes(m.id)));
  }, [messages]);

  /* ---- Render ---------------------------------------------------------- */

  const renderItem = useCallback(
    ({ item }: ListRenderItemInfo<StoredMessage>) => {
      const props = { message: item, onBurn: handleBurn, onRead: handleRead };
      switch (item.retention) {
        case 'timed':
          return <TimedBubble {...props} />;
        case 'viewOnce':
          return <ViewOnceBubble {...props} />;
        default:
          return <PersistentBubble {...props} />;
      }
    },
    [handleBurn, handleRead],
  );

  const inverted = useMemo(() => [...messages].reverse(), [messages]);

  return (
    <View style={styles.root}>
      <PrismBackdrop velocity={velocity} />

      <KeyboardAvoidingView
        style={styles.flex}
        behavior={Platform.OS === 'ios' ? 'padding' : undefined}
      >
        <Animated.FlatList
          ref={listRef as any}
          data={inverted}
          renderItem={renderItem}
          keyExtractor={(m: StoredMessage) => m.id}
          inverted
          onScroll={scrollHandler}
          scrollEventThrottle={16}
          contentContainerStyle={styles.listContent}
          showsVerticalScrollIndicator={false}
          keyboardDismissMode="interactive"
          removeClippedSubviews={Platform.OS === 'android'}
          ListFooterComponent={<View style={{ height: 110 }} />}
        />

        <Composer
          mode={mode}
          ttlMs={ttlMs}
          onModeChange={setMode}
          onTtlChange={setTtlMs}
          onSend={handleSend}
        />
      </KeyboardAvoidingView>

      <FrostedHeader
        alias={peer.alias}
        fingerprint={peer.fingerprint}
        verified={peer.verified}
        maskLabel={maskLabel}
        onBack={onBack}
      />

      {/* Last child, non-interactive, spans the whole viewport. */}
      <DynamicWatermark
        deviceFingerprint={deviceFingerprint}
        sessionId={sessionId}
        recipientFingerprint={peer.fingerprint}
        onCaptureDetected={handleCaptureDetected}
      />
    </View>
  );
};

/* ========================================================================== */
/* Styles                                                                     */
/* ========================================================================== */

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: Palette.voidMidnight },
  flex: { flex: 1 },
  listContent: { paddingTop: Space.md, paddingBottom: 140, paddingHorizontal: Space.md },

  /* Header */
  header: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    paddingBottom: Space.md,
    borderBottomWidth: Borders.hairWidth,
    borderBottomColor: Borders.specularLow,
    overflow: 'hidden',
  },
  headerRow: { flexDirection: 'row', alignItems: 'center', paddingHorizontal: Space.md },
  backBtn: { width: 28, alignItems: 'flex-start' },
  headerCenter: { flex: 1 },
  fpRow: { flexDirection: 'row', alignItems: 'center', marginTop: 3 },
  maskChip: {
    paddingHorizontal: Space.sm,
    paddingVertical: 5,
    borderRadius: Radius.pill,
    borderWidth: Borders.width,
    borderColor: Borders.specularLow,
    backgroundColor: withAlpha(Palette.hairline, 0.03),
    overflow: 'hidden',
  },

  /* Bubbles */
  bubbleWrap: { marginVertical: Space.xs, maxWidth: '82%' },
  bubbleMine: { alignSelf: 'flex-end' },
  bubbleTheirs: { alignSelf: 'flex-start' },
  bubble: { borderWidth: Borders.width, overflow: 'hidden' },
  bubbleRadiusMine: {
    borderTopLeftRadius: Radius.bubble,
    borderTopRightRadius: Radius.bubble,
    borderBottomLeftRadius: Radius.bubble,
    borderBottomRightRadius: Radius.bubbleTail,
  },
  bubbleRadiusTheirs: {
    borderTopLeftRadius: Radius.bubble,
    borderTopRightRadius: Radius.bubble,
    borderBottomLeftRadius: Radius.bubbleTail,
    borderBottomRightRadius: Radius.bubble,
  },
  bubbleInner: { paddingHorizontal: Space.md + 2, paddingVertical: Space.md - 1 },
  hudStrip: { flexDirection: 'row', alignItems: 'center', marginBottom: Space.xs + 2 },
  footRow: { flexDirection: 'row', alignItems: 'center', marginTop: Space.xs + 2 },
  microDot: { width: 5, height: 5, borderRadius: 3, marginRight: Space.xs + 2 },
  countRing: {
    width: 11,
    height: 11,
    borderRadius: 6,
    borderWidth: 1.4,
    marginRight: Space.xs + 2,
  },

  /* View-Once shroud */
  shroud: { ...StyleSheet.absoluteFill, borderRadius: Radius.sm, overflow: 'hidden' },
  iridescence: { ...StyleSheet.absoluteFill, width: '160%' },

  /* Composer */
  composer: {
    paddingTop: Space.sm,
    paddingHorizontal: Space.md,
    borderTopWidth: Borders.hairWidth,
    borderTopColor: Borders.specularLow,
    overflow: 'hidden',
  },
  pillRow: { flexDirection: 'row', gap: Space.sm, marginBottom: Space.sm },
  pill: {
    paddingHorizontal: Space.md,
    paddingVertical: 6,
    borderRadius: Radius.pill,
    borderWidth: Borders.width,
  },
  ttlRow: { flexDirection: 'row', gap: Space.xs + 2, marginBottom: Space.sm },
  ttlChip: {
    paddingHorizontal: Space.sm + 2,
    paddingVertical: 4,
    borderRadius: Radius.sm,
    borderWidth: Borders.width,
    borderColor: Borders.specularLow,
  },
  inputRow: {
    flexDirection: 'row',
    alignItems: 'flex-end',
    borderWidth: Borders.width,
    borderColor: Borders.specularLow,
    borderRadius: Radius.bubble,
    backgroundColor: withAlpha(Palette.glassElevated, 0.5),
    paddingLeft: Space.md,
    paddingRight: Space.xs + 2,
    paddingVertical: Space.xs + 2,
    overflow: 'hidden',
  },
  input: { flex: 1, maxHeight: 120, paddingVertical: Space.sm, paddingRight: Space.sm },
  sendBtn: {
    width: 38,
    height: 38,
    borderRadius: Radius.pill,
    alignItems: 'center',
    justifyContent: 'center',
    borderWidth: Borders.width,
    borderColor: Borders.specularLow,
    marginBottom: 2,
  },
});

export default ChatScreen;
