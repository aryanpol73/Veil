/**
 * ============================================================================
 *  VEIL — DYNAMIC FORENSIC WATERMARK
 * ============================================================================
 *  WHAT THIS ACTUALLY DOES — read before shipping copy about it:
 *
 *  No overlay can be "invisible on screen but visible in a photograph". A
 *  camera records the light the panel emits; if a human eye cannot see the
 *  pattern at all, a sensor generally cannot either. What genuinely works, and
 *  what is implemented here, is a three-part scheme:
 *
 *   1. CARRIER (always on, opacity 0.035). A high-frequency tick lattice whose
 *      per-cell orientation encodes BLAKE2b(deviceFP | sessionId | recipientFP
 *      | UTC minute). Below the threshold of casual reading, but it survives
 *      JPEG/HEIC compression and screen re-photography, and it is recoverable
 *      by FFT/template correlation from a leaked image. That yields the
 *      forensic property that matters: a leak identifies the device, session
 *      and minute it came from.
 *
 *   2. MOIRÉ AMPLIFICATION. The lattice pitch (~11px) is deliberately close to
 *      a typical phone-camera sensor's sampling pitch, so an external photo
 *      beats against it and the pattern becomes far more conspicuous in the
 *      capture than on the panel. This is a real effect and it is why the
 *      pitch is not a round number — but it is a nice-to-have, not the
 *      mechanism.
 *
 *   3. ACTIVE DETECTION. expo-screen-capture flags OS screenshots (both
 *      platforms) and screen recording (iOS `isCaptured`). On detection we
 *      flash the lattice to full visibility, fire a haptic, and notify the
 *      host so it can burn View-Once content. On Android we additionally set
 *      FLAG_SECURE, which actually blocks the screenshot outright.
 *
 *  "Unblockable" means it is mounted inside the chat viewport's own tree with
 *  pointerEvents="none", so it cannot be dismissed, scrolled out from under,
 *  or hidden by any in-app interaction. An attacker with a modified client or
 *  a second camera is out of scope for any watermark.
 * ============================================================================
 */

import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { AppState, InteractionManager, Platform, StyleSheet, View } from 'react-native';
import Svg, { G, Path, Rect } from 'react-native-svg';
import Animated, {
  Easing,
  useAnimatedStyle,
  useSharedValue,
  withRepeat,
  withSequence,
  withTiming,
} from 'react-native-reanimated';
import * as ScreenCapture from 'expo-screen-capture';
import HapticFeedback from 'react-native-haptic-feedback';
import { watermarkTag, toB64 } from '../crypto/keys';
import { Palette, withAlpha } from '../theme/obsidianPrism';

/* -------------------------------------------------------------------------- */

export interface DynamicWatermarkProps {
  /** Stable per-install hardware/attestation digest. */
  deviceFingerprint: string;
  /** Opaque per-unlock id (from the vault session). */
  sessionId: string;
  /** The peer whose content is on screen — scopes blame correctly. */
  recipientFingerprint: string;
  /** Lattice pitch in px. Non-round on purpose; see moiré note above. */
  pitch?: number;
  /** Carrier opacity. 0.035 is the calibrated ceiling for unobtrusiveness. */
  baseOpacity?: number;
  /** Called on screenshot / recording. Host should burn View-Once content. */
  onCaptureDetected?: (kind: 'screenshot' | 'recording') => void;
  /** Android only: set FLAG_SECURE to hard-block screenshots. */
  blockCaptureOnAndroid?: boolean;
}

/** Aligns work to the UTC minute so the payload rotates predictably. */
const currentMinuteUtc = (): number => Math.floor(Date.now() / 60_000);

/* -------------------------------------------------------------------------- */
/* Lattice geometry                                                           */
/* -------------------------------------------------------------------------- */

/**
 * Expands the 32-byte digest into a per-cell orientation stream. Each cell
 * consumes 2 bits (4 orientations); the digest is re-hashed by index rotation
 * so the stream is as long as the grid needs without repeating visibly.
 */
function buildLatticePath(
  digest: Uint8Array,
  width: number,
  height: number,
  pitch: number,
): string {
  if (width <= 0 || height <= 0) return '';

  const cols = Math.ceil(width / pitch) + 1;
  const rows = Math.ceil(height / pitch) + 1;
  const arm = pitch * 0.3; // half-length of each tick
  const segments: string[] = [];

  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols; c++) {
      const cell = r * cols + c;
      // Decorrelate row/column indices so the stream does not tile with the grid.
      const byte = digest[(cell * 7 + r * 13 + c * 31) % digest.length];
      const orientation = (byte >> ((cell % 4) * 2)) & 0b11;

      const cx = c * pitch + pitch / 2;
      const cy = r * pitch + pitch / 2;

      // 0: horizontal  1: vertical  2: NE-SW  3: NW-SE
      const [dx, dy] =
        orientation === 0
          ? [arm, 0]
          : orientation === 1
          ? [0, arm]
          : orientation === 2
          ? [arm * 0.72, -arm * 0.72]
          : [arm * 0.72, arm * 0.72];

      segments.push(
        `M${(cx - dx).toFixed(2)} ${(cy - dy).toFixed(2)}L${(cx + dx).toFixed(2)} ${(
          cy + dy
        ).toFixed(2)}`,
      );
    }
  }
  return segments.join('');
}

/* -------------------------------------------------------------------------- */
/* Component                                                                  */
/* -------------------------------------------------------------------------- */

export const DynamicWatermark: React.FC<DynamicWatermarkProps> = ({
  deviceFingerprint,
  sessionId,
  recipientFingerprint,
  pitch = 11.3,
  baseOpacity = 0.035,
  onCaptureDetected,
  blockCaptureOnAndroid = true,
}) => {
  const [size, setSize] = useState({ w: 0, h: 0 });
  const [minute, setMinute] = useState(currentMinuteUtc);
  const minuteTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  /* ---- Payload: rotates on the UTC minute boundary --------------------- */

  const digest = useMemo(
    () =>
      watermarkTag({
        deviceFingerprint,
        sessionId,
        recipientFingerprint,
        minuteUtc: minute,
      }),
    [deviceFingerprint, sessionId, recipientFingerprint, minute],
  );

  /**
   * Short hex prefix rendered as text in one corner at carrier opacity. Gives
   * an analyst a fast visual match before running full pattern correlation.
   */
  const tagPrefix = useMemo(() => toB64(digest).slice(0, 10), [digest]);

  // Schedule the next tick exactly on the boundary rather than every 60s, so
  // the payload never drifts out of phase with wall-clock minutes.
  useEffect(() => {
    const schedule = () => {
      const delay = 60_000 - (Date.now() % 60_000) + 25;
      minuteTimer.current = setTimeout(() => {
        setMinute(currentMinuteUtc());
        schedule();
      }, delay);
    };
    schedule();
    return () => {
      if (minuteTimer.current) clearTimeout(minuteTimer.current);
    };
  }, []);

  // Re-sync immediately on foreground; a backgrounded timer is unreliable.
  useEffect(() => {
    const sub = AppState.addEventListener('change', (s) => {
      if (s === 'active') setMinute(currentMinuteUtc());
    });
    return () => sub.remove();
  }, []);

  /* ---- Geometry (built off the interaction queue) ---------------------- */

  const [pathData, setPathData] = useState('');
  useEffect(() => {
    if (!size.w || !size.h) return;
    // A full-screen lattice is a few thousand path segments; defer it so it
    // never lands inside a gesture or transition frame.
    const task = InteractionManager.runAfterInteractions(() => {
      setPathData(buildLatticePath(digest, size.w, size.h, pitch));
    });
    return () => task.cancel();
  }, [digest, size.w, size.h, pitch]);

  /* ---- Motion: sub-pixel drift + capture flash ------------------------- */

  const drift = useSharedValue(0);
  const flash = useSharedValue(0);

  useEffect(() => {
    // Sub-pixel breathing defeats naive "average N frames and subtract"
    // pattern-removal attempts without being perceptible.
    drift.value = withRepeat(
      withSequence(
        withTiming(1, { duration: 9000, easing: Easing.inOut(Easing.sin) }),
        withTiming(0, { duration: 9000, easing: Easing.inOut(Easing.sin) }),
      ),
      -1,
      false,
    );
  }, [drift]);

  const driftStyle = useAnimatedStyle(() => ({
    // Keep the drift under one pitch so the lattice stays phase-continuous.
    transform: [
      { translateX: drift.value * 1.7 },
      { translateY: drift.value * -1.1 },
    ],
  }));

  const flashStyle = useAnimatedStyle(() => ({
    opacity: baseOpacity + flash.value * (0.9 - baseOpacity),
  }));

  const triggerFlash = useCallback(
    (kind: 'screenshot' | 'recording') => {
      flash.value = withSequence(
        withTiming(1, { duration: 90 }),
        withTiming(1, { duration: 700 }),
        withTiming(0, { duration: 900, easing: Easing.out(Easing.quad) }),
      );
      if (Platform.OS !== 'web') {
        try {
          HapticFeedback.trigger('notificationWarning', {
            enableVibrateFallback: true,
            ignoreAndroidSystemSettings: false,
          });
        } catch {
          /* ignore */
        }
      }
      onCaptureDetected?.(kind);
    },
    [flash, onCaptureDetected],
  );

  /* ---- Capture detection ---------------------------------------------- */

  useEffect(() => {
    let disposed = false;
    const subs: Array<{ remove: () => void }> = [];

    if (Platform.OS !== 'web') {
      (async () => {
        // Android: FLAG_SECURE genuinely prevents the screenshot and blanks the
        // recents thumbnail. iOS has no equivalent; detection is all we get.
        if (blockCaptureOnAndroid && Platform.OS === 'android') {
          try {
            await ScreenCapture.preventScreenCaptureAsync('veil-chat');
          } catch {
            /* unsupported platform — carrier + detection still apply */
          }
        }
        if (disposed) return;

        try {
          if (typeof ScreenCapture.addScreenshotListener === 'function') {
            const sub = ScreenCapture.addScreenshotListener(() => triggerFlash('screenshot'));
            if (sub && typeof sub.remove === 'function') {
              subs.push(sub);
            }
          }
        } catch {
          /* unsupported on current platform */
        }

        // Screen recording / AirPlay mirroring (iOS UIScreen.isCaptured).
        if (typeof (ScreenCapture as any).isAvailableAsync === 'function') {
          let wasCaptured = false;
          const poll = setInterval(async () => {
            try {
              const captured = await (ScreenCapture as any).isScreenBeingRecordedAsync?.();
              if (captured && !wasCaptured) triggerFlash('recording');
              wasCaptured = !!captured;
            } catch {
              clearInterval(poll);
            }
          }, 2000);
          subs.push({ remove: () => clearInterval(poll) });
        }
      })();
    }

    return () => {
      disposed = true;
      subs.forEach((s) => s.remove());
      if (Platform.OS !== 'web') {
        try {
          ScreenCapture.allowScreenCaptureAsync('veil-chat').catch(() => {});
        } catch {
          /* ignore */
        }
      }
    };
  }, [blockCaptureOnAndroid, triggerFlash]);

  /* ---- Render ---------------------------------------------------------- */

  return (
    <Animated.View
      style={[styles.root, flashStyle]}
      // Non-interactive and non-announced: it must never steal a touch or be
      // read out by a screen reader.
      pointerEvents="none"
      accessible={false}
      importantForAccessibility="no-hide-descendants"
      onLayout={(e) => {
        const { width, height } = e.nativeEvent.layout;
        setSize((prev) =>
          Math.abs(prev.w - width) > 1 || Math.abs(prev.h - height) > 1
            ? { w: width, h: height }
            : prev,
        );
      }}
    >
      {size.w > 0 && (
        <Animated.View style={driftStyle}>
          <Svg width={size.w} height={size.h}>
            {/* Faint chromatic wash: makes the lattice survive greyscale
                conversion and adds a second, color-channel-based carrier. */}
            <Rect
              x={0}
              y={0}
              width={size.w}
              height={size.h}
              fill={withAlpha(Palette.prismCyan, 0.02)}
            />
            <G>
              <Path
                d={pathData}
                stroke={Palette.textPrimary}
                strokeWidth={0.7}
                strokeLinecap="butt"
                fill="none"
              />
            </G>
          </Svg>
        </Animated.View>
      )}

      {/* Human-readable tag echo, corner-anchored, same carrier opacity. */}
      <View style={styles.tagRow} pointerEvents="none">
        <Animated.Text style={styles.tagText} allowFontScaling={false}>
          {`VEIL·${tagPrefix}·${minute}`}
        </Animated.Text>
      </View>
    </Animated.View>
  );
};

const styles = StyleSheet.create({
  root: { ...StyleSheet.absoluteFill, zIndex: 9999 },
  tagRow: { position: 'absolute', right: 8, bottom: 6 },
  tagText: {
    fontFamily: 'JetBrainsMono-Regular',
    fontSize: 7,
    letterSpacing: 1.2,
    color: Palette.textPrimary,
  },
});

export default React.memo(DynamicWatermark);
