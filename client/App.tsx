import React, { useEffect, useState } from 'react';
import { StyleSheet, View, ActivityIndicator } from 'react-native';
import { StatusBar } from 'expo-status-bar';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import { GestureHandlerRootView } from 'react-native-gesture-handler';
import { ChatScreen } from './src/screens/ChatScreen';
import { initCrypto, deriveVaultKey } from './src/crypto/keys';
import { insertMessage, listMessages, type StoredMessage } from './src/storage/db';
import { Palette } from './src/theme/obsidianPrism';

export default function App() {
  const [ready, setReady] = useState(false);

  useEffect(() => {
    console.time('argon2');
    deriveVaultKey('123456', new Uint8Array(16).fill(7), 'partition.primary');
    console.timeEnd('argon2');

    let mounted = true;
    (async () => {
      try {
        await initCrypto();
        // Seed initial encrypted conversation if thread is empty
        const threadId = 'dt_0';
        const existing = listMessages(threadId);
        if (existing.length === 0) {
          insertMessage({
            id: 'm_init_1',
            threadId,
            direction: 'in',
            retention: 'persistent',
            body: 'Encrypted channel initialized. Ephemeral X25519 ratchet engaged.',
          });
          insertMessage({
            id: 'm_init_2',
            threadId,
            direction: 'in',
            retention: 'timed',
            body: 'Self-destructing operational brief: rendezvous sector 4. Arms countdown on read.',
            ttlMs: 60_000,
          });
          insertMessage({
            id: 'm_init_3',
            threadId,
            direction: 'in',
            retention: 'viewOnce',
            body: 'Ephemeral single-use access token: 8F49-2A10-D9E7. Burns irreversibly upon release.',
          });
        }
      } catch (err) {
        console.error('[veil] init error', err);
      } finally {
        if (mounted) setReady(true);
      }
    })();
    return () => {
      mounted = false;
    };
  }, []);

  if (!ready) {
    return (
      <View style={styles.loading}>
        <StatusBar style="light" />
        <ActivityIndicator color={Palette.prismCyan} size="large" />
      </View>
    );
  }

  return (
    <GestureHandlerRootView style={styles.root}>
      <SafeAreaProvider>
        <StatusBar style="light" />
        <ChatScreen
          threadId="dt_0"
          peer={{
            alias: 'Dana R.',
            fingerprint: 'K7QP 4M2X 9WVE 3TNA 6HJD',
            verified: true,
          }}
          maskLabel="Personal"
          deviceFingerprint="V1-8842-CF90"
          sessionId="sess_veil_live"
          onBack={() => console.log('Back pressed')}
          onTransmit={async (msg) => {
            console.log('[veil] Transmitting message:', msg.id, msg.retention);
            await new Promise((r) => setTimeout(r, 200));
          }}
        />
      </SafeAreaProvider>
    </GestureHandlerRootView>
  );
}

const styles = StyleSheet.create({
  root: {
    flex: 1,
    backgroundColor: Palette.voidMidnight,
  },
  loading: {
    flex: 1,
    backgroundColor: Palette.voidMidnight,
    alignItems: 'center',
    justifyContent: 'center',
  },
});
