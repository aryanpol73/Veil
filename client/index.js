// MUST be the very first import to polyfill crypto.getRandomValues for libsodium
import 'react-native-get-random-values';
import { registerRootComponent } from 'expo';
import App from './App';

registerRootComponent(App);