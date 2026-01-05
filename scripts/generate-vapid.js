/**
 * Script to generate VAPID keys for Web Push notifications
 * Run with: npm run generate-vapid
 * 
 * VAPID (Voluntary Application Server Identification) keys are required
 * for sending push notifications. The public key is shared with the client,
 * while the private key must be kept secret on the server.
 */

const webpush = require('web-push');

// Generate VAPID keys
const vapidKeys = webpush.generateVAPIDKeys();

console.log('\n🔐 VAPID Keys Generated Successfully!\n');
console.log('Add these to your .env file:\n');
console.log(`VAPID_PUBLIC_KEY=${vapidKeys.publicKey}`);
console.log(`VAPID_PRIVATE_KEY=${vapidKeys.privateKey}`);
console.log('\n⚠️  IMPORTANT: Keep the private key secret! Never expose it in frontend code.\n');
console.log('📋 Copy the PUBLIC key to your frontend configuration.\n');
