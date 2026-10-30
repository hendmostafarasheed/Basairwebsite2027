import { AccessToken, RoomServiceClient } from '@livekit/server-sdk';
import { config } from './config.js';

export const roomService = new RoomServiceClient(
  config.livekitUrl.replace(/^wss:/, 'https:').replace(/^ws:/, 'http:'),
  config.livekitApiKey,
  config.livekitApiSecret
);

export async function createParticipantToken({ identity, name, roomName, canPublish, canSubscribe }) {
  const token = new AccessToken(config.livekitApiKey, config.livekitApiSecret, {
    identity: String(identity),
    name,
    ttl: '2h'
  });
  token.addGrant({
    roomJoin: true,
    room: roomName,
    canPublish,
    canSubscribe,
    canPublishData: true
  });
  return token.toJwt();
}
