// Live sound through Cloudflare Realtime (owner's choice, 2026-10-28): the speaker's page sends
// its microphone to the Realtime SFU over WebRTC, as /dev/snd/NAME; a listener's page receives it
// from there. The devices' drivers (crates/worker/src/dev) speak to Realtime with the app's
// secret, once the kernel has decided that the page may: one that writes the sound, or the
// presentation it speaks in, sends; one that reads it hears.
import { call } from './http.mjs';
import { hear, send } from './dev.mjs';

const ICE = [{ urls: 'stun:stun.cloudflare.com:3478' }];

// Until `pc` connects, or fails, or ten seconds pass.
function connected(pc) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('The sound did not connect')), 10000);
    const check = () => {
      if (pc.connectionState === 'connected') { clearTimeout(timer); resolve(); }
      else if (['failed', 'closed'].includes(pc.connectionState)) { clearTimeout(timer); reject(new Error('The sound did not connect')); }
    };
    pc.addEventListener('connectionstatechange', check); check();
  });
}

/** Send `microphone` live, as /dev/snd/NAME (the account's name by default), made with the
 * ACL entries `acl` (stream -m); or, with `presentation`, as a listener's voice in it, which
 * its presenter let them send (through the descriptor `fd` passed to this session, a guest's).
 * Settles with the device, what it is (its version) and what ends it. */
export async function speak(name, microphone, { acl = null, presentation = null, fd = null, ask = null } = {}) {
  const pc = new RTCPeerConnection({ iceServers: ICE, bundlePolicy: 'max-bundle' });
  let sent = null;
  const end = async () => { pc.close(); await sent?.end(); };
  try {
    const transceiver = pc.addTransceiver(microphone.getAudioTracks()[0], { direction: 'sendonly' });
    await pc.setLocalDescription(await pc.createOffer());
    // A voice says which ask let it speak, which its presenter's page knows it by.
    const offer = { sdp: pc.localDescription.sdp, mid: transceiver.mid, ...(ask ? { ask } : {}) };
    sent = await send(offer, { name: name ?? (presentation ? null : (await call('getcreds')).user), acl, presentation, fd });
    await pc.setRemoteDescription({ type: 'answer', sdp: sent.sdp });
    await connected(pc);
    return { device: sent.device, version: sent.version, end };
  } catch (error) {
    // A sound that never connected is no device for listeners to find.
    await end();
    throw error;
  }
}

/** Hear the sound /dev/snd/NAME live in `audio`; settles with what stops it, and what the device
 * is (its version), to know whether it is replaced while the page's line is down. `lost` hears
 * if the connection fails once made (a network that changed, say), to hear it again. */
export async function listen(device, audio, lost = () => {}) {
  const pc = new RTCPeerConnection({ iceServers: ICE, bundlePolicy: 'max-bundle' });
  try {
    pc.ontrack = event => { audio.srcObject = new MediaStream([event.track]); };
    const offered = await hear(device);
    await pc.setRemoteDescription({ type: 'offer', sdp: offered.sdp });
    await pc.setLocalDescription(await pc.createAnswer());
    await offered.reply(pc.localDescription.sdp);
    await connected(pc);
    pc.addEventListener('connectionstatechange', () => { if (pc.connectionState === 'failed') lost(); });
    return { stop: () => { pc.close(); audio.srcObject = null; }, version: offered.version };
  } catch (error) { pc.close(); throw error; }
}
