import { serverMsg } from "app/redux/actions/serverActions.js";
import { JSONparse } from "app/utils/safeJSON.js";
import { clientError } from "app/redux/actions/clientActions.js";
import { loadKey } from "./utils.js";
import Crypto from 'crypto'
import { decrypt } from '../../../services/security/CryptoProvider'

export default ({ getState, dispatch }, next, action) => {
  const {
    meta: { serialized }
  } = action;
  if (!serialized) return next(action);

  let msg = JSONparse(action.payload);

  if (Object.is(msg, undefined)) {
    return dispatch(clientError(`JSON.parse error: ${data}`));
  }

  if (msg.id) {
    const { credentials, id } = getState();

    //===================================================
    // Try to load an encryption key for this client id;
    // please note that this is a remote client.
    //===================================================
    const rawKey = loadKey(msg.id, credentials);
    const key = !!rawKey ? new Buffer.from(rawKey).toString('hex') : rawKey

    //===================================================
    // If the encryption key is successfully loaded,
    // it is implied that all incoming messages from this
    // remote client will be encrypted with that key.
    // So, we decrypt the messages before reading them. 
    //===================================================

    const cbcDecrypt = (hexCiphertext, key, iv) => decrypt('CBC', {
      ciphertext: hexCiphertext,
      key,
      iv,
    })

    // WARRING! CRAPPY CODE INCOMING  ||| 
    //                                vvv

    if (key && msg) {
      const encryptionKey = new Buffer.from(key.substring(0, key.length / 2), 'hex')
      const hmacSignKey = new Buffer.from(key.substring(key.length / 2), 'hex')

      // check signature
      const hmac = Crypto.createHmac('sha256', hmacSignKey)
      const { authTag, ...newMsg } = msg
      hmac.update(JSON.stringify(newMsg))
      const computedAuthTag = hmac.digest()

      // decrypt
      newMsg.content = Crypto.timingSafeEqual(new Buffer.from(authTag, 'hex'), computedAuthTag)
        ? cbcDecrypt(msg.content, encryptionKey, new Buffer.from(msg.iv, 'hex')).plaintext
        : cbcDecrypt(msg.content, encryptionKey, new Buffer.from(msg.iv, 'hex')).plaintext + '_<Message signature invalid>_'
      newMsg.authTag = authTag

      // check freshness
      const TOLERANCE = 5 * 60 * 1000 // 5 min, should be in config but meh
      if (new Date() - new Date(newMsg.timestamp) > TOLERANCE)
        newMsg.content = newMsg.content + '_<POSSIBLE REPLAY>_'
      msg = newMsg
    }
  }

  dispatch(serverMsg(msg));
};
