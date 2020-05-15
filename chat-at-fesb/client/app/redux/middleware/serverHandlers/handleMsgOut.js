// Info: config is an alias to "config/default.json" file
// (the alias is set in webpack.config.js).
import { Constants } from "config";
import Crypto from 'crypto'
import { encrypt } from '../../../services/security/CryptoProvider'

import serverAPI from "app/services/server-api/ServerAPI.js";
import { msgSent } from "app/redux/actions/clientActions.js";
import { loadKey } from "./utils.js";

const { MsgType } = Constants;

export default ({ getState, dispatch }, next, action) => {
  const {
    meta: { wrapped },
  } = action;
  if (wrapped) return next(action);

  const {
    client: { nickname, id },
    credentials,
  } = getState();

  //===================================================
  // Try to load an encryption key for this client id
  //===================================================
  const rawKey = loadKey(id, credentials)
  const key = !!rawKey ? new Buffer.from(rawKey).toString('hex') : rawKey

  //===================================================
  // If the encryption key is successfully loaded,
  // it is implied that all outgoing messages from this
  // client will be encrypted with that key.
  //===================================================

  const cbcEncrypt = (plaintext, cbcKey, iv) => encrypt('CBC', {
    plaintext,
    iv,
    key: cbcKey
  })

  let msg

  if (key) {
    const encryptionKey = new Buffer.from(key.substring(0, key.length / 2), 'hex')
    const hmacSignKey = new Buffer.from(key.substring(key.length / 2), 'hex')

    const encryptedO = cbcEncrypt(action.payload, encryptionKey, Crypto.randomBytes(16))
    const hmac = Crypto.createHmac('sha256', hmacSignKey)

    msg = {
      type: MsgType.BROADCAST,
      id,
      nickname,
      timestamp: Date.now(),
      content: encryptedO.ciphertext,
      iv: encryptedO.iv,
    };

    hmac.update(JSON.stringify(msg))
    msg.authTag = hmac.digest().toString('hex')

  } else {
    msg = {
      type: MsgType.BROADCAST,
      id,
      nickname,
      timestamp: Date.now(),
      content: action.payload,
    };
  }

  //===================================================
  // The resulting protected (CBC + HMAC) message
  // might look something like shown below:
  //
  //   msg = {
  //     type: "4",
  //     id: "3261434470825227",
  //     nickname: "Alice",
  //     timestamp: 1593720594459,
  //     content: "c850fcee1c9c7c3ee9c4fd4a621eda18057cce3f2eb5261e",
  //     iv: "2a24b323a7dc1c6dc31ab216d576d59f",
  //     authTag: "d3dc95ec39457edb366c19b4ad926638"
  //   }
  //====================================================

  serverAPI.send(msg).then(dispatch(msgSent(msg)));
};
