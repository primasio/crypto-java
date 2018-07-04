/*
 * Copyright 2018 Primas Lab Fundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.primas.service;

import com.primas.common.InvalidException;
import com.primas.crypto.ECKey;
import org.spongycastle.util.encoders.Hex;

import java.math.BigInteger;

/**
 * crypto processor
 * @author envin_xie
 * @since 2018-07-04
 */
public class ECKeyProcessor {
    /**
     * sign
     *
     * @param privateKey private key
     * @param content    content
     */
    public static String Sign(String privateKey, byte[] content) throws InvalidException {
        if (!CheckPrivateKey(privateKey)) {
            throw new InvalidException("private key`s format is error");
        }
        ECKey ecKey = ECKey.fromPrivate(Hex.decode(privateKey));
        //只能对contentHash签名
        ECKey.ECDSASignature ecdsaSignature = ecKey.doSign(content);
        return ecdsaSignature.toHex();
    }

    /**
     * verify
     *
     * @param publicKey public hex key
     * @param signMsg   signature
     * @param data      content
     */
    public static boolean VerifySignature(String publicKey, String signMsg, byte[] data) throws InvalidException {
        if (!CheckPublicKey(publicKey, true)) {
            throw new InvalidException("public key`s format is error");
        }

        byte recID = Byte.parseByte(signMsg.substring(signMsg.length() - 2), 16);
        byte[] decode = Hex.decode(signMsg.substring(0, signMsg.length() - 2));

        byte[] rBs = new byte[decode.length / 2];
        byte[] sBs = new byte[decode.length / 2];

        System.arraycopy(decode, 0, rBs, 0, decode.length / 2);
        System.arraycopy(decode, decode.length / 2, sBs, 0, decode.length / 2);

        BigInteger r = new BigInteger(Hex.toHexString(rBs), 16);
        BigInteger s = new BigInteger(Hex.toHexString(sBs), 16);


        ECKey.ECDSASignature sig = ECKey.ECDSASignature.fromComponents(r.toByteArray(), s.toByteArray(), recID);

        return ECKey.verify(data, sig, Hex.decode(publicKey));
    }

    /**
     * check private key
     *
     * @param privateKey private hex key
     */
    public static boolean CheckPrivateKey(String privateKey) {
        if (null == privateKey || "".equals(privateKey.trim()) || privateKey.length() != 64) {
            return false;
        }
        return true;
    }
    /**
     * check public key
     *
     * @param publicKey    public hex key
     * @param isCompressed compressed
     */
    public static boolean CheckPublicKey(String publicKey, boolean isCompressed) {
        if (publicKey == null) {
            return false;
        }
        return isCompressed ? publicKey.length() == 66 : publicKey.length() == 130;
    }

}
