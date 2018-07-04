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

package com.primas.test;

import com.primas.common.InvalidException;
import com.primas.crypto.cryptohash.Keccak256;
import com.primas.service.ECKeyProcessor;

public class EcKeyTest {

    public static void TestSign () {
        String priKey = "17d9862daed9a515cc0d5e8ceee577fe08d6ea811c74c84e3555a1d1b61fe9d3";
        String content = "primas-crypto-java";
        String pubKey = "02d037cf08c175380450a5a97d9612b502f52852bab3111b9cca690c872d2733af";
        Keccak256 keccak256 = new Keccak256();
        keccak256.update(content.getBytes());
        try {
            //sign data
            byte[] data = keccak256.digest();
            String sign = ECKeyProcessor.Sign(priKey, data);
            System.out.println(sign);

            //verify signature
            boolean verifyResult = ECKeyProcessor.VerifySignature(pubKey, sign, data);
            System.out.println("verify result:"+verifyResult);
        } catch (InvalidException e) {
            e.printStackTrace();
        }
    }
    public static void main (String []args) {
        TestSign();
    }
}
