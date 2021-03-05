/**
 * Copyright 2020 Webank.
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License at
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0
 *
 * <p>Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.webank.blockchain.data.export.common.tools;

import cn.hutool.core.convert.Convert;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;
import org.fisco.bcos.sdk.abi.datatypes.Address;
import org.fisco.bcos.sdk.abi.datatypes.StaticArray;
import org.fisco.bcos.sdk.crypto.signature.ECDSASignature;

import java.math.BigInteger;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.List;

/**
 * AddressUtils
 *
 * @Description: AddressUtils
 * @author maojiayu
 * @data Jan 30, 2019 6:05:47 PM
 *
 */
public class AddressUtils {

    public static String bigIntegerTypeToString(BigInteger bi) {
        Address address = new Address(bi);
        return address.toString();
    }

    public static String bigIntegerToString(Object obj) {
        return bigIntegerTypeToString(Convert.toBigInteger(obj));
    }

    public static String staticArrayToString(Object obj) {
        @SuppressWarnings("unchecked")
        StaticArray<Address> sa = (StaticArray<Address>) obj;
        List<Address> list = sa.getValue();
        return JacksonUtils.toJson(list);
    }


    public static final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");

    static final ECDomainParameters CURVE =
            new ECDomainParameters(
                    CURVE_PARAMS.getCurve(),
                    CURVE_PARAMS.getG(),
                    CURVE_PARAMS.getN(),
                    CURVE_PARAMS.getH());


    public static BigInteger recoverFromSignature(byte v, BigInteger r, BigInteger s, byte[] message) throws SignatureException {
        int header = v & 0xFF;
        // The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,
        //                  0x1D = second key with even y, 0x1E = second key with odd y
        if (header < 27 || header > 34) {
            throw new SignatureException("Header byte out of range: " + header);
        }
        int recId = header - 27;
        // 1.0 For j from 0 to h   (h == recId here and the loop is outside this function)
        //   1.1 Let x = r + jn
        BigInteger n = CURVE.getN(); // Curve order.
        BigInteger i = BigInteger.valueOf((long) recId / 2);
        BigInteger x = r.add(i.multiply(n));
        //   1.2. Convert the integer x to an octet string X of length mlen using the conversion
        //        routine specified in Section 2.3.7, where mlen = ⌈(log2 p)/8⌉ or mlen = ⌈m/8⌉.
        //   1.3. Convert the octet string (16 set binary digits)||X to an elliptic curve point R
        //        using the conversion routine specified in Section 2.3.4. If this conversion
        //        routine outputs "invalid", then do another iteration of Step 1.
        //
        // More concisely, what these points mean is to use X as a compressed public key.
        BigInteger prime = SecP256K1Curve.q;
        if (x.compareTo(prime) >= 0) {
            // Cannot have point co-ordinates larger than this as everything takes place modulo Q.
            return null;
        }
        // Compressed keys require you to know an extra bit of data about the y-coord as there are
        // two possibilities. So it's encoded in the recId.
        ECPoint R = decompressKey(x, (recId & 1) == 1);
        //   1.4. If nR != point at infinity, then do another iteration of Step 1 (callers
        //        responsibility).
        if (!R.multiply(n).isInfinity()) {
            return null;
        }
        //   1.5. Compute e from M using Steps 2 and 3 of ECDSA signature verification.
        BigInteger e = new BigInteger(1, message);
        //   1.6. For k from 1 to 2 do the following.   (loop is outside this function via
        //        iterating recId)
        //   1.6.1. Compute a candidate public key as:
        //               Q = mi(r) * (sR - eG)
        //
        // Where mi(x) is the modular multiplicative inverse. We transform this into the following:
        //               Q = (mi(r) * s ** R) + (mi(r) * -e ** G)
        // Where -e is the modular additive inverse of e, that is z such that z + e = 0 (mod n).
        // In the above equation ** is point multiplication and + is point addition (the EC group
        // operator).
        //
        // We can find the additive inverse by subtracting e from zero then taking the mod. For
        // example the additive inverse of 3 modulo 11 is 8 because 3 + 8 mod 11 = 0, and
        // -3 mod 11 = 8.
        BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
        BigInteger rInv = r.modInverse(n);
        BigInteger srInv = rInv.multiply(s).mod(n);
        BigInteger eInvrInv = rInv.multiply(eInv).mod(n);
        ECPoint q = ECAlgorithms.sumOfTwoMultiplies(CURVE.getG(), eInvrInv, R, srInv);

        byte[] qBytes = q.getEncoded(false);
        // We remove the prefix
        return new BigInteger(1, Arrays.copyOfRange(qBytes, 1, qBytes.length));
    }


    private static ECPoint decompressKey(BigInteger xBN, boolean yBit) {
        X9IntegerConverter x9 = new X9IntegerConverter();
        byte[] compEnc = x9.integerToBytes(xBN, 1 + x9.getByteLength(CURVE.getCurve()));
        compEnc[0] = (byte) (yBit ? 0x03 : 0x02);
        return CURVE.getCurve().decodePoint(compEnc);
    }
}
