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
package com.webank.blockchain.data.export.common.stash.rlp;

import java.math.BigInteger;

public class ByteUtil {

    protected static final byte[] EMPTY_BYTE_ARRAY = new byte[1];
    protected static final byte[] ZERO_BYTE_ARRAY = new byte[] { 0 };

    public static byte[] bigIntegerToBytes(BigInteger b, int numBytes) {
        if (b == null)
            return null;
        byte[] bytes = new byte[numBytes];
        byte[] biBytes = b.toByteArray();
        int start = (biBytes.length == numBytes + 1) ? 1 : 0;
        int length = Math.min(biBytes.length, numBytes);
        System.arraycopy(biBytes, start, bytes, numBytes - length, length);
        return bytes;
    }

    public static byte[] subBytes(byte[] src, int srcPos, int length) {
        byte[] dest = new byte[length];
        System.arraycopy(src, srcPos, dest, 0, length);
        return dest;
    }

    public static byte[] bigIntegerToBytes(BigInteger value) {
        if (value == null)
            return null;

        byte[] data = value.toByteArray();

        if (data.length != 1 && data[0] == 0) {
            byte[] tmp = new byte[data.length - 1];
            System.arraycopy(data, 1, tmp, 0, tmp.length);
            data = tmp;
        }
        return data;
    }

    public static BigInteger bytesToBigInteger(byte[] bb) {
        return (bb == null || bb.length == 0) ? BigInteger.ZERO : new BigInteger(1, bb);
    }

    public static byte[] intToBytesNoLeadZeroes(int val) {
        if (val == 0)
            return EMPTY_BYTE_ARRAY;

        int lenght = 0;

        int tmpVal = val;
        while (tmpVal != 0) {
            tmpVal = tmpVal >>> 8;
            ++lenght;
        }

        byte[] result = new byte[lenght];

        int index = result.length - 1;
        while (val != 0) {

            result[index] = (byte) (val & 0xFF);
            val = val >>> 8;
            index -= 1;
        }

        return result;
    }

    public static int byteArrayToInt(byte[] b) {
        if (b == null || b.length == 0)
            return 0;
        return new BigInteger(1, b).intValue();
    }

   
    public static String nibblesToPrettyString(byte[] nibbles) {
        StringBuilder builder = new StringBuilder();
        for (byte nibble : nibbles) {
            final String nibbleString = oneByteToHexString(nibble);
            builder.append("\\x").append(nibbleString);
        }
        return builder.toString();
    }

    public static String oneByteToHexString(byte value) {
        String retVal = Integer.toString(value & 0xFF, 16);
        if (retVal.length() == 1)
            retVal = "0" + retVal;
        return retVal;
    }

    public static byte[] byteConvert32Bytes(BigInteger n) {
        byte tmpd[] = (byte[]) null;
        if (n == null) {
            return null;
        }

        if (n.toByteArray().length == 33) {
            tmpd = new byte[32];
            System.arraycopy(n.toByteArray(), 1, tmpd, 0, 32);
        } else if (n.toByteArray().length == 32) {
            tmpd = n.toByteArray();
        } else {
            tmpd = new byte[32];
            for (int i = 0; i < 32 - n.toByteArray().length; i++) {
                tmpd[i] = 0;
            }
            System.arraycopy(n.toByteArray(), 0, tmpd,
                    32 - n.toByteArray().length, n.toByteArray().length);
        }
        return tmpd;
    }
    
   
    public static long byte4UnsignToLong(byte[] bytes, int pos) {
        if (bytes.length < pos + 4) {
            throw new RuntimeException("The bytes input is less than " + pos + 4);
        }
        int firstByte = (0x000000FF & ((int) bytes[pos + 3]));
        int secondByte = (0x000000FF & ((int) bytes[pos + 2]));
        int thirdByte = (0x000000FF & ((int) bytes[pos + 1]));
        int fourthByte = (0x000000FF & ((int) bytes[pos]));
        return ((long) (firstByte << 24 | secondByte << 16 | thirdByte << 8 | fourthByte)) & 0xFFFFFFFFL;
    }

}