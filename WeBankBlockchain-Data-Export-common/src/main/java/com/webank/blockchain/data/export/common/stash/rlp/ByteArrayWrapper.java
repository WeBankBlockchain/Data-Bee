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



import org.fisco.bcos.sdk.utils.Hex;

import java.io.Serializable;
import java.util.Arrays;


public class ByteArrayWrapper implements Comparable<ByteArrayWrapper>, Serializable {

    private static final long serialVersionUID = 19037950584492274L;
    private final byte[] bytes;
    private int hashCode = 0;

    public ByteArrayWrapper(byte[] data) {
        if (data == null)
            throw new NullPointerException("ByteArrayWrapper bytes is null");
        this.bytes = data;
        this.hashCode = Arrays.hashCode(data);
    }

    @Override
    public int hashCode() {
        return hashCode;
    }

    @Override
    public int compareTo(ByteArrayWrapper o) {
        return FastByteComparisons.compareTo(
                bytes, 0, bytes.length,
                o.getData(), 0, o.getData().length);
    }

    public byte[] getData() {
        return bytes;
    }

    @Override
    public String toString() {
        return bytes ==null? "" : Hex.toHexString(bytes);
    }
}
