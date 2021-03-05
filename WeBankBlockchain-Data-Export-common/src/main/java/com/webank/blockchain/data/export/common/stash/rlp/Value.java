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

import java.util.Arrays;
import java.util.List;

/**
 * Class to encapsulate an object and provide utilities for conversion
 */
public class Value {

    private Object value;
    private byte[] rlp;
    private boolean decoded = false;

    public static Value fromRlpEncoded(byte[] data) {

        if (data != null && data.length != 0) {
            Value v = new Value();
            v.setRlp(data);
            return v;
        }
        return null;
    }

    public Value(){
    }

    public Value(Object obj) {

        this.decoded = true;
        if (obj == null) return;

        if (obj instanceof Value) {
            this.value = ((Value) obj).asObj();
        } else {
            this.value = obj;
        }
    }
    
    public void setRlp(byte[] rlp){
        this.rlp = rlp;
    }

    public Value withHash(byte[] hash) {
        return this;
    }

    public Object asObj() {
        decode();
        return value;
    }

    public List<Object> asList() {
        decode();
        Object[] valueArray = (Object[]) value;
        return Arrays.asList(valueArray);
    }


    public String asString() {
        decode();
        if (isBytes()) {
            return new String((byte[]) value);
        } else if (isString()) {
            return (String) value;
        }
        return "";
    }

    public byte[] asBytes() {
        decode();
        if (isBytes()) {
            return (byte[]) value;
        } else if (isString()) {
            return asString().getBytes();
        }
        return ByteUtil.EMPTY_BYTE_ARRAY;
    }

    public String getHex(){
        return Hex.toHexString(this.encode());
    }

    public byte[] getData(){
        return this.encode();
    }

    public Value get(int index) {
        if (isList()) {
            // Guard for OutOfBounds
            if (asList().size() <= index) {
                return new Value(null);
            }
            if (index < 0) {
                throw new RuntimeException("Negative index not allowed");
            }
            return new Value(asList().get(index));
        }
        // If this wasn't a slice you probably shouldn't be using this function
        return new Value(null);
    }

    public void decode(){
        if (!this.decoded) {
            this.value = RLP.decode(rlp, 0).getDecoded();
            this.decoded = true;
        }
    }

    public byte[] encode() {
        if (rlp == null)
            rlp = RLP.encode(value);
        return rlp;
    }


    public boolean isList() {
        decode();
        return value != null && value.getClass().isArray() && !value.getClass().getComponentType().isPrimitive();
    }

    public boolean isString() {
        decode();
        return value instanceof String;
    }

    public boolean isBytes() {
        decode();
        return value instanceof byte[];
    }

    // it's only if the isBytes() = true;
    public boolean isReadableString() {

        decode();
        int readableChars = 0;
        byte[] data = (byte[]) value;

        if (data.length == 1 && data[0] > 31 && data[0] < 126) {
            return true;
        }

        for (byte aData : data) {
            if (aData > 32 && aData < 126) ++readableChars;
        }

        return (double) readableChars / (double) data.length > 0.55;
    }

    public boolean isHashCode() {
        decode();
        return this.asBytes().length == 32;
    }

    public boolean isNull() {
        decode();
        return value == null;
    }

    public boolean isEmpty() {
        decode();
        if (isNull()) return true;
        if (isBytes() && asBytes().length == 0) return true;
        if (isList() && asList().isEmpty()) return true;
        if (isString() && asString().isEmpty()) return true;

        return false;
    }

    public int length() {
        decode();
        if (isList()) {
            return asList().size();
        } else if (isBytes()) {
            return asBytes().length;
        } else if (isString()) {
            return asString().length();
        }
        return 0;
    }

    public String toString() {

        decode();
        StringBuilder stringBuilder = new StringBuilder();

        if (isList()) {
            Object[] list = (Object[]) value;
            if (list.length == 2) {
                stringBuilder.append("[ ");
                Value key = new Value(list[0]);
                byte[] keyNibbles = CompactEncoder.binToNibblesNoTerminator(key.asBytes());
                String keyString = ByteUtil.nibblesToPrettyString(keyNibbles);
                stringBuilder.append(keyString);
                stringBuilder.append(",");
                Value val = new Value(list[1]);
                stringBuilder.append(val.toString());
                stringBuilder.append(" ]");
                return stringBuilder.toString();
            }
            stringBuilder.append(" [");
            for (int i = 0; i < list.length; ++i) {
                Value val = new Value(list[i]);
                if (val.isString() || val.isEmpty()) {
                    stringBuilder.append("'").append(val.toString()).append("'");
                } else {
                    stringBuilder.append(val.toString());
                }
                if (i < list.length - 1)
                    stringBuilder.append(", ");
            }
            stringBuilder.append("] ");

            return stringBuilder.toString();
        } else if (isEmpty()) {
            return "";
        } else if (isBytes()) {

            StringBuilder output = new StringBuilder();
            if (isHashCode()) {
                output.append(asBytes() == null ? "" : Hex.toHexString(asBytes()));
            } else if (isReadableString()) {
                output.append("'");
                for (byte oneByte : asBytes()) {
                    if (oneByte < 16) {
                        output.append("\\x").append(ByteUtil.oneByteToHexString(oneByte));
                    } else {
                        output.append(Character.valueOf((char) oneByte));
                    }
                }
                output.append("'");
                return output.toString();
            }
            return this.asBytes() == null ? "" : Hex.toHexString(this.asBytes());
        } else if (isString()) {
            return asString();
        }
        return "Unexpected type";
    }

    
}
