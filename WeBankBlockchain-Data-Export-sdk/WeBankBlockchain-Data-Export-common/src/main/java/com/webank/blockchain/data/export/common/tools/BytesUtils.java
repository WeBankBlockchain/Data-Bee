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

import cn.hutool.core.util.StrUtil;
import org.apache.commons.lang3.StringUtils;
import org.fisco.bcos.sdk.abi.datatypes.Bytes;
import org.fisco.bcos.sdk.abi.datatypes.BytesType;
import org.fisco.bcos.sdk.abi.datatypes.DynamicBytes;
import org.fisco.bcos.sdk.abi.datatypes.Int;
import org.fisco.bcos.sdk.abi.datatypes.NumericType;
import org.fisco.bcos.sdk.abi.datatypes.StaticArray;
import org.fisco.bcos.sdk.abi.datatypes.Type;
import org.fisco.bcos.sdk.abi.datatypes.Uint;
import org.fisco.bcos.sdk.abi.datatypes.generated.Bytes32;
import org.fisco.bcos.sdk.abi.datatypes.generated.Int256;
import org.fisco.bcos.sdk.abi.datatypes.generated.Int8;
import org.fisco.bcos.sdk.abi.datatypes.generated.Uint256;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * BytesUtils
 *
 * @Description: BytesUtils
 * @author maojiayu
 * @data Dec 17, 2018 4:19:25 PM
 *
 */
public class BytesUtils {

    public static Bytes32 stringToBytes32(String string) {
        byte[] byteValue = string.getBytes();
        byte[] byteValueLen32 = new byte[32];
        System.arraycopy(byteValue, 0, byteValueLen32, 0, byteValue.length);
        return new Bytes32(byteValueLen32);
    }

    public static String bytesToString(Object obj) {
        return bytesTypeToString((Bytes) obj);
    }

    public static String bytesTypeToString(Bytes b) {
        return StrUtil.str(b.getValue(), Charset.defaultCharset());
    }

    public static String bytesArrayTypeToString(byte[] b) {
        return StrUtil.str(b, Charset.defaultCharset());
    }

    public static String bytesArrayToString(Object obj) {      
        if(String.class.isInstance(obj)) {
            return (String) obj;
        }
        byte[] b = (byte[]) obj;
        return bytesArrayTypeToString(b);
    }

    public static List<String> bytes32ListToStringList(List<Bytes32> list) {
        List<String> strList = new ArrayList<>();
        for (Bytes32 b : list) {
            String s = bytesTypeToString(b);
            strList.add(s);
        }
        return strList;
    }

    @SuppressWarnings("unchecked")
    public static String bytes32DynamicArrayToString(Object bytes32DynamicArray) {
        return bytes32DynamicArrayToString((List<Bytes32>) bytes32DynamicArray);
    }

    @SuppressWarnings("unchecked")
    public static String uint256DynamicArrayToString(Object list) {
        return uint256DynamicArrayToString((List<Uint256>) list);
    }

    public static String uint256DynamicArrayToString(List<Uint256> list) {
        List<String> stringList = new ArrayList<>();
        for (int i = 0; i < list.size(); i++) {
            stringList.add(list.get(i).getValue().toString());
        }
        return JacksonUtils.toJson(stringList);
    }

    public static String uintDynamicArrayToString(List<Uint> list) {
        List<String> stringList = new ArrayList<>();
        for (int i = 0; i < list.size(); i++) {
            stringList.add(list.get(i).getValue().toString());
        }
        return JacksonUtils.toJson(stringList);
    }

    public static String int8DynamicArrayToString(List<Int8> list) {
        List<String> stringList = new ArrayList<>();
        for (int i = 0; i < list.size(); i++) {
            stringList.add(list.get(i).getValue().toString());
        }
        return JacksonUtils.toJson(stringList);
    }

    public static String int256DynamicArrayToString(List<Int256> list) {
        List<String> stringList = new ArrayList<>();
        for (int i = 0; i < list.size(); i++) {
            stringList.add(list.get(i).getValue().toString());
        }
        return JacksonUtils.toJson(stringList);
    }

    @SuppressWarnings("unchecked")
    public static String int256DynamicArrayToString(Object list) {
        return int256DynamicArrayToString((List<Int256>) list);
    }

    public static String uint256ArrayToString(List<Uint256> list) {
        List<String> stringList = new ArrayList<>();
        for (int i = 0; i < list.size(); i++) {
            stringList.add(list.get(i).getValue().toString());
        }
        return JacksonUtils.toJson(stringList);
    }

    @SuppressWarnings("unchecked")
    public static String uint256ArrayToString(Object list) {
        return uint256ArrayToString((List<Uint256>) list);
    }

    public static String intDynamicArrayToString(List<Int> list) {
        List<String> stringList = new ArrayList<>();
        for (int i = 0; i < list.size(); i++) {
            stringList.add(list.get(i).getValue().toString());
        }
        return JacksonUtils.toJson(stringList);
    }

    public static String bytes32DynamicArrayToString(List<Bytes32> bytes32List) {
        return JacksonUtils.toJson(bytes32DynamicArrayToList(bytes32List));
    }

    public static List<String> bytes32DynamicArrayToList(List<Bytes32> bytes32List) {
        List<String> stringList = new ArrayList<>();
        for (int i = 0; i < bytes32List.size(); i++) {
            stringList.add(bytesTypeToString(bytes32List.get(i)).trim());
        }
        return stringList;
    }

    public static String bytes32ListTypeToString(List<Bytes32> list) {
        return JacksonUtils.toJson(bytes32ListToStringList(list));
    }

    @SuppressWarnings("unchecked")
    public static String bytes32ListToString(Object obj) {
        return JacksonUtils.toJson(bytes32ListToStringList((List<Bytes32>) obj));
    }

    @SuppressWarnings("unchecked")
    public static String staticArrayBytes32ToString(Object obj) {
        StaticArray<Bytes32> sa = (StaticArray<Bytes32>) obj;
        List<Bytes32> list = sa.getValue();
        return bytes32ListTypeToString(list);
    }

    @SuppressWarnings("unchecked")
    public static String bytesListObjectToString(Object obj) {
        List<Bytes> list = (List<Bytes>) obj;
        return bytesListToString(list);
    }

    public static String bytesListToString(List<Bytes> list) {
        return JacksonUtils
                .toJson(list.stream().map(b -> b.getValue()).map(b -> new String(b)).collect(Collectors.toList()));
    }

    @SuppressWarnings("unchecked")
    public static String dynamicBytesListObjectToString(Object obj) {
        List<DynamicBytes> list = (List<DynamicBytes>) obj;
        return dynamicBytesListToString(list);
    }

    public static String dynamicBytesListToString(List<DynamicBytes> list) {
        return JacksonUtils
                .toJson(list.stream().map(b -> b.getValue()).map(b -> new String(b)).collect(Collectors.toList()));
    }

    public static String listByteArrayToString(List<byte[]> list) {
        return JacksonUtils.toJson(list.stream().map(b -> String.valueOf(b)).collect(Collectors.toList()));
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    public static String typeListToString(Object typeList) {
        List<Type> list = (List<Type>) typeList;
        List<String> stringList =
                list.stream().map(t -> t.getValue()).map(s -> String.valueOf(s)).collect(Collectors.toList());
        return JacksonUtils.toJson(stringList);
    }

    @SuppressWarnings("unchecked")
    public static String numericTypeListToString(Object typeList) {
        List<NumericType> list = (List<NumericType>) typeList;
        List<BigInteger> stringList = list.stream().map(t -> t.getValue()).collect(Collectors.toList());
        return JacksonUtils.toJson(stringList);
    }

    @SuppressWarnings("unchecked")
    public static String bytesTypeListToString(Object typeList) {
        List<BytesType> list = (List<BytesType>) typeList;
        List<String> stringList = list.stream().map(t -> t.getValue())
                .map(b -> StrUtil.str(b, Charset.defaultCharset())).collect(Collectors.toList());
        return JacksonUtils.toJson(stringList);
    }

    @SuppressWarnings("unchecked")
    public static String stringListToString(Object stringList) {
        String s = JacksonUtils.toJson(stringList);
        if (StringUtils.contains(s, "value") && StringUtils.contains(s, "typeAsString")) {
            List<Map<String, String>> maps = JacksonUtils.fromJson(s, List.class, Map.class);
            List<String> r = new ArrayList<>();
            for (Map<String, String> map : maps) {
                String v = map.get("value");
                if (v != null) {
                    r.add(v);
                }
            }
            return JacksonUtils.toJson(r);
        } else {
            return s;
        }
    }
}
