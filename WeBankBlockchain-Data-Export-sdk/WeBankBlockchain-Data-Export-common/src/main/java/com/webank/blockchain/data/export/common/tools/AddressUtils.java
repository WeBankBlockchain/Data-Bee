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
import org.fisco.bcos.sdk.abi.datatypes.Address;
import org.fisco.bcos.sdk.abi.datatypes.StaticArray;

import java.math.BigInteger;
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

}
