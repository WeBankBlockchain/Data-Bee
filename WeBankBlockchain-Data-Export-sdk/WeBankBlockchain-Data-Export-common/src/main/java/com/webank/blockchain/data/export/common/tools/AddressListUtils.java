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

import org.fisco.bcos.sdk.abi.datatypes.Address;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;


/**
 * AddressListUtils
 *
 * @Description: AddressListUtils
 * @author maojiayu
 * @data Dec 28, 2018 6:13:58 PM
 *
 */
public class AddressListUtils {

    public static List<Address> toAddressList(List<String> strList) {
        if (strList.isEmpty()) {
            return new ArrayList<Address>();
        } else {
            return strList.stream().map(str -> {
                return new Address(str);
            }).collect(Collectors.toList());
        }
    }

    public static List<String> addressToStrList(List<Address> adressList) {
        if (adressList.isEmpty()) {
            return new ArrayList<String>();
        } else {
            return adressList.stream().map(addr -> {
                return addr.toString().trim();
            }).collect(Collectors.toList());
        }
    }

}
