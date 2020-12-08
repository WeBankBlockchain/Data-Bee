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
package com.webank.blockchain.data.export.core.utils;

import org.fisco.bcos.sdk.abi.wrapper.ABICodecObject;
import org.fisco.bcos.sdk.abi.wrapper.ABIDefinition;
import org.fisco.bcos.sdk.abi.wrapper.ABIDefinitionFactory;
import org.fisco.bcos.sdk.abi.wrapper.ABIObject;
import org.fisco.bcos.sdk.abi.wrapper.ABIObjectFactory;
import org.fisco.bcos.sdk.abi.wrapper.ContractABIDefinition;
import org.fisco.bcos.sdk.client.Client;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import com.webank.blockchain.data.export.common.tools.JacksonUtils;
import com.webank.blockchain.data.export.core.DataBeeApplicationTests;

/**
 * MethodDecodeTest
 *
 * @Description: MethodDecodeTest
 * @author maojiayu
 * @data Oct 26, 2020 11:14:10 AM
 *
 */
public class MethodDecodeTest extends DataBeeApplicationTests{
    @Autowired
    Client client;
    
    @Test
    public void testDecode() {
        String input =
                "0xdf94431c0000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000147365742076616c75657320e5ad97e7aca6e4b8b2000000000000000000000000";
        String abi =
                "[{\"name\":\"setValues\",\"type\":\"function\",\"constant\":false,\"payable\":false,\"anonymous\":false,\"stateMutability\":\"nonpayable\",\"inputs\":[{\"name\":\"i\",\"type\":\"int256\",\"indexed\":false,\"components\":null,\"typeAsString\":\"int256\"},{\"name\":\"a\",\"type\":\"address[]\",\"indexed\":false,\"components\":null,\"typeAsString\":\"address[]\"},{\"name\":\"s\",\"type\":\"string\",\"indexed\":false,\"components\":null,\"typeAsString\":\"string\"}],\"outputs\":[],\"methodSignatureAsString\":\"setValues(int256,address[],string)\"}]";
        ABICodecObject abiCodecObject = new ABICodecObject();
        ABIDefinitionFactory abiDefinitionFactory = new ABIDefinitionFactory(client.getCryptoSuite());
        ABIObjectFactory abiObjectFactory = new ABIObjectFactory();
        ContractABIDefinition contractABIDefinition = abiDefinitionFactory.loadABI(abi);
        ABIDefinition abiDef = contractABIDefinition.getFunctions().get("setValues").get(0);
        ABIObject outputABIObject = abiObjectFactory.createInputObject(abiDef);
        System.out.println(JacksonUtils.toJson(outputABIObject));
    }

}
