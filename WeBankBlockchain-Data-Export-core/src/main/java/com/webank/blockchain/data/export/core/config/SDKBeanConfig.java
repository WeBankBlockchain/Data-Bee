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
package com.webank.blockchain.data.export.core.config;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.fisco.bcos.sdk.BcosSDK;
import org.fisco.bcos.sdk.client.Client;
import org.fisco.bcos.sdk.config.ConfigOption;
import org.fisco.bcos.sdk.config.exceptions.ConfigException;
import org.fisco.bcos.sdk.config.model.ConfigProperty;
import org.fisco.bcos.sdk.crypto.keypair.CryptoKeyPair;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.google.common.collect.Maps;

/**
 * Web3jV2BeanConfig
 *
 * @Description: Web3jV2BeanConfig
 * @author maojiayu
 * @data Apr 16, 2019 11:13:23 AM
 *
 */
@Configuration
public class SDKBeanConfig {

    @Autowired
    private SystemEnvironmentConfig systemEnvironmentConfig;
    
    @Bean
    public CryptoKeyPair cryptoKeyPair() throws ConfigException {
        Client client = getClient();
        return client.getCryptoSuite().createKeyPair();
    }
    
    @Bean
    public Client getClient() throws ConfigException {
        BcosSDK sdk = getSDK();
        return sdk.getClient(systemEnvironmentConfig.getGroupId());
    }
    
    @Bean
    public BcosSDK getSDK() throws ConfigException {
        ConfigProperty configProperty = new ConfigProperty();
        setPeers(configProperty);
        setCertPath(configProperty);
        ConfigOption option = new ConfigOption(configProperty);
        return new BcosSDK(option);
    }
    
    public void setPeers(ConfigProperty configProperty) {
        String[] nodes = StringUtils.split(systemEnvironmentConfig.getNodeStr(), ";");
        List<String> peers = Arrays.asList(nodes);
        Map<String, Object> network = Maps.newHashMapWithExpectedSize(1);
        network.put("peers", peers);
        configProperty.setNetwork(network);
    }
    
    public void setCertPath(ConfigProperty configProperty) {
        Map<String, Object> cryptoMaterial = Maps.newHashMapWithExpectedSize(1);
        cryptoMaterial.put("certPath", "config");
        configProperty.setCryptoMaterial(cryptoMaterial);
    }
}
