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

import org.junit.jupiter.api.Test;

import com.webank.blockchain.data.export.core.DataBeeApplicationTests;

import cn.hutool.setting.dialect.Props;

/**
 * PropertiesTest
 *
 * @Description: PropertiesTest
 * @author maojiayu
 * @data Jul 7, 2020 5:08:59 PM
 *
 */
public class PropertiesTest extends DataBeeApplicationTests{
    
    @Test
    public void test() {
        Props props = new Props("application-sharding-tables.properties");
        String ps = props.getProperty("spring.shardingsphere.datasource.ds.password");
        System.out.println(ps);
    }
    
    public static void main(String[] args) {
        Props props = new Props("application-sharding-tables.properties");
        String ps = props.getProperty("spring.shardingsphere.datasource.ds.password");
        System.out.println(ps);
    }
}
