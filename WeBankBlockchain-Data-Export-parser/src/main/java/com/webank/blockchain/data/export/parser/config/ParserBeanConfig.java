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
package com.webank.blockchain.data.export.parser.config;

import com.webank.blockchain.data.export.parser.crawler.face.BcosEventCrawlerInterface;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

/**
 * BeanConfig
 *
 * @Description: BeanConfig
 * @author maojiayu
 * @data Jul 3, 2019 11:39:50 AM
 *
 */
@Configuration
@Slf4j
public class ParserBeanConfig {

    @Bean
    @ConditionalOnMissingBean(type = "BcosEventCrawlerInterface")
    public Map<String, BcosEventCrawlerInterface> getEmptyEventMap() {
        return new HashMap<String, BcosEventCrawlerInterface>();
    }

}
