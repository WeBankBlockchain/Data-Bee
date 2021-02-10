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
package com.webank.blockchain.data.export.db.config;

import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

/**
 * BeanConfig registers system common beans.
 *
 * @author maojiayu
 * @data Dec 28, 2018 5:07:41 PM
 *
 */
@Configuration
@ComponentScan
@EntityScan(basePackages = { "com.webank.blockchain.data.export.db.entity", "com.webank.blockchain.data.export.db.generated.entity" })
@EnableJpaRepositories(basePackages = { "com.webank.blockchain.data.export.db.repository",
        "com.webank.blockchain.data.export.db.generated.repository" })
public class DBBeanConfig {

}