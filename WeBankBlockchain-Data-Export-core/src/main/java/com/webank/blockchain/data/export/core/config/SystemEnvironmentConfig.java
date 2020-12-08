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

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * System Environment Config.
 *
 * @Description: SystemEnvironmentConfig
 * @author maojiayu
 * @data Dec 28, 2018 5:21:48 PM
 *
 */
@Configuration
@ConfigurationProperties("system")
@Data
public class SystemEnvironmentConfig {
    private String nodeStr;
    private int groupId;

    private String configPath;

    private int crawlBatchUnit = 1000;

    private boolean multiLiving;
    private String zookeeperServiceLists;
    private String zookeeperNamespace;
    private String elasticJobName;
    private String elasticJobcron;
    private int elasticJobshardingTotalCount;

    private long frequency;
    private String contractPackName;
    private String group;
    private String baseProjectPath;
    private String projectName;
    private String contractPath;

    private long startBlockHeight = 0;
    private String startDate;
    
    private int encryptType = 0;
}
