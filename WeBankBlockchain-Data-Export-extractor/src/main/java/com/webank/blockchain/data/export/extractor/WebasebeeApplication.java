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
package com.webank.blockchain.data.export.extractor;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * webasebeeApplication connect to fisco-bcos, and depot its datas.
 *
 * @Description: webase-bee project is a java project created by webase-monkey project, that using for crawling data
 *               from fisco-bcos netwwork, including block data，event data, transaction data and account data.
 * @author maojiayu
 * @data Dec 28, 2018 4:15:20 PM
 *
 */
@SpringBootApplication
public class WebasebeeApplication {

    public static void main(String[] args) {
        SpringApplication.run(WebasebeeApplication.class, args);
    }

}
