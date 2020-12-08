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
package com.webank.blockchain.data.export.codegen.task;

import com.webank.blockchain.data.export.codegen.code.service.CodeGenerateService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

/**
 * GenerateCodeApplicationRunner: task entrance.
 *
 * @author maojiayu
 * @date 2018-11-29 16:37:38
 * 
 */
@Component
@Profile("!test")
@Order(value = 1)
@Slf4j
public class GenerateCodeApplicationRunner implements ApplicationRunner {
    @Autowired
    private CodeGenerateService codeGenerateService;

    @Override
    public void run(ApplicationArguments var1) throws Exception {

        log.info("Begin to generate code.");
        codeGenerateService.generateBee();
        log.info("Code generation Finished!");       
        Runtime.getRuntime().exit(0);
    }
}