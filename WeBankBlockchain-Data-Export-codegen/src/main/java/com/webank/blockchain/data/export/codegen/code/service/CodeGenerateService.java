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
package com.webank.blockchain.data.export.codegen.code.service;

import java.io.IOException;
import java.util.Map;

import com.webank.blockchain.data.export.codegen.code.template.CodeTemplateGenerateService;
import com.webank.blockchain.data.export.codegen.code.template.face.ConfigGenerateParas;
import com.webank.blockchain.data.export.codegen.code.template.face.EventGenerateParas;
import com.webank.blockchain.data.export.codegen.code.template.face.MethodGenerateParas;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.webank.blockchain.data.export.codegen.code.template.GrafanaGenerateService;
import com.webank.blockchain.data.export.codegen.vo.ContractInfo;

import lombok.extern.slf4j.Slf4j;

/**
 * CodeGenerateService
 *
 * @Description: CodeGenerateService used to generate java code files for crawling block chain network data.
 * @author maojiayu
 * @data 2018-12-04 15:56:40
 *
 */
@Service
@Slf4j
public class CodeGenerateService {

    /** @Fields templateGenerateService : template generate service */
    @SuppressWarnings("rawtypes")
    @Autowired
    private CodeTemplateGenerateService templateGenerateService;
    @Autowired
    private ContractInfoService contractInfoService;
    @Autowired
    private GrafanaGenerateService grafanaGenerateService;
    /** @Fields configParasMap : config params map for generating config files */
    @Autowired
    private Map<String, ConfigGenerateParas> configParasMap;
    /** @Fields methodParasMap : method params map for generating code files of crawling method data */
    @Autowired
    private Map<String, MethodGenerateParas> methodParasMap;

    /** @Fields eventParasMap : event params map for generating code files of crawling event data */
    @Autowired
    private Map<String, EventGenerateParas> eventParasMap;

    @SuppressWarnings("unchecked")
    public void generateBee() throws ClassNotFoundException, IOException {
        ContractInfo info = contractInfoService.parseFromContract();
        // generate java code files for crawling event data from block chain network
        templateGenerateService.generate(info.getEventList(), eventParasMap);
        // generate java code files for crawling method data from blcok chain network
        templateGenerateService.generate(info.getMethodList(), methodParasMap);
        // generate config files for crawling data.
        templateGenerateService.generate(info, configParasMap);
        log.info("Begin to generate grafana dashboard json.");
        grafanaGenerateService.genereate();
        log.info("Grafana json generation Finished!");
    }
}
