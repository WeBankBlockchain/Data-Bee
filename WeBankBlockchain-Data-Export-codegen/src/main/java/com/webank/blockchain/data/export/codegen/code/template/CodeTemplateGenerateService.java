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
package com.webank.blockchain.data.export.codegen.code.template;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Map;

import com.webank.blockchain.data.export.codegen.config.SystemEnvironmentConfig;
import com.webank.blockchain.data.export.codegen.code.template.face.GenerateParas;
import org.apache.commons.io.FileUtils;
import org.beetl.core.GroupTemplate;
import org.beetl.core.Template;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.webank.blockchain.data.export.codegen.vo.ContractNameVO;

import lombok.extern.slf4j.Slf4j;

/**
 * TemplateGenerateService
 *
 * @Description: TemplateGenerateService
 * @author maojiayu
 * @data 2018-12-19 14:51:00
 *
 */
@Slf4j
@Service
public class CodeTemplateGenerateService<T> {

    /** @Fields gt : group template */
    @Autowired
    protected GroupTemplate gt;
    @Autowired
    protected SystemEnvironmentConfig systemEnvironmentConfig;

    /**
     * write generated files to corresponding packages.
     * 
     * @param generateParas: paras for writing files
     * @param vo
     * @return void
     */
    @SuppressWarnings({ "unchecked", "rawtypes" })
    public void write(GenerateParas generateParas, ContractNameVO vo) {
        Template template = gt.getTemplate(generateParas.getTemplatePath());
        template.binding(generateParas.getMap(vo));
        String renderResult = template.render();
        try {
            String filePath = systemEnvironmentConfig.getBaseProjectPath() + File.separator
                    + generateParas.getGeneratedFilePath(vo);
            FileUtils.write(new File(filePath), renderResult, "utf-8", false);
            log.info("Write succeed: {}", filePath);
        } catch (IOException e) {
            log.error("GeneratedFiles write fail. cause: {}", e.getMessage());
        }
    }

    /**
     * create java code files for crawling data from block chain network and write to corresponding packages.
     * 
     * @param clazz: contract class
     * @param parser: methodParser or eventParser
     * @param map
     * @return List<T>
     */
    public <T extends ContractNameVO> void generate(List<T> metaInfos, Map<String, GenerateParas> map) {
        for (T mataInfo : metaInfos) {
            map.forEach((k, v) -> {
                write(v, mataInfo);
            });
        }
    }

    /**
     * create config files for crawling data from block chain network and write to corresponding packages.
     * 
     * @param config
     * @param map
     * @return void
     */
    public <T extends ContractNameVO> void generate(T config, Map<String, GenerateParas> map) {
        map.forEach((k, v) -> {
            write(v, config);
        });
    }

}
