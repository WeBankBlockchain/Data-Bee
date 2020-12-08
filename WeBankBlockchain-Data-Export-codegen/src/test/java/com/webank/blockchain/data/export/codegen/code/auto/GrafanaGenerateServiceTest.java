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
package com.webank.blockchain.data.export.codegen.code.auto;

import java.io.IOException;

import com.webank.blockchain.data.export.codegen.code.template.GrafanaGenerateService;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import com.webank.blockchain.data.export.codegen.DataBeeCodegenApplicationTests;

/**
 * GrafanaGenerateService
 *
 * @Description: GrafanaGenerateService
 * @author maojiayu
 * @data Mar 27, 2019 5:42:59 PM
 *
 */
public class GrafanaGenerateServiceTest extends DataBeeCodegenApplicationTests {
    @Autowired
    private GrafanaGenerateService service;
    
    @Test
    public void testGenerate() throws ClassNotFoundException, IOException {
        service.genereate();
        Assertions.assertNotNull(service);
    }

}
