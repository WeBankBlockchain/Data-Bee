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
package com.webank.blockchain.data.export.core.exception;

import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.boot.diagnostics.AbstractFailureAnalyzer;
import org.springframework.boot.diagnostics.FailureAnalysis;

/**
 * NoSuchBeanExceptionAnalyzer
 *
 * @Description: NoSuchBeanExceptionAnalyzer
 * @author maojiayu
 * @data Jul 16, 2019 10:20:32 AM
 *
 */
public class NoSuchBeanExceptionAnalyzer extends AbstractFailureAnalyzer<NoSuchBeanDefinitionException> {

    @Override
    protected FailureAnalysis analyze(Throwable rootFailure, NoSuchBeanDefinitionException cause) {
        return new FailureAnalysis(cause.getMessage(),
                "please check your package path of java contract files and system.contractPackName in application.properties. Ensure your config is equal to your java package. eg. the default config is system.contractPackName=org.fisco.bcos.temp just as it in HelloWorld.Java",
                cause);
    }

}
