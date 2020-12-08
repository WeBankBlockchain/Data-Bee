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
package com.webank.blockchain.data.export.core.api.manager;

import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;

import com.webank.blockchain.data.export.common.tools.ResponseUtils;
import com.webank.blockchain.data.export.common.vo.CommonResponse;

import lombok.extern.slf4j.Slf4j;

/**
 * ExceptionManager
 *
 * @Description: ExceptionManager
 * @author maojiayu
 * @data Jan 23, 2019 4:40:43 PM
 *
 */

@ControllerAdvice
@Slf4j
public class ExceptionManager {
    @ResponseBody
    @ExceptionHandler
    public CommonResponse processException(Exception e) {
        log.error("ERROR occurred: {}", e.getMessage());
        if (e instanceof HttpMessageNotReadableException) {
            return ResponseUtils.paramError(
                    "Http read convert error. Not a valid input, please check your input field! " + e.getMessage());
        }
        return ResponseUtils.exception(e);
    }
}
