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
package com.webank.blockchain.data.export.common.vo;

import com.webank.blockchain.data.export.common.constants.StatusCode;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.Accessors;

import java.util.HashMap;

/**
 * ValidErrorResponse， wrap the basic valid error usage of MVC.
 *
 * @author maojiayu
 * @data Dec 28, 2018 6:05:45 PM
 *
 */
@Data
@Accessors(chain = true)
@EqualsAndHashCode(callSuper = true)
public class ValidErrorResponse extends CommonResponse {
    public ValidErrorResponse() {
        this.status = StatusCode.PARAMETER_ERROR;
        msg = new Msg().setGlobal("").setFields(new HashMap<>());
    }

}
