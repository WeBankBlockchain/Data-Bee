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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.webank.blockchain.data.export.common.constants.StatusCode;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.Map;

/**
 * CommonResponse
 *
 * @author maojiayu
 * @data Dec 28, 2018 6:02:57 PM
 *
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Accessors(chain = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CommonResponse {
    protected int status = 0;
    protected Msg msg;
    public static CommonResponse SUCCESS = new CommonResponse();
    public static CommonResponse UNLOGIN = new CommonResponse(StatusCode.SESSION_EXPIRED, "user not login");
    public static CommonResponse UNAUTH = new CommonResponse(StatusCode.UNAUTH, "user no auth");
    public static CommonResponse SYSERROR = new CommonResponse(StatusCode.EXECUTE_ERROR, "execute error");
    public static CommonResponse NOBLOCK = new CommonResponse(StatusCode.PARAMETER_ERROR, "no block data");

    public CommonResponse(int status, String error) {
        this.status = status;
        this.msg = new Msg().setGlobal(error);
    }

    @Data
    @Accessors(chain = true)
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Msg {
        private String global;
        private Map<String, String> fields;
    }
}
