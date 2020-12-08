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
package com.webank.blockchain.data.export.common.tools;

import com.webank.blockchain.data.export.common.vo.CommonDataResponse;
import com.webank.blockchain.data.export.common.vo.CommonResponse;
import com.webank.blockchain.data.export.common.vo.ValidErrorResponse;
import com.webank.blockchain.data.export.common.constants.StatusCode;
import org.springframework.validation.BindingResult;

/**
 * ResponseUtils
 *
 * @Description: ResponseUtils
 * @author maojiayu
 * @data Apr 1, 2019 9:25:46 PM
 *
 */
public class ResponseUtils {

    /**
     * return with result
     * 
     * @param data
     * @return
     */
    public static CommonResponse data(Object data) {
        return new CommonDataResponse<>().setData(data);
    }

    /**
     * return success
     * 
     * @return
     */
    public static CommonResponse success() {
        return CommonResponse.SUCCESS;
    }

    /**
     * execute error
     * 
     * @param msg
     * @return
     */
    public static CommonResponse error(String msg) {
        return new CommonResponse(StatusCode.EXECUTE_ERROR, msg);
    }

    /**
     * parameter error
     * 
     * @param msg
     * @return
     */
    public static CommonResponse paramError(String msg) {
        return new CommonResponse(StatusCode.PARAMETER_ERROR, msg);
    }

    /**
     * no request result
     * 
     * @param msg
     * @return
     */
    public static CommonResponse resultEmptyError(String msg) {
        return new CommonResponse(StatusCode.RESULT_EMPTY, msg);
    }

    /**
     * status error
     * 
     * @param msg
     * @return
     */
    public static CommonResponse statusError(String msg) {
        return new CommonResponse(StatusCode.STATUS_ERROR, msg);
    }

    public static CommonResponse unAuth(String msg) {
        return new CommonResponse(StatusCode.UNAUTH, msg);
    }

    /**
     * exception
     * 
     * @param e
     * @return
     */
    public static CommonResponse exception(Throwable e) {
        return new CommonResponse(StatusCode.EXCEPTION_OCCUR, e.getMessage());
    }

    /**
     * get error message from error configs.
     * 
     * @param name
     * @return
     */
    public static CommonResponse message(String name) {
        String value = MessageLoader.getMessage(name);
        return error(value);
    }

    /**
     * validate error
     * 
     * @param result
     * @return
     */
    public static ValidErrorResponse validateError(BindingResult result) {
        return new ValidErrorResponse(result);
    }

    public static CommonResponse unlogin() {
        return CommonResponse.UNLOGIN;
    }

    public static CommonResponse unauth() {
        return CommonResponse.UNAUTH;
    }
}
