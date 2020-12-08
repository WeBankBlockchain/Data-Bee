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
package com.webank.blockchain.data.export.core.api.controller;

import java.io.IOException;

import javax.validation.Valid;
import javax.validation.constraints.Min;

import com.webank.blockchain.data.export.core.service.BlockDataResetService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.webank.blockchain.data.export.common.tools.ResponseUtils;
import com.webank.blockchain.data.export.common.vo.CommonResponse;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;

/**
 * 
 * BlockDataResetterController
 *
 * @Description: BlockDataResetterController
 * @author graysonzhang
 * @data 2019-03-21 14:46:34
 *
 */
@RestController
@RequestMapping("/api/blockdata/")
@Api(value = "BlockDataResetterController", tags = "Block Data Infomation Reset")
public class BlockDataResetterController {

    @Autowired
    private BlockDataResetService blockDataResetService;

    @ResponseBody
    @RequestMapping("/reset")
    @ApiOperation(value = "reset single block data", httpMethod = "POST")
    public CommonResponse resetBlockDataByBlockId(@RequestBody @Valid @Min(0) long blockHeight, BindingResult result)
            throws IOException {
        if (result.hasErrors()) {
            return ResponseUtils.validateError(result);
        }

        return blockDataResetService.resetBlockDataByBlockId(blockHeight);
    }

}
