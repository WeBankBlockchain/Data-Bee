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

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;

import com.webank.blockchain.data.export.db.vo.BlockHeightQueryReq;
import com.webank.blockchain.data.export.db.vo.TimeRangeQueryReq;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.webank.blockchain.data.export.common.tools.ResponseUtils;
import com.webank.blockchain.data.export.common.vo.CommonResponse;
import com.webank.blockchain.data.export.core.api.manager.BlockDetailInfoApiManager;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;

/**
 * BlockTxDetailInfoManager
 *
 * @Description: BlockTxDetailInfoManager
 * @author maojiayu
 * @data Dec 21, 2018 11:47:08 AM
 *
 */
@RestController
@RequestMapping("/api/blockDetailInfo")
@Api(value = "BlockDetailInfoController", tags = "Block Detail Infomation Query")
public class BlockDetailInfoController {
    @Autowired
    private BlockDetailInfoApiManager blockDetailInfoManager;

    @ResponseBody
    @RequestMapping("/time/get")
    @ApiOperation(value = "Base on time range", httpMethod = "POST")
    public CommonResponse getBlockTxDetailInfoByTimeRange(@RequestBody @Valid TimeRangeQueryReq req,
            BindingResult result) {
        if (result.hasErrors()) {
            return ResponseUtils.validateError(result);
        }

        return blockDetailInfoManager.getPageListByTimeRange(req);
    }

    @PostMapping("/blockHeight/get")
    @ApiOperation(value = "get block height detail", httpMethod = "POST")
    public CommonResponse getBlockDetailInfoByBlockHeight(@RequestBody @Valid BlockHeightQueryReq req,
            BindingResult result) {
        if (result.hasErrors()) {
            return ResponseUtils.validateError(result);
        }
        return blockDetailInfoManager.getBlockDetailInfoByBlockHeight(req);
    }

    @PostMapping("/hash/get")
    @ApiOperation(value = "get block Info by Hash", httpMethod = "POST")
    public CommonResponse getBlockDetailInfoByBlockHash(@RequestBody @Valid @NotBlank String blockHash,
            BindingResult result) {
        if (result.hasErrors()) {
            return ResponseUtils.validateError(result);
        }
        if (!StringUtils.startsWithIgnoreCase(blockHash, "0x")) {
            return ResponseUtils.paramError("Block hash is not valid.");
        }
        return blockDetailInfoManager.getBlockDetailInfoByBlockHash(blockHash);
    }

}
