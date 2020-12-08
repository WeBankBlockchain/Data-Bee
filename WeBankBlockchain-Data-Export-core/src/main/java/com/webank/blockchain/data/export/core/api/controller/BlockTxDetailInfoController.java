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

import com.webank.blockchain.data.export.db.vo.BlockHeightQueryReq;
import com.webank.blockchain.data.export.db.vo.TimeRangeQueryReq;
import com.webank.blockchain.data.export.db.vo.TxFromQueryReq;
import com.webank.blockchain.data.export.core.api.manager.BlockTxDetailInfoApiManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.webank.blockchain.data.export.common.tools.JacksonUtils;
import com.webank.blockchain.data.export.common.tools.ResponseUtils;
import com.webank.blockchain.data.export.common.vo.CommonResponse;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;

/**
 * BlockTxDetailInfoManager
 *
 * @Description: BlockTxDetailInfoManager
 * @author maojiayu
 * @data Dec 21, 2018 11:47:08 AM
 *
 */
@RestController
@RequestMapping("/api/blockTxDetailInfo")
@Api(value = "BlockTxDetailInfoController", tags = "Block Transaction Details Query")
@Slf4j
public class BlockTxDetailInfoController {

    @Autowired
    private BlockTxDetailInfoApiManager blockTxDetailInfoManager;

    @ResponseBody
    @RequestMapping("/time/get")
    @ApiOperation(value = "based on time range", httpMethod = "POST")
    public CommonResponse getBlockTxDetailInfoByTimeRange(@RequestBody @Valid TimeRangeQueryReq req,
            BindingResult result) {
        if (result.hasErrors()) {
            return ResponseUtils.validateError(result);
        }

        return blockTxDetailInfoManager.getPageListByTimeRange(req);
    }

    @PostMapping("/blockHeight/get")

    @ApiOperation(value = "query block tx detail info by block height", httpMethod = "POST")
    public CommonResponse getBlockDetailInfoByBlockHeight(@RequestBody @Valid BlockHeightQueryReq req, BindingResult result) {
        if (result.hasErrors()) {
            log.error("parameter error: {}", JacksonUtils.toJson(result.getAllErrors()));
            return ResponseUtils.validateError(result);
        }
        return blockTxDetailInfoManager.getBlockTxDetailInfoByBlockHeight(req);
    }
    
    @PostMapping("/txFrom/get")

    @ApiOperation(value = "query block tx detail info by tx from", httpMethod = "POST")
    public CommonResponse getBlockDetailInfoByTxFrom(@RequestBody @Valid TxFromQueryReq req, BindingResult result) {
        if (result.hasErrors()) {
            return ResponseUtils.validateError(result);
        }
        return blockTxDetailInfoManager.getBlockTxDetailInfoByTxFrom(req);
    }
}
