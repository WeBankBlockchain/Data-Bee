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

import com.webank.blockchain.data.export.db.repository.BlockTaskPoolRepository;
import org.fisco.bcos.sdk.client.Client;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.webank.blockchain.data.export.common.enums.TxInfoStatusEnum;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;

/**
 * BlockTaskInfoController
 *
 * @Description: BlockTaskInfoController
 * @author maojiayu
 * @data May 21, 2019 7:42:45 PM
 *
 */
@RestController
@RequestMapping("/api/blockTaskPool")
@Api(value = "BlockTaskPoolController", tags = "Block Task Pool Query")
public class BlockTaskPoolController {
    @Autowired
    private Client client;
    @Autowired
    private BlockTaskPoolRepository blockTaskPoolRepository;

    @ResponseBody
    @RequestMapping("/blocks/get")
    @ApiOperation(value = "Get finished block count", httpMethod = "GET")
    public long getFinishedBlockCount() {
        return blockTaskPoolRepository.countBySyncStatus((short) TxInfoStatusEnum.DONE.getStatus());
    }

    @ResponseBody
    @RequestMapping("/blockHeight/get")
    @ApiOperation(value = "Get block height", httpMethod = "GET")
    public long getBlockHeight() {
        return client.getBlockNumber().getBlockNumber().longValue();
    }

}
