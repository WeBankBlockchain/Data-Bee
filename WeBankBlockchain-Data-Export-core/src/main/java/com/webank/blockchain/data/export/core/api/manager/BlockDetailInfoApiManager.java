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

import com.webank.blockchain.data.export.db.dao.BlockDetailInfoDAO;
import com.webank.blockchain.data.export.db.repository.BlockDetailInfoRepository;
import com.webank.blockchain.data.export.db.service.CommonQueryService;
import com.webank.blockchain.data.export.db.service.TimeRangeQueryService;
import com.webank.blockchain.data.export.db.vo.BlockHeightQueryReq;
import com.webank.blockchain.data.export.db.vo.TimeRangeQueryReq;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.webank.blockchain.data.export.common.tools.ResponseUtils;
import com.webank.blockchain.data.export.common.vo.CommonResponse;

/**
 * BlockDetailInfoApiManager
 *
 * @Description: BlockDetailInfoApiManager
 * @author maojiayu
 * @data Dec 21, 2018 11:03:51 AM
 *
 */
@Service
public class BlockDetailInfoApiManager {

    @Autowired
    private TimeRangeQueryService timeRangeQueryService;
    @Autowired
    private BlockDetailInfoDAO blockDetailInfoDao;
    @Autowired
    private BlockDetailInfoRepository blockDetailInfoRepository;
    @Autowired
    private CommonQueryService commonQueryService;


    public CommonResponse getPageListByTimeRange(TimeRangeQueryReq req) {

        return timeRangeQueryService.getPageListByTimeRange(req, blockDetailInfoRepository);
    }
    @SuppressWarnings("unchecked")
    public CommonResponse getBlockDetailInfoByBlockHeight(BlockHeightQueryReq req) {
        return commonQueryService.getPageListByCommonReq(req.toCommonParaQueryPageReq(), blockDetailInfoRepository);
    }

    public CommonResponse getBlockDetailInfoByBlockHash(String blockHash) {
        return ResponseUtils.data(blockDetailInfoDao.getBlockDetailInfoByBlockHash(blockHash));
    }
}
