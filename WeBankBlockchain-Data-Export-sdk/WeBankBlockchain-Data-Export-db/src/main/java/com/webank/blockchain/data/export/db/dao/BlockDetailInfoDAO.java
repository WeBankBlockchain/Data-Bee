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
package com.webank.blockchain.data.export.db.dao;

import cn.hutool.core.bean.BeanUtil;
import com.webank.blockchain.data.export.common.bo.data.BlockDetailInfoBO;
import com.webank.blockchain.data.export.common.bo.data.BlockInfoBO;
import com.webank.blockchain.data.export.db.entity.BlockDetailInfo;
import com.webank.blockchain.data.export.db.repository.BlockDetailInfoRepository;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * BlockDetailInfoDAO
 *
 * @author maojiayu
 * @data Dec 12, 2018 2:45:13 PM
 *
 */
@Slf4j
@AllArgsConstructor
public class BlockDetailInfoDAO implements SaveInterface<BlockInfoBO> {

    private final BlockDetailInfoRepository blockDetailInfoRepository;
    
    public void save(BlockDetailInfoBO bo) {
        BlockDetailInfo blockDetailInfo = new BlockDetailInfo();
        BeanUtil.copyProperties(bo, blockDetailInfo, true);
        save(blockDetailInfo);
    }

    public void save(BlockDetailInfo blockDetailInfo) {
        blockDetailInfoRepository.save(blockDetailInfo);
    }

    @Override
    public void save(BlockInfoBO t) {
        save(t.getBlockDetailInfo());
    }
}
