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
import com.webank.blockchain.data.export.common.bo.data.BlockRawDataBO;
import com.webank.blockchain.data.export.db.entity.BlockRawData;
import com.webank.blockchain.data.export.db.repository.BlockRawDataRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * @author wesleywang
 * @Description:
 * @date 2020/10/23
 */
@Component
public class BlockRawDataDAO implements SaveInterface<BlockRawDataBO>{

    @Autowired
    private BlockRawDataRepository blockRawDataRepository;

    @Override
    public void save(BlockRawDataBO blockRawDataBO) {
        BlockRawData blockRawData = new BlockRawData();
        BeanUtil.copyProperties(blockRawDataBO, blockRawData, true);
        save(blockRawData);
    }

    public void save(BlockRawData blockRawData) {
        BaseDAO.saveWithTimeLog(blockRawDataRepository, blockRawData);
    }
}
