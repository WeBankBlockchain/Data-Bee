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
package com.webank.blockchain.data.export.db.repository;

import cn.hutool.core.collection.CollectionUtil;
import cn.hutool.db.DaoTemplate;
import cn.hutool.db.Db;
import cn.hutool.db.Entity;
import com.webank.blockchain.data.export.common.entity.ExportConstant;
import com.webank.blockchain.data.export.db.entity.BlockDetailInfo;
import com.webank.blockchain.data.export.db.entity.BlockTxDetailInfo;
import com.webank.blockchain.data.export.db.tools.BeanUtils;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * BlockTxDetailInfoRepository
 *
 * @Description: BlockTxDetailInfoRepository
 * @author graysonzhang
 * @data 2018-12-20 14:52:22
 *
 */
@Slf4j
@AllArgsConstructor
public class BlockTxDetailInfoRepository implements RollbackInterface {

    private DaoTemplate blockTxDetailInfoDao;

    private String tableName;

    /**
     * Get block transaction info according to block height, return BlockTxDetailInfo object list.
     * 
     * @param blockHeight: block height
     * @return List<BlockTxDetailInfo>
     */
    public List<BlockTxDetailInfo> findByBlockHeight(long blockHeight){
        List<Entity> entityList = null;
        try {
            entityList = blockTxDetailInfoDao.find("block_height", blockHeight);
        } catch (SQLException e) {
            log.error(" BlockTxDetailInfoRepository findByBlockHeight failed ", e);
        }
        List<BlockTxDetailInfo> result = new ArrayList<>();
        entityList.forEach(e -> {
            result.add(e.toBean(BlockTxDetailInfo.class));
        });
        return result;
    }

    /**
     * Get block transaction info according to transaction sender, return BlockTxDetailInfo object list.
     *
     * @param txFrom: transaction sender
     * @return List<BlockTxDetailInfo>
     */
    public List<BlockTxDetailInfo> findByTxFrom(String txFrom){
        List<Entity> entityList = null;
        try {
            entityList = blockTxDetailInfoDao.find("tx_from", txFrom);
        } catch (SQLException e) {
            log.error(" BlockTxDetailInfoRepository findByTxFrom failed ", e);
        }
        List<BlockTxDetailInfo> result = new ArrayList<>();
        if (CollectionUtil.isEmpty(entityList)){
            return result;
        }
        entityList.forEach(e -> {
            result.add(BeanUtils.toBean(e, BlockTxDetailInfo.class));
        });
        return result;
    }

    /*
     * @see com.webank.blockchain.data.export.sys.db.repository.RollbackInterface#rollback(long)
     */
    public void rollback(long blockHeight){
        try {
            blockTxDetailInfoDao.del(Entity.create(tableName).set("block_height",">= " + blockHeight));
        } catch (SQLException e) {
            log.error(" BlockTxDetailInfoRepository rollback failed ", e);
        }
    }

    /*
     * @see com.webank.blockchain.data.export.sys.db.repository.RollbackInterface#rollback(long)
     */
    public void rollback(long startBlockHeight, long endBlockHeight){
        try {
            Db.use(ExportConstant.getCurrentContext().getDataSource()).execute(
                    "delete from "+ tableName +" where block_height >= ? and block_height< ?",startBlockHeight,endBlockHeight);
        } catch (SQLException e) {
            log.error(" BlockTxDetailInfoRepository rollback failed ", e);
        }
    }

    public void save(BlockTxDetailInfo blockTxDetailInfo) {
        try {
            Entity entity = Entity.parse(blockTxDetailInfo,true,true);
            entity.setTableName(tableName);
            blockTxDetailInfoDao.addForGeneratedKey(entity);
        } catch (SQLException e) {
            log.error(" BlockDetailInfoRepository save failed ", e);
        }
    }
}
