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
import cn.hutool.db.handler.NumberHandler;
import cn.hutool.db.handler.RsHandler;
import com.webank.blockchain.data.export.common.entity.ExportConstant;
import com.webank.blockchain.data.export.db.entity.BlockDetailInfo;
import com.webank.blockchain.data.export.db.tools.BeanUtils;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

/**
 * BlockDetailInfoRepository
 *
 * @Description: BlockDetailInfoRepository
 * @author graysonzhang
 * @data 2018-11-14 18:03:48
 *
 */
@Slf4j
@AllArgsConstructor
public class BlockDetailInfoRepository implements RollbackInterface {

    private DaoTemplate blockDetailDao;

    private final String tableName = ExportConstant.BLOCK_DETAIL_INFO_TABLE;


    /**
     * Get one block detail info order by block height and desc from block_detail_info table.
     * 
     * @return BlockDetailInfo
     */
    public BlockDetailInfo findTopByOrderByBlockHeightDesc(){
        List<Entity> entityList = null;
        try {
            entityList = blockDetailDao.findBySql("block_detail_info order by block_height desc limit 1");
        } catch (SQLException e) {
            log.error(" BlockDetailInfoRepository findTopByOrderByBlockHeightDesc failed ", e);
        }
        if (CollectionUtil.isEmpty(entityList)){
            return null;
        }
        Entity entity = entityList.get(0);
        return BeanUtils.toBean(entity,BlockDetailInfo.class);
    }

    /**
     * Get records' count from block_detail_info table.
     * 
     * @return long
     */
    public long sumByTxCount(){
        try {
            return Db.use(ExportConstant.getCurrentContext().getDataSource()).query(
                    "select count(tx_count) from block_detail_info", NumberHandler.create()).intValue();
        } catch (SQLException e) {
            log.error(" BlockDetailInfoRepository sumByTxCount failed ", e);
        }
        return 0;
    }

    /**
     * Get records' count from block_detail_info table when block height >= beginIndex and <= endIndex.
     * 
     * @param beginIndex
     * @param endIndex
     * @return long
     */
    public long sumByTxCountBetweens(long beginIndex, long endIndex){
        try {
            return Db.use(ExportConstant.getCurrentContext().getDataSource()).query(
                    "select sum(tx_count) from block_detail_info where block_height >= ? and blockHeight< ?",
                    (RsHandler<Long>) rs -> rs.getLong(0),beginIndex,endIndex);
        } catch (SQLException e) {
            log.error(" BlockDetailInfoRepository sumByTxCountBetweens failed ", e);
        }
        return 0;

    }

    /*
     * @see com.webank.blockchain.data.export.sys.db.repository.RollbackInterface#rollback(long)
     */
    public void rollback(long blockHeight) {
        try {
            blockDetailDao.del(Entity.create(tableName).set("block_height",">= " + blockHeight));
        } catch (SQLException e) {
            log.error(" BlockDetailInfoRepository rollback failed ", e);
        }
    }

    /*
     * @see com.webank.blockchain.data.export.sys.db.repository.RollbackInterface#rollback(long, long)
     */
    public void rollback(long startBlockHeight, long endBlockHeight) {
        try {
            Db.use(ExportConstant.getCurrentContext().getDataSource()).execute(
                    "delete from block_detail_info where block_height >= ? and block_height< ?",startBlockHeight,endBlockHeight);
        } catch (SQLException e) {
            log.error(" BlockDetailInfoRepository rollback failed ", e);
        }
    }

    public void save(BlockDetailInfo blockDetailInfo) {
        try {
            blockDetailDao.addForGeneratedKey(Entity.parse(blockDetailInfo,true,true));
        } catch (SQLException e) {
            log.error(" BlockDetailInfoRepository save failed ", e);
        }
    }

    public BlockDetailInfo findByBlockHeight(long blockHeight){
        Entity entity = null;
        try {
            entity = blockDetailDao.get("block_height", blockHeight);
        } catch (SQLException e) {
            log.error(" BlockDetailInfoRepository findByBlockHeight failed ", e);
        }
        return BeanUtils.toBean(entity,BlockDetailInfo.class);
    }


}
