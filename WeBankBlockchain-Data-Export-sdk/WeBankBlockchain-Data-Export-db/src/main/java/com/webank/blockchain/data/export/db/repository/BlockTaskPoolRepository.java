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
import com.webank.blockchain.data.export.db.entity.BlockTaskPool;
import com.webank.blockchain.data.export.db.tools.BeanUtils;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * BlockTaskPoolRepository
 *
 * @Description: BlockTaskPoolRepository
 * @author maojiayu
 * @data Jan 11, 2019 10:10:04 AM
 *
 */
@Slf4j
@AllArgsConstructor
public class BlockTaskPoolRepository implements RollbackInterface{

    private DaoTemplate blockTaskPoolDao;

    private final String tableName = ExportConstant.BLOCK_TASK_POOL_TABLE;

    public BlockTaskPool findTopByOrderByBlockHeightDesc() {
        List<Entity> entityList = null;
        try {
            entityList = blockTaskPoolDao.findBySql("order by block_height desc limit 1");
        } catch (SQLException e) {
            log.error(" BlockTaskPoolRepository findTopByOrderByBlockHeightDesc failed ", e);
        }
        if (CollectionUtil.isEmpty(entityList)){
            return null;
        }
        Entity entity = entityList.get(0);
        return BeanUtils.toBean(entity, BlockTaskPool.class);
    }

    public  BlockTaskPool findByBlockHeight(long blockHeight) {
        Entity entity = null;
        try {
            entity = blockTaskPoolDao.get("block_height", blockHeight);
        } catch (SQLException e) {
            log.error(" BlockTaskPoolRepository findByBlockHeight failed ", e);
        }
        return BeanUtils.toBean(entity, BlockTaskPool.class);
    }

    public List<BlockTaskPool> findByCertainty(short certainty) {
        List<Entity> entityList = null;
        try {
            entityList = blockTaskPoolDao.find("certainty", certainty);
        } catch (SQLException e) {
            log.error(" BlockTaskPoolRepository findByCertainty failed ", e);
        }
        List<BlockTaskPool> result = new ArrayList<>();
        if(CollectionUtil.isEmpty(entityList)) {
            return result;
        }
        entityList.forEach(e -> {
            result.add(BeanUtils.toBean(e, BlockTaskPool.class));
        });
        return result;
    }

    public List<BlockTaskPool> findByBlockHeightRange(long startNumber, long endNumber)  {
        List<Entity> entityList = null;
        try {
            entityList = blockTaskPoolDao.findBySql(
                    "where block_height >= ? or block_height <= ?", startNumber,endNumber);
        } catch (SQLException e) {
            log.error(" BlockTaskPoolRepository findByBlockHeightRange failed ", e);
        }
        List<BlockTaskPool> result = new ArrayList<>();
        if(CollectionUtil.isEmpty(entityList)) {
            return result;
        }
        entityList.forEach(e -> {
            result.add(BeanUtils.toBean(e, BlockTaskPool.class));
        });
        return result;
    }

    public long countByBlockHeightRange(long startNumber, long endNumber) {
        try {
            return blockTaskPoolDao.count(Entity.create(tableName).set("block_height",
                    "between " + startNumber +" and " + endNumber));
        } catch (SQLException e) {
            log.error(" BlockTaskPoolRepository countByBlockHeightRange failed ", e);
        }
        return 0;
    }

    public List<BlockTaskPool> findUnNormalRecords() {
        List<Entity> entityList = null;
        try {
            entityList = blockTaskPoolDao.findBySql(
                    "where sync_status = 4 or sync_status = 3");
        } catch (SQLException e) {
            log.error(" BlockTaskPoolRepository findUnNormalRecords failed ", e);
        }
        List<BlockTaskPool> result = new ArrayList<>();
        if(CollectionUtil.isEmpty(entityList)) {
            return result;
        }
        entityList.forEach(e -> {
            result.add(BeanUtils.toBean(e, BlockTaskPool.class));
        });
        return result;
    }

    public List<BlockTaskPool> findBySyncStatusOrderByBlockHeightLimit(short syncStatus, int limit) {
        List<Entity> entityList = null;
        try {
            entityList = blockTaskPoolDao.findBySql(
                    "where sync_status = ? order by block_height limit ?",syncStatus,limit);
        } catch (SQLException e) {
            log.error(" BlockTaskPoolRepository findBySyncStatusOrderByBlockHeightLimit failed ", e);
        }
        List<BlockTaskPool> result = new ArrayList<>();
        if(CollectionUtil.isEmpty(entityList)) {
            return result;
        }
        entityList.forEach(e -> {
            result.add(BeanUtils.toBean(e, BlockTaskPool.class));
        });
        return result;
    }

    public List<BlockTaskPool> findBySyncStatusModByBlockHeightLimit(int shardingCount, int shardingItem,
            short syncStatus, int limit) {
        List<Entity> entityList = null;
        try {
            entityList = blockTaskPoolDao.findBySql(
                    "where block_height% ? = ? and sync_status = ? limit ?",
                    shardingCount,shardingItem,syncStatus,limit);
        } catch (SQLException e) {
            log.error(" BlockTaskPoolRepository findBySyncStatusModByBlockHeightLimit failed ", e);
        }
        List<BlockTaskPool> result = new ArrayList<>();
        if(CollectionUtil.isEmpty(entityList)) {
            return result;
        }
        entityList.forEach(e -> {
            result.add(BeanUtils.toBean(e, BlockTaskPool.class));
        });
        return result;
    }

    public List<BlockTaskPool> findBySyncStatusAndDepotUpdatetimeLessThan(short syncStatus, Date time) {
        List<Entity> entityList = null;
        try {
            entityList = blockTaskPoolDao.findBySql(
                    "where sync_status = ? and depot_updatetime < ? ",
                    syncStatus,time);
        } catch (SQLException e) {
            log.error(" BlockTaskPoolRepository findBySyncStatusAndDepotUpdatetimeLessThan failed ", e);
        }
        List<BlockTaskPool> result = new ArrayList<>();
        if(CollectionUtil.isEmpty(entityList)) {
            return result;
        }
        entityList.forEach(e -> {
            result.add(BeanUtils.toBean(e, BlockTaskPool.class));
        });
        return result;
    }

    public void setSyncStatusByBlockHeight(short syncStatus, Date updateTime, long blockHeight) {
        try {
            blockTaskPoolDao.update(Entity.create().set("sync_status",syncStatus).set("depot_updatetime",updateTime),
                    Entity.create(tableName).set("block_height",blockHeight));
        } catch (SQLException e) {
            log.error(" BlockTaskPoolRepository setSyncStatusByBlockHeight failed ", e);
        }
    }

    public void setCertaintyByBlockHeight(short certainty, long blockHeight) {
        try {
            blockTaskPoolDao.update(Entity.create().set("certainty",certainty),
                    Entity.create(tableName).set("block_height",blockHeight));
        } catch (SQLException e) {
            log.error(" BlockTaskPoolRepository setCertaintyByBlockHeight failed ", e);

        }
    }

    public void setSyncStatusAndCertaintyByBlockHeight(short syncStatus, short certainty, long blockHeight) {
        try {
            blockTaskPoolDao.update(Entity.create().set("sync_status",syncStatus).set("certainty",certainty),
                    Entity.create(tableName).set("block_height",blockHeight));
        } catch (SQLException e) {
            log.error(" BlockTaskPoolRepository setSyncStatusAndCertaintyByBlockHeight failed ", e);
        }
    }

    /*
     * @see com.webank.blockchain.data.export.sys.db.repository.RollbackInterface#rollback(long)
     */
    public void rollback(long blockHeight) {
        try {
            blockTaskPoolDao.del(Entity.create(tableName).set("block_height",">= " + blockHeight));
        } catch (SQLException e) {
            log.error(" BlockTaskPoolRepository rollback failed ", e);
        }
    }

    /*
     * @see com.webank.blockchain.data.export.sys.db.repository.RollbackInterface#rollback(long, long)
     */
    public void rollback(long startBlockHeight, long endBlockHeight) {
        try {
            Db.use(ExportConstant.getCurrentContext().getDataSource()).execute(
                    "delete from block_task_pool where block_height >= ? and block_height< ?",startBlockHeight,endBlockHeight);
        } catch (SQLException e) {
            log.error(" BlockTaskPoolRepository rollback failed ", e);
        }
    }

    public void saveAll(List<BlockTaskPool> list) {
            list.forEach(this::save);
    }

    public void save(BlockTaskPool blockTaskPool) {
        try {
            blockTaskPoolDao.addOrUpdate(Entity.parse(blockTaskPool, true, true));
        } catch (SQLException e) {
            log.error(" BlockTaskPoolRepository saveAll failed ", e);
        }
    }


}
