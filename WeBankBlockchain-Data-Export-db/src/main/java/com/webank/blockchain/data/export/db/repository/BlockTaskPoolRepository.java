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

import java.util.Date;
import java.util.List;
import java.util.Optional;

import javax.transaction.Transactional;

import com.webank.blockchain.data.export.db.entity.BlockTaskPool;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

/**
 * BlockTaskPoolRepository
 *
 * @Description: BlockTaskPoolRepository
 * @author maojiayu
 * @data Jan 11, 2019 10:10:04 AM
 *
 */
@Repository
public interface BlockTaskPoolRepository
        extends JpaRepository<BlockTaskPool, Long>, JpaSpecificationExecutor<BlockTaskPool> {

    public Optional<BlockTaskPool> findTopByOrderByBlockHeightDesc();

    public Optional<BlockTaskPool> findByBlockHeight(long blockHeight);

    public List<BlockTaskPool> findByCertainty(short certainty);

    @Query(value = "select * from #{#entityName} where block_height >= ?1 or block_height <= ?2 ", nativeQuery = true)
    public List<BlockTaskPool> findByBlockHeightRange(long startNumber, long endNumber);

    public long countBySyncStatus(short syncStatus);

    @Query(value = "select count(pk_id) from #{#entityName} where block_height >= ?1 or block_height <= ?2 ", nativeQuery = true)
    public long countByBlockHeightRange(long startNumber, long endNumber);

    @Query(value = "select * from #{#entityName} where sync_status = 4 or sync_status = 3 ", nativeQuery = true)
    public List<BlockTaskPool> findUnNormalRecords();

    @Query(value = "select * from #{#entityName} where sync_status = ?1 order by block_height limit ?2", nativeQuery = true)
    public List<BlockTaskPool> findBySyncStatusOrderByBlockHeightLimit(short syncStatus, int limit);

    @Query(value = "select * from #{#entityName} where block_height% ?1 = ?2 and sync_status = ?3 limit ?4", nativeQuery = true)
    public List<BlockTaskPool> findBySyncStatusModByBlockHeightLimit(int shardingCount, int shardingItem,
            short syncStatus, int limit);

    public List<BlockTaskPool> findBySyncStatusAndDepotUpdatetimeLessThan(short syncStatus, Date time);

    @Transactional
    @Modifying
    @Query(value = "update #{#entityName} set sync_status = ?1, depot_updatetime= ?2 where block_height = ?3", nativeQuery = true)
    public void setSyncStatusByBlockHeight(short syncStatus, Date updateTime, long blockHeight);

    @Transactional
    @Modifying
    @Query(value = "update #{#entityName} set certainty = ?1 where block_height = ?2", nativeQuery = true)
    public void setCertaintyByBlockHeight(short certainty, long blockHeight);

    @Transactional
    @Modifying
    @Query(value = "update #{#entityName} set sync_status = ?1, certainty = ?2 where block_height = ?3", nativeQuery = true)
    public void setSyncStatusAndCertaintyByBlockHeight(short syncStatus, short certainty, long blockHeight);

    /*
     * @see com.webank.blockchain.data.export.sys.db.repository.RollbackInterface#rollback(long)
     */
    @Transactional
    @Modifying
    @Query(value = "delete from  #{#entityName} where block_height >= ?1", nativeQuery = true)
    public void rollback(long blockHeight);

    /*
     * @see com.webank.blockchain.data.export.sys.db.repository.RollbackInterface#rollback(long, long)
     */
    @Transactional
    @Modifying
    @Query(value = "delete from  #{#entityName} where block_height >= ?1 and block_height< ?2", nativeQuery = true)
    public void rollback(long startBlockHeight, long endBlockHeight);
}
