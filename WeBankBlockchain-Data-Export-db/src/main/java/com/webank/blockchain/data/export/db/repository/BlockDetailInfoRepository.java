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

import javax.transaction.Transactional;

import com.webank.blockchain.data.export.db.entity.BlockDetailInfo;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

/**
 * BlockDetailInfoRepository
 *
 * @Description: BlockDetailInfoRepository
 * @author graysonzhang
 * @data 2018-11-14 18:03:48
 *
 */
@Repository
public interface BlockDetailInfoRepository
        extends JpaRepository<BlockDetailInfo, Long>, JpaSpecificationExecutor<BlockDetailInfo>, RollbackInterface,
        CommonHeightFindInterface<BlockDetailInfo>, CommonHashFindInterface<BlockDetailInfo> {

    /**
     * Get one block detail info order by block height and desc from block_detail_info table.
     * 
     * @return BlockDetailInfo
     */
    public BlockDetailInfo findTopByOrderByBlockHeightDesc();

    /**
     * Get records' count from block_detail_info table.
     * 
     * @return long
     */
    @Query(value = "select count(tx_count) from block_detail_info", nativeQuery = true)
    public long sumByTxCount();

    /**
     * Get records' count from block_detail_info table when block height >= beginIndex and <= endIndex.
     * 
     * @param beginIndex
     * @param endIndex
     * @return long
     */
    @Query(value = "select sum(tx_count) from block_detail_info where block_height >= ?1 and block_height< ?2", nativeQuery = true)
    public long sumByTxCountBetweens(long beginIndex, long endIndex);

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
