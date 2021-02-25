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

import cn.hutool.db.DaoTemplate;
import cn.hutool.db.Db;
import cn.hutool.db.Entity;
import com.webank.blockchain.data.export.common.entity.ExportConstant;
import com.webank.blockchain.data.export.db.entity.BlockRawData;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.sql.SQLException;

/**
 * @author wesleywang
 * @Description:
 * @date 2020/10/23
 */
@Slf4j
@AllArgsConstructor
public class BlockRawDataRepository implements RollbackInterface {

    private DaoTemplate blockRawDataDao;

    private final String tableName;


    public void rollback(long blockHeight){
        try {
            blockRawDataDao.del(Entity.create(tableName).set("block_height",">= " + blockHeight));
        } catch (SQLException e) {
            log.error(" BlockRawDataRepository rollback failed ", e);
        }
    }

    public void rollback(long startBlockHeight, long endBlockHeight){
        try {
            Db.use(ExportConstant.getCurrentContext().getDataSource()).execute(
                    "delete from " + tableName +" where block_height >= ? and block_height< ?",startBlockHeight,endBlockHeight);
        } catch (SQLException e) {
            log.error(" BlockRawDataRepository rollback failed ", e);
        }
    }


    public void save(BlockRawData blockRawData) {
        try {
            Entity entity = Entity.parse(blockRawData,true,true);
            entity.setTableName(tableName);
            blockRawDataDao.addForGeneratedKey(entity);
        } catch (SQLException e) {
            log.error(" BlockRawDataRepository save failed ", e);
        }
    }
}
