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
import com.webank.blockchain.data.export.db.entity.TxRawData;
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
public class TxRawDataRepository implements RollbackInterface{


    private DaoTemplate txRawDataDao;

    private String tableName;

    /*
     * @see com.webank.blockchain.data.export.sys.db.repository.RollbackInterface#rollback(long)
     */
    public void rollback(long blockHeight){
        try {
            txRawDataDao.del(Entity.create(tableName).set("block_height",">= " + blockHeight));
        } catch (SQLException e) {
            log.error(" TxRawDataRepository rollback failed ", e);
        }
    }

    /*
     * @see com.webank.blockchain.data.export.sys.db.repository.RollbackInterface#rollback(long)
     */
    public void rollback(long startBlockHeight, long endBlockHeight){
        try {
            Db.use(ExportConstant.getCurrentContext().getDataSource()).execute(
                    "delete from " + tableName + " where block_height >= ? and block_height< ?",startBlockHeight,endBlockHeight);
        } catch (SQLException e) {
            log.error(" TxRawDataRepository rollback failed ", e);
        }
    }

    public void save(TxRawData txRawData) {
        try {
            Entity entity = Entity.parse(txRawData,true,true);
            entity.setTableName(tableName);
            txRawDataDao.addForGeneratedKey(entity);
        } catch (SQLException e) {
            log.error(" TxRawDataRepository save failed ", e);
        }

    }
}
