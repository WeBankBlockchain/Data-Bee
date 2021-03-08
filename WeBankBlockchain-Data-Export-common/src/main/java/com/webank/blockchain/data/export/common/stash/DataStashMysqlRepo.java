package com.webank.blockchain.data.export.common.stash;

import cn.hutool.db.Db;
import cn.hutool.db.Entity;
import cn.hutool.db.meta.MetaUtil;
import com.webank.blockchain.data.export.common.entity.ExportConstant;
import lombok.extern.slf4j.Slf4j;

import java.sql.SQLException;
import java.util.List;

/**
 * @author wesleywang
 * @Description:
 * @date 2021/3/3
 */
@Slf4j
public class DataStashMysqlRepo {

    private final Db stashDb;

    public static DataStashMysqlRepo create() {
        return new DataStashMysqlRepo();
    }

    public DataStashMysqlRepo() {
        stashDb = Db.use(ExportConstant.getCurrentContext().getStashDataSource());
    }

    public String queryBlock(long blockHeight){
        try {
            return stashDb.queryString(
                    "select value from _sys_hash_2_block_ where _num_ = ? ", blockHeight);
        } catch (SQLException e) {
            log.error(" DataStashMysqlRepo queryBlock failed ", e);
        }
        return null;
    }

    public long queryBlockHeight(String transactionHash){
        try {
            Number height =  stashDb.queryNumber(
                    "select _num_ from _sys_tx_hash_2_block_ where _hash_ = ? ", transactionHash);
            if (height == null) {
                return -1;
            }
            return height.longValue();
        } catch (SQLException e) {
            log.warn(" DataStashMysqlRepo queryBlock failed ", e);
        }
        return -1;
    }


    public long queryBlockNumber(){
        try {
            return stashDb.count(Entity.create("_sys_hash_2_block_")) - 1;
        } catch (SQLException e) {
            log.error(" DataStashMysqlRepo queryBlockNumber failed ", e);
        }
        return -1;
    }

    public String queryCode(String contractAddress) {
        try {
            String contractTable = "c_" + contractAddress.replace("0x","");
            return stashDb.queryString(
                    "select value from " + contractTable  + " where  " + contractTable +".key = ?", "code");
        } catch (SQLException e) {
            if (e.getErrorCode() == 1146 || e.getMessage().contains("doesn't exist")) {
                log.warn("the stash table contractAddress: {} not find ", contractAddress);
                return null;
            }
            log.warn("DataStashMysqlRepo queryCode failed ", e);
        }
        return null;
    }
}
