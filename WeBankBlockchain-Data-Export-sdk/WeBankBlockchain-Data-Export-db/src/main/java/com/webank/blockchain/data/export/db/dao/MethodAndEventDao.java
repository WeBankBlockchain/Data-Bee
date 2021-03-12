package com.webank.blockchain.data.export.db.dao;

import cn.hutool.core.collection.CollectionUtil;
import cn.hutool.db.Db;
import cn.hutool.db.Entity;
import com.webank.blockchain.data.export.common.bo.data.BlockInfoBO;
import com.webank.blockchain.data.export.common.bo.data.CommonBO;
import com.webank.blockchain.data.export.common.entity.ExportConstant;
import lombok.extern.slf4j.Slf4j;

import java.sql.SQLException;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * @author wesleywang
 * @Description:
 * @date 2020/12/28
 */
@Slf4j
public class MethodAndEventDao implements SaveInterface<BlockInfoBO>{

    @Override
    public void save(BlockInfoBO blockInfoBO) {
        save(blockInfoBO.getEventInfoList());
        save(blockInfoBO.getMethodInfoList());
    }

    private void save(List<? extends CommonBO> list){
        if (CollectionUtil.isEmpty(list)) {
            return;
        }
        list.forEach(eventBO -> {
            try {
                Entity entity = Entity.create(eventBO.getTable());
                for (Map.Entry<String,Object> entry : eventBO.getEntity().entrySet()){
                    entity.set(entry.getKey(), entry.getValue());
                }
                entity.set("depot_updatetime", new Date());
                Db.use(ExportConstant.getCurrentContext().getDataSource()).insert(entity);
            } catch (SQLException e) {
                log.error("save failed ", e);
            }
        });
    }
}
