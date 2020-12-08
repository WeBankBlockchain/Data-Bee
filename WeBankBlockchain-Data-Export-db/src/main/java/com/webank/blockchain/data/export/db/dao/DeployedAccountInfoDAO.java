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
import com.webank.blockchain.data.export.common.bo.contract.ContractMapsInfo;
import com.webank.blockchain.data.export.common.bo.contract.ContractDetail;
import com.webank.blockchain.data.export.common.bo.data.DeployedAccountInfoBO;
import com.webank.blockchain.data.export.db.entity.DeployedAccountInfo;
import com.webank.blockchain.data.export.db.repository.DeployedAccountInfoRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * @author wesleywang
 * @Description:
 * @date 2020/10/26
 */
@Component
public class DeployedAccountInfoDAO implements SaveInterface<DeployedAccountInfoBO>{

    @Autowired
    private DeployedAccountInfoRepository deployedAccountInfoRepository;
    @Autowired
    private ContractMapsInfo contractMapsInfo;

    public void save(DeployedAccountInfo deployedAccountInfo) {
        BaseDAO.saveWithTimeLog(deployedAccountInfoRepository, deployedAccountInfo);
    }

    public void save(List<DeployedAccountInfoBO> deployedAccountInfoBOS) {
        deployedAccountInfoBOS.forEach(this::save);
    }

    @Override
    public void save(DeployedAccountInfoBO deployedAccountInfoBO) {
        DeployedAccountInfo deployedAccountInfo = new DeployedAccountInfo();
        BeanUtil.copyProperties(deployedAccountInfoBO, deployedAccountInfo, true);
        ContractDetail contractMethodInfo = contractMapsInfo.getContractBinaryMap().get(deployedAccountInfoBO.getBinary());
        deployedAccountInfo.setAbiHash(contractMethodInfo.getContractInfoBO().getAbiHash());
        save(deployedAccountInfo);
    }
}
