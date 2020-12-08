package com.webank.blockchain.data.export.common.bo.data;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.experimental.Accessors;

import java.util.List;
import java.util.Map;

/**
 * @author wesleywang
 * @Description:
 * @date 2020/10/26
 */
@Data
@AllArgsConstructor
@Accessors(chain = true)
public class BlockContractInfoBO {

    private Map<String, String> txHashContractAddressMapping;

    private List<DeployedAccountInfoBO> deployedAccountInfoBOS;
}
