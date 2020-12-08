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
package com.webank.blockchain.data.export.codegen.config;


import com.webank.blockchain.data.export.codegen.vo.ContractInfo;
import lombok.Data;

import java.util.List;

/**
 * 
 * ContractsConfig
 *
 * @Description: ContractsConfig
 * @author graysonzhang
 * @data 2018-11-7 19:52:20
 *
 */
@Data
public class ContractsConfig {
	
	/** @Fields contractsPackage : contracts package that contains all contract java code files */
	private String contractsPackage;
	
	/** @Fields allTableCount : sharding for all tables */
	private int allTableCount;
	
	/** @Fields contractList : contract list */
	private List<ContractInfo> contractList;
}
