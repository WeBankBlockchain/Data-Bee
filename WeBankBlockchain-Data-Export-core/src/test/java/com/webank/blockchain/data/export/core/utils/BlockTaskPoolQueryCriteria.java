/*
 *  Copyright 2019-2020 Zheng Jie
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package com.webank.blockchain.data.export.core.utils;

import java.util.List;

import com.webank.blockchain.data.export.db.tools.QueryAnnotation;

import lombok.Data;


/**
 * DatabaseQueryCriteria
 *
 * @Description: DatabaseQueryCriteria
 * @author maojiayu
 * @data Jun 24, 2020 11:21:49 PM
 *
 */
@Data
public class BlockTaskPoolQueryCriteria{

	/**
	 * 精确
	 */
    @QueryAnnotation
    private int syncStatus;

	@QueryAnnotation(type = QueryAnnotation.Type.BETWEEN)
	private List<Long> blockHeight;
}
